package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	_ "github.com/lib/pq"
)

type LogLine struct {
	ipaddress  string
	date       time.Time
	request    string
	statuscode int
	bytes      int
	duration   int
	env        string
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: goaccesslog <nginx-logfile-name>...")
	}
	db, err := connectDatabase()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	insertStmt, err := db.Prepare("INSERT INTO accesslog (ipaddress,dateutc,datestr,request,status,bytes,duration,env,hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
	if err != nil {
		log.Fatal(err)
	}
	defer insertStmt.Close()
	hashStmt, err := db.Prepare("SELECT 1 FROM accesslog WHERE hash=$1")
	if err != nil {
		log.Fatal(err)
	}
	defer hashStmt.Close()
	for idx := 1; idx < len(os.Args); idx++ {
		err = insertAccessLogFile(insertStmt, hashStmt, os.Args[idx])
		if err != nil {
			log.Fatal(err)
		}
	}
}

func insertAccessLogFile(insertStmt, hashStmt *sql.Stmt, fileName string) error {
	fmt.Printf("Process log file '%s'...\n", fileName)
	bytes, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	data := string(bytes)
	data = strings.ReplaceAll(data, "\t", "")
	data = strings.ReplaceAll(data, "\r", "")
	lines := strings.Split(data, "\n")
	insertCnt, skipCnt := 0, 0
	for _, line := range lines {
		hash := hashLine(line)
		logLine, ok := parseLogLine(line)
		if ok {
			skip, err := insertLogLine(insertStmt, hashStmt, logLine, hash)
			if err != nil {
				return err
			}
			if skip {
				skipCnt++
			} else {
				insertCnt++
			}
		}
	}
	fmt.Printf("Processed %d lines in log file. Inserted %d row(s). Skipped %d row(s).\n", insertCnt+skipCnt, insertCnt, skipCnt)
	return nil
}

func hashLine(line string) string {
	hasher := md5.New()
	hasher.Write([]byte(line))
	return hex.EncodeToString(hasher.Sum(nil))
}

func connectDatabase() (*sql.DB, error) {
	con := os.Getenv("DB_DATASOURCE")
	if len(con) == 0 {
		return nil, errors.New("MISSING_ENV_DB_DATASOURCE")
	}
	db, err := sql.Open("postgres", con)
	if err != nil {
		return nil, err
	}
	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, err
	}
	query := `create table if not exists accesslog (
			ipaddress varchar(32),
			dateutc bigint,
			datestr varchar(100),
			request varchar,
			status int,
			bytes int,
			duration int,
			env varchar,
			hash varchar(100)
		)`
	_, err = db.Exec(query)
	if err != nil {
		db.Close()
		return nil, err
	}
	query = "create index if not exists accesslog_hash_idx on accesslog (hash)"
	_, err = db.Exec(query)
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func insertLogLine(insertStmt, hashStmt *sql.Stmt, logLine LogLine, hash string) (bool, error) {
	dateutc := logLine.date.Unix()
	datestr := logLine.date.Format(time.RFC3339)
	rows, err := hashStmt.Query(hash)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	skipped := true
	if !rows.Next() {
		_, err = insertStmt.Exec(logLine.ipaddress, dateutc, datestr, logLine.request, logLine.statuscode, logLine.bytes, logLine.duration, logLine.env, hash)
		if err != nil {
			return false, err
		}
		skipped = false
	}
	return skipped, nil
}

func parseLogLine(line string) (LogLine, bool) {
	logLine := LogLine{}
	logLine.ipaddress, line = parseIpAddress(line)
	if len(logLine.ipaddress) > 0 {
		logLine.date, line = parseDate(line)
		logLine.request, line = parseRequest(line)
		logLine.statuscode, line = parseInt(line)
		logLine.bytes, line = parseInt(line)
		logLine.duration, line = parseDuration(line)
		logLine.env, _ = parseEnv(line)
		return logLine, true
	}
	return logLine, false
}

func parseIpAddress(line string) (string, string) {
	var ipaddress strings.Builder
	for idx, c := range line {
		if c == ' ' {
			return ipaddress.String(), line[idx:]
		}
		ipaddress.WriteRune(c)
	}
	return "", ""
}

func parseDate(line string) (time.Time, string) {
	str, rest := extractString(line, '[', ']')
	arr := strings.Split(str, " ")
	datestr := strings.Replace(arr[0], ":", " ", 1)
	t, err := time.Parse("02/Jan/2006 15:04:05", datestr)
	if err != nil {
		log.Fatal(err)
	}
	return t, rest
}

func parseRequest(line string) (string, string) {
	return extractString(line, '"', '"')
}

func parseEnv(line string) (string, string) {
	return extractString(line, '"', '"')
}

func parseInt(line string) (int, string) {
	var sb strings.Builder
	for idx, c := range line {
		if unicode.IsDigit(c) {
			sb.WriteRune(c)
		} else if sb.Len() > 0 {
			num, _ := strconv.Atoi(sb.String())
			return num, line[idx:]
		}
	}
	return 0, ""
}

func parseDuration(line string) (int, string) {
	f, rest := parseFloat(line)
	return int(f * 1000.0), rest
}

func parseFloat(line string) (float64, string) {
	var sb strings.Builder
	for idx, c := range line {
		if c == '.' || unicode.IsDigit(c) {
			sb.WriteRune(c)
		} else if sb.Len() > 0 {
			num, _ := strconv.ParseFloat(sb.String(), 64)
			return num, line[idx:]
		}
	}
	return 0.0, ""
}

func extractString(line string, bracketStart, bracketEnd rune) (string, string) {
	var sb strings.Builder
	startFound := false
	for idx, c := range line {
		if c == bracketStart && !startFound {
			startFound = true
		} else if c == bracketEnd && startFound {
			return sb.String(), line[idx:]
		} else if startFound {
			sb.WriteRune(c)
		}
	}
	return "", ""
}
