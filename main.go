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
	remote_addr      string
	time_local       time.Time
	request_method   string
	request_uri      string
	request_protocol string
	request_length   int
	request_time     int
	status           int
	bytes_sent       int
	user_agent       string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: goaccesslog [add <nginx-logfile-name>...] | [clear] | [analyse] | [view]")
		os.Exit(-1)
	}
	db, err := connectDatabase()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	switch os.Args[1] {
	case "add":
		add(db, os.Args[2:])
	case "clear":
		clear(db)
	case "analyse":
		analyse(db)
	case "view":
		viewBlockedIps(db)
	}
}

func analyse(db *sql.DB) {
	_, err := db.Exec("delete from blockedips")
	if err != nil {
		log.Fatal(err)
	}
	findSuspiciousRequests(db)
}

func clear(db *sql.DB) {
	_, err := db.Exec("delete from accesslog")
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec("delete from blockedips")
	if err != nil {
		log.Fatal(err)
	}
}

func add(db *sql.DB, fileNames []string) {
	insertStmt, err := db.Prepare("INSERT INTO accesslog (remote_addr,time_local,request_method,request_uri,request_protocol,request_length,request_time,status,bytes_sent,user_agent,hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
	if err != nil {
		log.Fatal(err)
	}
	defer insertStmt.Close()
	hashStmt, err := db.Prepare("SELECT 1 FROM accesslog WHERE hash=$1")
	if err != nil {
		log.Fatal(err)
	}
	defer hashStmt.Close()
	for _, fileName := range fileNames {
		err = insertAccessLogFile(insertStmt, hashStmt, fileName)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func viewBlockedIps(db *sql.DB) {
	rows, err := db.Query(
		"select ip from blockedips order by ip asc")
	if err != nil {
		log.Fatal(err)
	}
	for rows.Next() {
		var ip string
		err = rows.Scan(&ip)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(ip)
	}
}

func findSuspiciousRequests(db *sql.DB) {
	// find requests from IP addresses that failed and used unexpected request methods or took more than 5000ms
	rows, err := db.Query(
		"select remote_addr,request_method,request_uri,request_protocol,request_time,status " +
			"from accesslog where status >= 400 and (request_method not in ('GET','POST','PUT','OPTIONS','PRI','HEAD','DELETE','CONNECT','TRACE','PATCH') or request_time > 5000) and " +
			"remote_addr not in (select ip from blockedips)")
	if err != nil {
		log.Fatal(err)
	}
	blockips := make(map[string]bool)
	for rows.Next() {
		var remote_addr, request_method, request_uri, request_protocol string
		var request_time, status int
		err = rows.Scan(&remote_addr, &request_method, &request_uri, &request_protocol, &request_time, &status)
		if err != nil {
			log.Fatal(err)
		}
		if !blockips[remote_addr] && !isValidUri(request_uri) {
			fmt.Println("Block IP", remote_addr, request_method, request_uri, request_protocol, request_time, status)
			blockips[remote_addr] = true
		}
	}
	// find requests from IP addresses that failed more than 100 times or redirects more than 100 times
	rows, err = db.Query(
		"select cnt,remote_addr,request_uri,status from " +
			"(select count(remote_addr) as cnt,remote_addr,request_uri,status from accesslog where (status >= 400 or status = 301) " +
			"group by remote_addr,request_uri,status) as tmp where " +
			"tmp.cnt > 100 and tmp.remote_addr not in (select ip from blockedips)")
	if err != nil {
		log.Fatal(err)
	}
	for rows.Next() {
		var remote_addr, request_uri string
		var cnt, status int
		err = rows.Scan(&cnt, &remote_addr, &request_uri, &status)
		if err != nil {
			log.Fatal(err)
		}
		if !blockips[remote_addr] && !isValidUri(request_uri) {
			fmt.Println("Block IP", remote_addr, request_uri, status, cnt)
			blockips[remote_addr] = true
		}
	}
	if len(blockips) > 0 {
		stmt, err := db.Prepare("INSERT INTO blockedips (ip) VALUES ($1)")
		if err != nil {
			log.Fatal(err)
		}
		defer stmt.Close()
		for ip := range blockips {
			_, err = stmt.Exec(ip)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

func isValidUri(uri string) bool {
	test := strings.ToLower(uri)
	if test == "/" {
		return true
	}
	patterns := []string{"api", "arkanoid", "backgammon", "chess", "contacts", "diary", "documents", "index", "makeadate", "notes", "pwdman", "password", "skat", "slideshow", "tetris", "usermgmt", "view", "webpack"}
	for _, p := range patterns {
		if strings.Contains(test, p) {
			return true
		}
	}
	return false
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
			remote_addr varchar(32),
			time_local timestamptz,
			request_method varchar(32),
			request_uri varchar,
			request_protocol varchar(32),
			request_length int,
			request_time int,
			status int,
			bytes_sent int,
			user_agent varchar,
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
	query = `create table if not exists blockedips (ip varchar(32))`
	_, err = db.Exec(query)
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func insertLogLine(insertStmt, hashStmt *sql.Stmt, logLine LogLine, hash string) (bool, error) {
	rows, err := hashStmt.Query(hash)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	skipped := true
	if !rows.Next() {
		_, err = insertStmt.Exec(logLine.remote_addr, logLine.time_local, logLine.request_method, logLine.request_uri, logLine.request_protocol, logLine.request_length, logLine.request_time, logLine.status, logLine.bytes_sent, logLine.user_agent, hash)
		if err != nil {
			return false, err
		}
		skipped = false
	}
	return skipped, nil
}

func parseLogLine(line string) (LogLine, bool) {
	logLine := LogLine{}
	logLine.remote_addr, line = parseIpAddress(line)
	if len(logLine.remote_addr) > 0 {
		_, line = parseDate(line)
		msec, line := parseMsec(line)
		logLine.time_local = time.UnixMilli(msec)
		logLine.request_uri, line = parseRequest(line)
		idx := strings.Index(logLine.request_uri, " ")
		if idx > 0 && idx < 32 {
			logLine.request_method = logLine.request_uri[0:idx]
			logLine.request_uri = logLine.request_uri[idx+1:]
			idx = strings.Index(logLine.request_uri, " ")
			if idx > 0 {
				logLine.request_protocol = logLine.request_uri[idx+1:]
				logLine.request_uri = logLine.request_uri[0:idx]
			}
		}
		logLine.request_length, line = parseInt(line)
		logLine.status, line = parseInt(line)
		logLine.bytes_sent, line = parseInt(line)
		logLine.request_time, line = parseDuration(line)
		logLine.user_agent, _ = parseEnv(line)
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

func parseMsec(line string) (int64, string) {
	sec, r1 := parseInt(line)
	// skip .
	msec, r2 := parseInt(r1[1:])
	return int64(sec)*1000 + int64(msec), r2
}

func parseInt(line string) (int, string) {
	var sb strings.Builder
	var idx int
	var c rune
	for idx, c = range line {
		if unicode.IsDigit(c) {
			sb.WriteRune(c)
		} else if sb.Len() > 0 {
			break
		}
	}
	num, _ := strconv.Atoi(sb.String())
	return num, line[idx:]
}

func parseDuration(line string) (int, string) {
	f, rest := parseFloat(line)
	return int(f * 1000.0), rest
}

func parseFloat(line string) (float64, string) {
	var sb strings.Builder
	var idx int
	var c rune
	for idx, c = range line {
		if c == '.' || unicode.IsDigit(c) {
			sb.WriteRune(c)
		} else if sb.Len() > 0 {
			break
		}
	}
	num, _ := strconv.ParseFloat(sb.String(), 64)
	return num, line[idx:]
}

func extractString(line string, bracketStart, bracketEnd rune) (string, string) {
	var sb strings.Builder
	startFound := false
	for idx, c := range line {
		if c == bracketStart && !startFound {
			startFound = true
		} else if c == bracketEnd && startFound {
			return sb.String(), line[idx+1:]
		} else if startFound {
			sb.WriteRune(c)
		}
	}
	return "", ""
}
