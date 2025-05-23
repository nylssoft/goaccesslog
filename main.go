package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/fsnotify/fsnotify"
	_ "github.com/mattn/go-sqlite3"
)

var flagLog = flag.String("log", "/var/log/nginx/access.log", "nginx log file")
var flagDatabase = flag.String("database", "./goaccesslog.db", "database file")
var flagVerbose = flag.Bool("verbose", false, "verbose logging")

const SIZE_1K = 1024
const SIZE_1M = SIZE_1K * SIZE_1K
const SIZE_1G = SIZE_1M * SIZE_1K

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
	flag.Parse()
	fmt.Printf("Copy nginx log file entries from '%s' into sqlite database file '%s'.\n", *flagLog, *flagDatabase)
	fmt.Println("Note: nginx log format is expected to be")
	fmt.Println("   log_format noreferer '$remote_addr - $remote_user [$time_local] $msec \"$request\" $request_length $status $body_bytes_sent $request_time \"$http_user_agent\"';")
	ticker := time.NewTicker(60 * time.Second)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("Failed to create file watcher.", err)
	}
	defer watcher.Close()
	logFile := *flagLog
	logDir := filepath.Dir(logFile)
	shutdown := make(chan bool, 1)
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		update := false
		var lastTimeLocal time.Time
	loop:
		for {
			select {
			case sig := <-stop:
				fmt.Printf("Shutdown signal %v received\n", sig)
				shutdown <- true
				break loop
			case event := <-watcher.Events:
				if !update && event.Has(fsnotify.Write) && event.Name == logFile {
					update = true
					if *flagVerbose {
						fmt.Println("Detected modified log file. Update database on next schedule.")
					}
				}
			case <-ticker.C:
				if update {
					update = false
					lastTimeLocal, err = updateDatabase(logFile, lastTimeLocal)
					if err != nil {
						fmt.Println("ERROR: Failed to update database.", err)
					}
				}
			case err := <-watcher.Errors:
				fmt.Println("ERROR: Failed to watch directory.", err)
			}
		}
	}()
	err = watcher.Add(logDir)
	if err != nil {
		log.Fatal("Failed to add directory to file watcher.", err)
	}
	<-shutdown
}

func updateDatabase(fileName string, lastTimeLocal time.Time) (time.Time, error) {
	db, err := prepareDatabase()
	if err != nil {
		return lastTimeLocal, err
	}
	defer db.Close()
	insertStmt, err := db.Prepare("INSERT INTO accesslog (remote_addr,time_local,request_method,request_uri,request_protocol,request_length,request_time,status,bytes_sent,user_agent,hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
	if err != nil {
		return lastTimeLocal, err
	}
	defer insertStmt.Close()
	hashStmt, err := db.Prepare("SELECT 1 FROM accesslog WHERE hash=$1")
	if err != nil {
		return lastTimeLocal, err
	}
	defer hashStmt.Close()
	lastTimeLocal, err = processLogFile(insertStmt, hashStmt, fileName, lastTimeLocal)
	if err != nil {
		return lastTimeLocal, err
	}
	return lastTimeLocal, nil
}

func prepareDatabase() (*sql.DB, error) {
	fileInfo, err := os.Stat(*flagDatabase)
	if err == nil && fileInfo.Size() > SIZE_1G {
		log.Fatal("Database file is too large.")
	}
	db, err := sql.Open("sqlite3", *flagDatabase)
	if err == nil {
		stmt := `CREATE TABLE IF NOT EXISTS accesslog (
			remote_addr TEXT,
			time_local TIMESTAMP,
			request_method TEXT,
			request_uri TEXT,
			request_protocol TEXT,
			request_length INTEGER,
			request_time INTEGER,
			status INTEGER,
			bytes_sent INTEGER,
			user_agent TEXT,
			hash TEXT)`
		_, err = db.Exec(stmt)
		if err == nil {
			stmt = "CREATE INDEX IF NOT EXISTS accesslog_hash_idx ON accesslog (hash)"
			_, err = db.Exec(stmt)
		}
		if err != nil {
			db.Close()
		}
	}
	return db, err
}

func processLogFile(insertStmt, hashStmt *sql.Stmt, fileName string, lastTimeLocal time.Time) (time.Time, error) {
	if *flagVerbose {
		fmt.Printf("Process log entries in log file '%s'. Last processed log entry: %s.\n", fileName, lastTimeLocal)
	}
	bytes, err := os.ReadFile(fileName)
	if err != nil {
		return lastTimeLocal, err
	}
	data := string(bytes)
	data = strings.ReplaceAll(data, "\t", "")
	data = strings.ReplaceAll(data, "\r", "")
	lines := strings.Split(data, "\n")
	insertCnt, skipCnt, errCnt := 0, 0, 0
	for _, line := range lines {
		logLine, err := parseLogLine(line)
		if err != nil {
			fmt.Printf("ERROR: Failed to parse log line '%s': %s\n", line, err.Error())
			continue
		}
		if logLine.time_local.Compare(lastTimeLocal) >= 0 && logLine.status != 301 && logLine.status != 302 {
			skipped, err := insertLogLine(insertStmt, hashStmt, logLine, hashLine(line))
			if err != nil {
				fmt.Printf("ERROR: Failed to insert log line '%s': %s\n", line, err.Error())
				errCnt++
			} else if skipped {
				skipCnt++
			} else {
				insertCnt++
			}
			lastTimeLocal = logLine.time_local
		}
	}
	if *flagVerbose && (insertCnt > 0 || skipCnt > 0 || errCnt > 0) {
		fmt.Printf("Inserted %d log lines. Skipped %d log lines. Errors occurred in %d log lines.\n", insertCnt, skipCnt, errCnt)
	}
	return lastTimeLocal, nil
}

func hashLine(line string) string {
	hasher := md5.New()
	hasher.Write([]byte(line))
	return hex.EncodeToString(hasher.Sum(nil))
}

func parseLogLine(line string) (LogLine, error) {
	var err error
	logLine := LogLine{}
	logLine.remote_addr, line = parseIpAddress(line)
	if len(logLine.remote_addr) > 0 {
		_, line, err = parseDate(line)
		if err != nil {
			return logLine, err
		}
		msec, line := parseMsec(line)
		logLine.time_local = time.UnixMilli(msec)
		logLine.request_uri, line = parseRequest(line)
		idx := strings.Index(logLine.request_uri, " ")
		if idx > 0 && idx < 32 {
			logLine.request_method = logLine.request_uri[0:idx]
			logLine.request_uri = logLine.request_uri[idx+1:]
			idx = strings.LastIndex(logLine.request_uri, " ")
			if idx > 0 && len(logLine.request_uri)-idx < 32 {
				logLine.request_protocol = logLine.request_uri[idx+1:]
				logLine.request_uri = logLine.request_uri[0:idx]
			}
		}
		logLine.request_length, line = parseInt(line)
		logLine.status, line = parseInt(line)
		logLine.bytes_sent, line = parseInt(line)
		logLine.request_time, line = parseDuration(line)
		logLine.user_agent, _ = parseEnv(line)
		return logLine, nil
	}
	return logLine, nil
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

func parseDate(line string) (time.Time, string, error) {
	str, rest := extractString(line, '[', ']')
	arr := strings.Split(str, " ")
	datestr := strings.Replace(arr[0], ":", " ", 1)
	t, err := time.Parse("02/Jan/2006 15:04:05", datestr)
	return t, rest, err
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
