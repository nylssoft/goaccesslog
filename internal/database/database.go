package database

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nylssoft/goaccesslog/internal/config"
	"github.com/nylssoft/goaccesslog/internal/logline"
	"github.com/nylssoft/goaccesslog/internal/ufw"
)

// public

const SIZE_1K = 1024
const SIZE_1M = SIZE_1K * SIZE_1K
const SIZE_1G = SIZE_1M * SIZE_1K

func Update(cfg *config.Config, locks *ufw.Locks, lastTimeLocal time.Time) (time.Time, error) {
	db, err := prepare(cfg)
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
	lastTimeLocal, err = processLogFile(cfg, locks, insertStmt, hashStmt, cfg.Nginx.AccessLogFilename, lastTimeLocal)
	if err != nil {
		return lastTimeLocal, err
	}
	return lastTimeLocal, nil
}

// private

func prepare(cfg *config.Config) (*sql.DB, error) {
	fileInfo, err := os.Stat(cfg.Database.Filename)
	if err == nil && fileInfo.Size() > SIZE_1G {
		log.Fatal("Database file is too large.")
	}
	db, err := sql.Open("sqlite3", cfg.Database.Filename)
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

func processLogFile(cfg *config.Config, locks *ufw.Locks, insertStmt, hashStmt *sql.Stmt, fileName string, lastTimeLocal time.Time) (time.Time, error) {
	if cfg.Logger.Verbose {
		log.Printf("Process log entries in log file '%s'. Last processed log entry: %s.\n", fileName, lastTimeLocal)
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
		logLine, err := logline.Parse(line)
		if err != nil {
			log.Printf("ERROR: Failed to parse log line '%s': %s\n", line, err.Error())
			continue
		}
		if logLine.TimeLocal.Compare(lastTimeLocal) >= 0 {
			skipped, err := insertLogLine(insertStmt, hashStmt, logLine, hashLine(line))
			if err != nil {
				log.Printf("ERROR: Failed to insert log line '%s': %s\n", line, err.Error())
				errCnt++
			} else if skipped {
				skipCnt++
			} else {
				insertCnt++
				if !locks.IsLocked(logLine.RemoteAddr) && cfg.IsMaliciousRequest(logLine.RemoteAddr, logLine.RequestUri, logLine.Status) {
					locks.Lock(logLine.RemoteAddr)
				}
			}
			lastTimeLocal = logLine.TimeLocal
		}
	}
	if cfg.Logger.Verbose && (insertCnt > 0 || skipCnt > 0 || errCnt > 0) {
		log.Printf("Inserted %d log lines. Skipped %d log lines. Errors occurred in %d log lines.\n", insertCnt, skipCnt, errCnt)
	}
	return lastTimeLocal, nil
}

func insertLogLine(insertStmt, hashStmt *sql.Stmt, logLine logline.LogLine, hash string) (bool, error) {
	rows, err := hashStmt.Query(hash)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	skipped := true
	if !rows.Next() {
		_, err = insertStmt.Exec(logLine.RemoteAddr, logLine.TimeLocal, logLine.RequestMethod, logLine.RequestUri, logLine.RequestProtocol, logLine.RequestLength, logLine.RequestTime, logLine.Status, logLine.BytesSent, logLine.UserAgent, hash)
		if err != nil {
			return false, err
		}
		skipped = false
	}
	return skipped, nil
}

func hashLine(line string) string {
	hasher := md5.New()
	hasher.Write([]byte(line))
	return hex.EncodeToString(hasher.Sum(nil))
}
