package analyzer

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
	"github.com/nylssoft/goaccesslog/internal/parser"
	"github.com/nylssoft/goaccesslog/internal/ufw"
)

type analyzer_impl struct {
	db         *sql.DB
	insertStmt *sql.Stmt
	hashStmt   *sql.Stmt
	// dependencies
	config config.Config
	ufw    ufw.Ufw
}

const size_1K = 1024
const size_1M = size_1K * size_1K
const size_1G = size_1M * size_1M

func (analyzer *analyzer_impl) Analyze(lastTimeLocal time.Time) (time.Time, error) {
	defer analyzer.closeDatabase()
	if analyzer.config.IsVerbose() {
		log.Printf("Process log entries in log file '%s'. Last processed log entry: %s.\n", analyzer.config.AccessLogFilename(), lastTimeLocal)
	}
	bytes, err := os.ReadFile(analyzer.config.AccessLogFilename())
	if err != nil {
		return lastTimeLocal, err
	}
	data := string(bytes)
	data = strings.ReplaceAll(data, "\t", "")
	data = strings.ReplaceAll(data, "\r", "")
	lines := strings.Split(data, "\n")
	insertCnt, skipCnt, errCnt := 0, 0, 0
	for _, line := range lines {
		logLine, err := parser.Parse(line)
		if err != nil {
			log.Printf("ERROR: Failed to parse log line '%s': %s\n", line, err.Error())
			continue
		}
		if logLine.TimeLocal.Compare(lastTimeLocal) >= 0 {
			skipped, err := analyzer.insertLogLine(logLine, hashLine(line))
			if err != nil {
				log.Printf("ERROR: Failed to insert log line '%s': %s\n", line, err.Error())
				errCnt++
			} else if skipped {
				skipCnt++
			} else {
				insertCnt++
				if !analyzer.ufw.IsRejected(logLine.RemoteAddr) &&
					analyzer.config.IsMaliciousRequest(logLine.RemoteAddr, logLine.RequestProtocol, logLine.RequestUri, logLine.Status) {
					analyzer.ufw.Reject(logLine.RemoteAddr)
				}
			}
			lastTimeLocal = logLine.TimeLocal
		}
	}
	if analyzer.config.IsVerbose() && (insertCnt > 0 || skipCnt > 0 || errCnt > 0) {
		log.Printf("Inserted %d log lines. Skipped %d log lines. Errors occurred in %d log lines.\n", insertCnt, skipCnt, errCnt)
	}
	analyzer.ufw.ReleaseIfExpired()
	return lastTimeLocal, err
}

func (analyzer *analyzer_impl) insertLogLine(logLine parser.LogLine, hash string) (bool, error) {
	analyzer.initDatabase()
	rows, err := analyzer.hashStmt.Query(hash)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	skipped := true
	if !rows.Next() {
		_, err = analyzer.insertStmt.Exec(logLine.RemoteAddr, logLine.TimeLocal, logLine.RequestMethod, logLine.RequestUri, logLine.RequestProtocol, logLine.RequestLength, logLine.RequestTime, logLine.Status, logLine.BytesSent, logLine.UserAgent, hash)
		if err != nil {
			return false, err
		}
		skipped = false
	}
	return skipped, nil
}

func (analyzer *analyzer_impl) initDatabase() error {
	var err error
	if analyzer.db == nil {
		var fileInfo os.FileInfo
		fileInfo, err = os.Stat(analyzer.config.DatabaseFilename())
		if err == nil && fileInfo.Size() > size_1G {
			log.Fatal("Database file is too large.")
		}
		var db *sql.DB
		db, err = sql.Open("sqlite3", analyzer.config.DatabaseFilename())
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
			} else {
				analyzer.db = db
			}
		}
	}
	if err == nil && analyzer.insertStmt == nil {
		var stmt *sql.Stmt
		stmt, err = analyzer.db.Prepare("INSERT INTO accesslog (remote_addr,time_local,request_method,request_uri,request_protocol,request_length,request_time,status,bytes_sent,user_agent,hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
		if err == nil {
			analyzer.insertStmt = stmt
		}
	}
	if err == nil && analyzer.hashStmt == nil {
		var stmt *sql.Stmt
		stmt, err = analyzer.db.Prepare("SELECT 1 FROM accesslog WHERE hash=$1")
		if err == nil {
			analyzer.hashStmt = stmt
		}
	}
	return err
}

func (analyzer *analyzer_impl) closeDatabase() {
	if analyzer.hashStmt != nil {
		analyzer.hashStmt.Close()
		analyzer.hashStmt = nil
	}
	if analyzer.insertStmt != nil {
		analyzer.insertStmt.Close()
		analyzer.insertStmt = nil
	}
	if analyzer.db != nil {
		analyzer.db.Close()
		analyzer.db = nil
	}
}

func hashLine(line string) string {
	hasher := md5.New()
	hasher.Write([]byte(line))
	return hex.EncodeToString(hasher.Sum(nil))
}
