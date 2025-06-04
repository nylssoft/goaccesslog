package parser

import (
	"strings"
	"time"
)

type LogLine struct {
	RemoteAddr      string
	TimeLocal       time.Time
	RequestMethod   string
	RequestUri      string
	RequestProtocol string
	RequestLength   int
	RequestTime     int
	Status          int
	BytesSent       int
	UserAgent       string
}

func Parse(line string) (LogLine, error) {
	var err error
	logLine := LogLine{}
	logLine.RemoteAddr, line = parseIpAddress(line)
	if len(logLine.RemoteAddr) > 0 {
		_, line, err = parseDate(line)
		if err != nil {
			return logLine, err
		}
		msec, line := parseMsec(line)
		logLine.TimeLocal = time.UnixMilli(msec)
		logLine.RequestUri, line = parseRequest(line)
		idx := strings.Index(logLine.RequestUri, " ")
		if idx > 0 && idx < 32 {
			logLine.RequestMethod = logLine.RequestUri[0:idx]
			logLine.RequestUri = logLine.RequestUri[idx+1:]
			idx = strings.LastIndex(logLine.RequestUri, " ")
			if idx > 0 && len(logLine.RequestUri)-idx < 32 {
				logLine.RequestProtocol = logLine.RequestUri[idx+1:]
				logLine.RequestUri = logLine.RequestUri[0:idx]
			}
		}
		logLine.RequestLength, line = parseInt(line)
		logLine.Status, line = parseInt(line)
		logLine.BytesSent, line = parseInt(line)
		logLine.RequestTime, line = parseDuration(line)
		logLine.UserAgent, _ = parseEnv(line)
		return logLine, nil
	}
	return logLine, nil
}
