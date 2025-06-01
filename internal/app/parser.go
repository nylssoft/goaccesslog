package app

import (
	"strconv"
	"strings"
	"time"
	"unicode"
)

// public

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

// private

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
