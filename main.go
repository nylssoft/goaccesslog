package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type LogLine struct {
	ipaddress  string
	date       time.Time
	request    string
	statuscode int
	bytes      int
	duration   float64
	env        string
}

func main() {
	fmt.Println("Hello Go!")
	bytes, err := os.ReadFile("access.log")
	if err != nil {
		log.Fatal(err)
	}
	data := string(bytes)
	data = strings.ReplaceAll(data, "\t", "")
	data = strings.ReplaceAll(data, "\r", "")
	lines := strings.Split(data, "\n")
	m := make(map[string][]LogLine)
	for _, line := range lines {
		logLine, ok := parseLogLine(line)
		if ok {
			// fmt.Println(logLine.ipaddress, logLine.date.Format(time.RFC3339))
			all := m[logLine.ipaddress]
			all = append(all, logLine)
			m[logLine.ipaddress] = all
		}
	}
	for k, v := range m {
		fmt.Println(k)
		for _, l := range v {
			if l.statuscode != 200 {
				fmt.Println("   ",
					l.date.Format(time.RFC3339), l.request,
					l.statuscode, l.bytes,
					l.duration, l.env)
			}
		}
	}
}

func parseLogLine(line string) (LogLine, bool) {
	logLine := LogLine{}
	logLine.ipaddress, line = parseIpAddress(line)
	if len(logLine.ipaddress) > 0 {
		logLine.date, line = parseDate(line)
		logLine.request, line = parseRequest(line)
		logLine.statuscode, line = parseInt(line)
		logLine.bytes, line = parseInt(line)
		logLine.duration, line = parseFloat(line)
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
