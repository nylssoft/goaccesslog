package parser

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	logLine, err := Parse(`127.0.0.1 - - [01/Jun/2025:18:24:22 +0200] 1748795062.703 "GET /hello HTTP/1.1" 78 404 162 0.000 "curl/7.81.0"`)
	assertNil(t, err)
	assertEquals(t, "127.0.0.1", logLine.RemoteAddr)
	assertEquals(t, time.Unix(0, 1748795062703*int64(time.Millisecond)), logLine.TimeLocal)
	assertEquals(t, "GET", logLine.RequestMethod)
	assertEquals(t, "/hello", logLine.RequestUri)
	assertEquals(t, "HTTP/1.1", logLine.RequestProtocol)
	assertEquals(t, 78, logLine.RequestLength)
	assertEquals(t, 404, logLine.Status)
	assertEquals(t, 162, logLine.BytesSent)
	assertEquals(t, 0, logLine.RequestTime)
	assertEquals(t, "curl/7.81.0", logLine.UserAgent)
}

func TestParseFail(t *testing.T) {
	_, err := Parse(`127.0.0.1 - - [] "GET /hello HTTP/1.1" 78 404 162 0.000 "curl/7.81.0"`)
	assertNotNil(t, err)
	_, err = Parse(`- - [01/Jun/2025:18:24:22 +0200] 1748795062.703 "GET /hello HTTP/1.1" 78 404 162 0.000 "curl/7.81.0"`)
	assertNil(t, err)
	_, err = Parse(`127.0.0.1 - - [01/Jun/2025:18:24:22 +0200 1748795062.703 "GET /hello HTTP/1.1" 78 404 162 0.000 "curl/7.81.0"`)
	assertNotNil(t, err)
	_, err = Parse(``)
	assertNil(t, err)
}

func assertNil(t *testing.T, value any) {
	if value != nil {
		t.Errorf("Expected value must be nil but is '%v'.", value)
	}
}

func assertNotNil(t *testing.T, value any) {
	if value == nil {
		t.Errorf("Expected value must not be nil but is '%v'.", value)
	}
}

func assertEquals(t *testing.T, expected, value any) {
	if expected != value {
		t.Errorf("Expected value '%s' but was value '%s'.", expected, value)
	}
}
