package parser

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	logLine, err := Parse(`127.0.0.1 - - [01/Jun/2025:18:24:22 +0200] 1748795062.703 "GET /hello HTTP/1.1" 78 404 162 0.000 "curl/7.81.0"`)
	assert.Nil(t, err)
	assert.Equal(t, "127.0.0.1", logLine.RemoteAddr)
	assert.Equal(t, time.Unix(0, 1748795062703*int64(time.Millisecond)), logLine.TimeLocal)
	assert.Equal(t, "GET", logLine.RequestMethod)
	assert.Equal(t, "/hello", logLine.RequestUri)
	assert.Equal(t, "HTTP/1.1", logLine.RequestProtocol)
	assert.Equal(t, 78, logLine.RequestLength)
	assert.Equal(t, 404, logLine.Status)
	assert.Equal(t, 162, logLine.BytesSent)
	assert.Equal(t, 0, logLine.RequestTime)
	assert.Equal(t, "curl/7.81.0", logLine.UserAgent)
}

func TestParseFail(t *testing.T) {
	_, err := Parse(`127.0.0.1 - - [] "GET /hello HTTP/1.1" 78 404 162 0.000 "curl/7.81.0"`)
	assert.NotNil(t, err)
	_, err = Parse(`- - [01/Jun/2025:18:24:22 +0200] 1748795062.703 "GET /hello HTTP/1.1" 78 404 162 0.000 "curl/7.81.0"`)
	assert.Nil(t, err)
	_, err = Parse(`127.0.0.1 - - [01/Jun/2025:18:24:22 +0200 1748795062.703 "GET /hello HTTP/1.1" 78 404 162 0.000 "curl/7.81.0"`)
	assert.NotNil(t, err)
	_, err = Parse(``)
	assert.Nil(t, err)
}
