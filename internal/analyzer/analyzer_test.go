package analyzer

import (
	"os"
	"path"
	"testing"
	"text/template"
	"time"

	"github.com/nylssoft/goaccesslog/internal/config"
	"github.com/nylssoft/goaccesslog/internal/ufw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockExecutor struct {
	ret string
	err error
}

func (e *mockExecutor) Exec(cmdName string, args ...string) ([]byte, error) {
	return []byte(e.ret), e.err
}

func TestAnalzse(t *testing.T) {

	tempDir := t.TempDir()
	filename := path.Join(tempDir, "config.json")
	nginxfile := path.Join(tempDir, "test-nginx.log")
	logfile := path.Join(tempDir, "test.log")
	dbfile := path.Join(tempDir, "test.db")
	err := os.WriteFile(nginxfile, []byte(""), 0666)
	require.NoError(t, err)
	createConfigFile(t, filename, logfile, dbfile, nginxfile, "goodRule", "starts-with(ip,'127.')", "badrule", "eq(status,444)")

	cfg := config.NewConfig()
	err = cfg.Init(filename)
	require.Nil(t, err)

	e := mockExecutor{}
	ufw := ufw.NewUfw(&e, "unittest", time.Second, 1)

	analyzer := NewAnalyzer(cfg, ufw)
	assert.NotNil(t, analyzer)

	var lastTimeLocal time.Time
	lastTimeLocal, err = analyzer.Analyze(lastTimeLocal)
	assert.Nil(t, err)
	assert.NotNil(t, lastTimeLocal)

	err = os.WriteFile(nginxfile, []byte(`127.0.0.1 - - [44/ddd/2025:18:05:17 +0200] 1748793917.616 "GET / HTTP/1.1" 73 200 612 0.000 "curl/7.81.0"`), 0666)
	require.NoError(t, err)

	lastTimeLocal = time.Time{}
	lastTimeLocal, err = analyzer.Analyze(lastTimeLocal)
	assert.Nil(t, err)
	assert.NotNil(t, lastTimeLocal)

	err = os.WriteFile(nginxfile, []byte(`127.0.0.1 - - [01/Jun/2025:18:05:17 +0200] 1748793917.616 "GET / HTTP/1.1" 73 200 612 0.000 "curl/7.81.0"`), 0666)
	require.NoError(t, err)

	// insert log line
	lastTimeLocal = time.Time{}
	lastTimeLocal, err = analyzer.Analyze(lastTimeLocal)
	assert.Nil(t, err)
	assert.NotNil(t, lastTimeLocal)
	// skip insert as hash already exists
	lastTimeLocal, err = analyzer.Analyze(lastTimeLocal)
	assert.Nil(t, err)
	assert.NotNil(t, lastTimeLocal)

	// insert only first log line as the second has a lower date, reject first IP
	content := `8.8.8.8 - - [01/Jun/2025:18:05:17 +0200] 1748793917.616 "GET / HTTP/1.1" 73 444 612 0.000 "curl/7.81.0
	127.0.0.1 - - [01/Jun/2025:18:05:16 +0200] 1748792917.616 "GET / HTTP/1.1" 73 200 612 0.000 "curl/7.81.0"`
	err = os.WriteFile(nginxfile, []byte(content), 0666)
	require.NoError(t, err)
	lastTimeLocal = time.Time{}
	lastTimeLocal, err = analyzer.Analyze(lastTimeLocal)
	assert.Nil(t, err)
	assert.NotNil(t, lastTimeLocal)

}

func createConfigFile(t *testing.T, configFilename, logFilename, databaseFilename, accessLogfilename, goodRuleName, goodRuleCondition, badRuleName, badRuleCondition string) {
	data := `{
    "Nginx": {
        "AccessLogFilename": "{{.AccessLogFilename}}"
    },
    "Database": {
        "Filename": "{{.DatabaseFilename}}"
    },
    "Logger": {
        "Filename": "{{.LogFilename}}",
        "MaxSize": 10,
        "MaxAge": 7,
        "Verbose": true
    },
    "Rules": {
        "Good": [
            {
                "name": "{{.GoodRuleName}}",
                "condition": "{{.GoodRuleCondition}}"
            }
        ],
        "Bad": [
            {
                "name": "{{.BadRuleName}}",
                "condition": "{{.BadRuleCondition}}"
            }
		]
    }}`
	tmpl, err := template.New("test").Parse(data)
	require.NoError(t, err)
	file, err := os.Create(configFilename)
	require.NoError(t, err)
	var a struct {
		AccessLogFilename string
		DatabaseFilename  string
		LogFilename       string
		GoodRuleName      string
		GoodRuleCondition string
		BadRuleName       string
		BadRuleCondition  string
	}
	a.AccessLogFilename = accessLogfilename
	a.DatabaseFilename = databaseFilename
	a.LogFilename = logFilename
	a.GoodRuleName = goodRuleName
	a.GoodRuleCondition = goodRuleCondition
	a.BadRuleName = badRuleName
	a.BadRuleCondition = badRuleCondition
	err = tmpl.Execute(file, a)
	require.NoError(t, err)
	file.Close()
}
