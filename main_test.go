package main

import (
	"flag"
	"os"
	"path"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMainNoArgs(t *testing.T) {
	flag.CommandLine = flag.NewFlagSet("empty", flag.ExitOnError)
	flagConfig = flag.String("config", "", "config file")
	os.Args = []string{"goaccesslog"}
	ret := doMain()
	assert.Equal(t, 1, ret)
}

func TestMain(t *testing.T) {
	tempDir := t.TempDir()
	filename := path.Join(tempDir, "config.json")
	nginxfile := path.Join(tempDir, "test-nginx.log")
	logfile := path.Join(tempDir, "test.log")
	dbfile := path.Join(tempDir, "test.db")
	createConfigFile(t, filename, logfile, dbfile, nginxfile, "goodRule", "starts-with(ip,'127.')", "badrule", "eq(status,444)")

	flag.CommandLine = flag.NewFlagSet("goaccesslog", flag.ExitOnError)
	flagConfig = flag.String("config", "", "config file")
	os.Args = []string{"goaccesslog", "-config", filename}
	ret := doMain()
	assert.Equal(t, 2, ret)
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
