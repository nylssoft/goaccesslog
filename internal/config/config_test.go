package config

import (
	"os"
	"path"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	tempDir := t.TempDir()
	filename := path.Join(tempDir, "test-invalid.json")

	// config constructor
	config := NewConfig()
	assert.NotNil(t, config)

	// file not found
	err := config.Init("fiiledoesnotexist.json")
	assert.Error(t, err)

	// json parse error
	err = os.WriteFile(filename, []byte(`content`), 0666)
	require.NoError(t, err)
	err = config.Init(filename)
	assert.Error(t, err)

	goodRuleName := ""
	goodRuleCondition := ""
	badRuleName := ""
	badRuleCondition := ""
	// missing log filename in config
	filename = path.Join(tempDir, "config.json")
	createConfigFile(t, filename, "", "", "", goodRuleName, goodRuleCondition, badRuleName, badRuleCondition)
	err = config.Init(filename)
	assert.Error(t, err)

	// missing database filename in config
	logfile := path.Join(tempDir, "test.log")
	createConfigFile(t, filename, logfile, "", "", goodRuleName, goodRuleCondition, badRuleName, badRuleCondition)
	err = config.Init(filename)
	assert.Error(t, err)

	// missing nginx access log filename in config
	dbfile := path.Join(tempDir, "test.db")
	createConfigFile(t, filename, logfile, dbfile, "", goodRuleName, goodRuleCondition, badRuleName, badRuleCondition)
	err = config.Init(filename)
	assert.Error(t, err)

	// missing nginx access log filename does not exist
	nginxfile := path.Join(tempDir, "test-nginx.log")
	createConfigFile(t, filename, logfile, dbfile, nginxfile, goodRuleName, goodRuleCondition, badRuleName, badRuleCondition)
	err = config.Init(filename)
	assert.Error(t, err)

	// missing rule name
	err = os.WriteFile(nginxfile, []byte(""), 0666)
	require.NoError(t, err)
	createConfigFile(t, filename, logfile, dbfile, nginxfile, goodRuleName, goodRuleCondition, badRuleName, badRuleCondition)
	err = config.Init(filename)
	assert.Error(t, err)

	// missing condition
	goodRuleName = "valid-ips"
	badRuleName = "hex-requests"
	createConfigFile(t, filename, logfile, dbfile, nginxfile, goodRuleName, goodRuleCondition, badRuleName, badRuleCondition)
	err = config.Init(filename)
	assert.Error(t, err)

	// invalid good condition
	goodRuleCondition = `starts-with( ip, 127)`
	createConfigFile(t, filename, logfile, dbfile, nginxfile, goodRuleName, goodRuleCondition, badRuleName, badRuleCondition)
	err = config.Init(filename)
	assert.Error(t, err)

	// invalid bad condition
	goodRuleCondition = `starts-with( ip, '127')`
	badRuleCondition = `contains( uri, \x)`
	createConfigFile(t, filename, logfile, dbfile, nginxfile, goodRuleName, goodRuleCondition, badRuleName, badRuleCondition)
	err = config.Init(filename)
	assert.Error(t, err)

	// valid condition, no error
	goodRuleCondition = "starts-with( ip, '127')"
	badRuleCondition = `contains( uri, '\\x')`
	createConfigFile(t, filename, logfile, dbfile, nginxfile, goodRuleName, goodRuleCondition, badRuleName, badRuleCondition)
	err = config.Init(filename)
	assert.NoError(t, err)
	assert.True(t, config.IsVerbose())
	assert.Equal(t, nginxfile, config.AccessLogFilename())
	assert.Equal(t, dbfile, config.DatabaseFilename())

	// rule with sane name reused
	badRuleName = goodRuleName
	createConfigFile(t, filename, logfile, dbfile, nginxfile, goodRuleName, goodRuleCondition, badRuleName, badRuleCondition)
	err = config.Init(filename)
	assert.Error(t, err)

}

func TestIsMaliciousRequest(t *testing.T) {
	// prepare valid config
	tempDir := t.TempDir()
	filename := path.Join(tempDir, "config.json")
	logfile := path.Join(tempDir, "test.log")
	dbfile := path.Join(tempDir, "test.db")
	nginxfile := path.Join(tempDir, "test-nginx.log")
	err := os.WriteFile(nginxfile, []byte(""), 0666)
	require.NoError(t, err)
	goodRuleName := "valid-ips"
	badRuleName := "hex-requests"
	goodCondition := "starts-with( ip, '127')"
	badCondition := `contains( uri, '\\x')`
	config := NewConfig()
	createConfigFile(t, filename, logfile, dbfile, nginxfile, goodRuleName, goodCondition, badRuleName, badCondition)
	err = config.Init(filename)
	require.NoError(t, err)

	ret := config.IsMaliciousRequest("127.0.0.1", "GET", "index.html", 200)
	assert.False(t, ret)
	ret = config.IsMaliciousRequest("127.0.0.1", "GET", "\\x00", 400)
	assert.False(t, ret)
	ret = config.IsMaliciousRequest("8.8.8.8", "GET", "\\x00", 400)
	assert.True(t, ret)
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
