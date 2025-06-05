package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/nylssoft/goaccesslog/internal/rule"
	"gopkg.in/natefinch/lumberjack.v2"
)

type configRule struct {
	Name      string `json:"name"`
	Condition string `json:"condition"`
}

type config_impl struct {
	Expressions map[string][]rule.Expression
	Nginx       struct {
		AccessLogFilename string `json:"accessLogFilename"`
	} `json:"nginx"`
	Database struct {
		Filename string `json:"filename"`
	} `json:"database"`
	Logger struct {
		Filename string `json:"filename"`
		MaxSize  int    `json:"maxsize"`
		MaxAge   int    `json:"maxage"`
		Verbose  bool   `json:"verbose"`
	} `json:"logger"`
	Rules struct {
		Good []configRule `json:"good"`
		Bad  []configRule `json:"bad"`
	} `json:"rules"`
}

func (cfg *config_impl) Init(filename string) error {
	data, err := os.ReadFile(filename)
	if err == nil {
		err = json.Unmarshal(data, &cfg)
	}
	if err != nil {
		return err
	}
	fmt.Println("Copies nginx access log file entries into sqlite database and locks malicious IP addresses.")
	fmt.Println("  config file          :", filename)
	fmt.Println("  log file             :", cfg.Logger.Filename)
	fmt.Println("  nginx access log file:", cfg.Nginx.AccessLogFilename)
	fmt.Println("  sqlite database file :", cfg.Database.Filename)
	err = canWriteFile(cfg.Logger.Filename, "log")
	if err == nil {
		err = canWriteFile(cfg.Database.Filename, "database")
	}
	if err == nil {
		err = canReadFile(cfg.Nginx.AccessLogFilename, "nginx access log")
	}
	if err == nil {
		err = cfg.updateExpressions()
	}
	if err != nil {
		return err
	}
	log.SetOutput(&lumberjack.Logger{
		Filename: cfg.Logger.Filename,
		MaxSize:  cfg.Logger.MaxSize,
		MaxAge:   cfg.Logger.MaxAge,
		Compress: true})
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.Println("goaccesslog version 0.2.6")
	log.Println()
	log.Println("Note: nginx log format is expected to be")
	log.Println("  log_format noreferer '$remote_addr - $remote_user [$time_local] $msec \"$request\" $request_length $status $body_bytes_sent $request_time \"$http_user_agent\"';")
	log.Println()
	log.Println("Rules to detect malicious requests:")
	for _, badrule := range cfg.Rules.Bad {
		log.Printf("  %s: %s\n", badrule.Name, badrule.Condition)
	}
	log.Println()
	log.Println("Rules to detect valid requests (overwrite malicious requests):")
	for _, goodrule := range cfg.Rules.Good {
		log.Printf("  %s: %s\n", goodrule.Name, goodrule.Condition)
	}
	log.Println()
	return nil
}

func (cfg *config_impl) IsVerbose() bool {
	return cfg.Logger.Verbose
}

func (cfg *config_impl) AccessLogFilename() string {
	return cfg.Nginx.AccessLogFilename
}

func (cfg *config_impl) DatabaseFilename() string {
	return cfg.Database.Filename
}

func (cfg *config_impl) IsMaliciousRequest(ip string, protocol string, uri string, status int) bool {
	data := map[rule.Property]any{}
	data[rule.PROP_IP] = ip
	data[rule.PROP_PROTOCOL] = protocol
	data[rule.PROP_URI] = uri
	data[rule.PROP_STATUS] = status
	var isMalicious bool
	// evaluate whether request is considered as malicious
	for _, badrule := range cfg.Rules.Bad {
		isMalicious = rule.EvaluateExpressions(cfg.Expressions[badrule.Name], data)
		if isMalicious {
			log.Printf("Detected malicious request for bad rule '%s'. IP %s, Status %d, URI '%s'.\n", badrule.Name, ip, status, uri)
			break
		}
	}
	// good rules overwrite bad rules
	if isMalicious {
		for _, goodrule := range cfg.Rules.Good {
			if rule.EvaluateExpressions(cfg.Expressions[goodrule.Name], data) {
				log.Printf("Overwrite request using good rule '%s'.\n", goodrule.Name)
				isMalicious = false
				break
			}
		}
	}
	return isMalicious
}

func (config *config_impl) updateExpressions() error {
	config.Expressions = make(map[string][]rule.Expression)
	for _, rules := range [][]configRule{config.Rules.Good, config.Rules.Bad} {
		for _, rule := range rules {
			expressions, err := parseRule(rule)
			if err != nil {
				return err
			}
			if _, contains := config.Expressions[rule.Name]; contains {
				return fmt.Errorf("rule name '%s' is not unique", rule.Name)
			}
			config.Expressions[rule.Name] = expressions
		}
	}
	return nil
}

func parseRule(cr configRule) ([]rule.Expression, error) {
	if len(cr.Name) == 0 {
		return nil, errors.New("missing 'name' in rule definition")
	}
	if len(cr.Condition) == 0 {
		return nil, errors.New("missing 'condition' in rule definition")
	}
	expressions, err := rule.ParseCondition(cr.Condition)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rule '%s': %s", cr.Name, err.Error())
	}
	return expressions, err
}

func canReadFile(filename string, desc string) error {
	return canOpenFile(filename, desc, true)
}

func canWriteFile(filename string, desc string) error {
	return canOpenFile(filename, desc, false)
}

func canOpenFile(filename string, desc string, readonly bool) error {
	if len(filename) == 0 {
		return fmt.Errorf("missing %s filename in config", desc)
	}
	var err error
	var file *os.File
	if readonly {
		file, err = os.Open(filename)
	} else {
		file, err = os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0640)
	}
	if err == nil {
		file.Close()
	}
	return err
}
