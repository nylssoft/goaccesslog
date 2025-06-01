package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"gopkg.in/natefinch/lumberjack.v2"
)

// public

type ConfigRule struct {
	Name      string `json:"name"`
	Condition string `json:"condition"`
}

type Config struct {
	Expressions map[string][]Expression
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
		Good []ConfigRule `json:"Good"`
		Bad  []ConfigRule `json:"Bad"`
	} `json:"rules"`
}

func NewConfig(filename string) (*Config, error) {
	var config Config
	data, err := os.ReadFile(filename)
	if err == nil {
		err = json.Unmarshal(data, &config)
	}
	if err != nil {
		return nil, err
	}
	config.Expressions = make(map[string][]Expression)
	var expressions []Expression
	fmt.Println("Copies nginx access log file entries into sqlite database and locks malicious IP addresses.")
	fmt.Println("  config file          :", filename)
	fmt.Println("  log file             :", config.Logger.Filename)
	fmt.Println("  nginx access log file:", config.Nginx.AccessLogFilename)
	fmt.Println("  sqlite database file :", config.Database.Filename)
	err = canWriteFile(config.Logger.Filename, "log")
	if err == nil {
		err = canWriteFile(config.Database.Filename, "database")
	}
	if err == nil {
		err = canReadFile(config.Nginx.AccessLogFilename, "nginx access log")
	}
	if err == nil {
		for _, goodrule := range config.Rules.Good {
			expressions, err = ParseCondition(goodrule.Condition)
			if err != nil {
				break
			}
			config.Expressions[goodrule.Name] = expressions
		}
	}
	if err == nil {
		for _, badrule := range config.Rules.Bad {
			expressions, err = ParseCondition(badrule.Condition)
			if err != nil {
				break
			}
			config.Expressions[badrule.Name] = expressions
		}
	}
	if err != nil {
		return nil, err
	}
	log.SetOutput(&lumberjack.Logger{
		Filename: config.Logger.Filename,
		MaxSize:  config.Logger.MaxSize,
		MaxAge:   config.Logger.MaxAge,
		Compress: true})
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.Println("goaccesslog version 0.2.4")
	log.Println()
	log.Println("Note: nginx log format is expected to be")
	log.Println("  log_format noreferer '$remote_addr - $remote_user [$time_local] $msec \"$request\" $request_length $status $body_bytes_sent $request_time \"$http_user_agent\"';")
	log.Println()
	log.Println("Rules to detect malicious requests:")
	for _, badrule := range config.Rules.Bad {
		log.Printf("  %s: %s\n", badrule.Name, badrule.Condition)
	}
	log.Println()
	log.Println("Rules to detect valid requests (overwrite malicious requests):")
	for _, goodrule := range config.Rules.Good {
		log.Printf("  %s: %s\n", goodrule.Name, goodrule.Condition)
	}
	log.Println()
	return &config, nil
}

func (cfg *Config) IsMaliciousRequest(ip string, uri string, status int) bool {
	data := map[Property]any{}
	data[PROP_IP] = ip
	data[PROP_STATUS] = status
	data[PROP_URI] = uri
	var isMalicious bool
	// evaluate whether request is considered as malicious
	for _, badrule := range cfg.Rules.Bad {
		isMalicious = EvaluateExpressions(cfg.Expressions[badrule.Name], data)
		if isMalicious {
			log.Printf("Detected malicious request for bad rule '%s'. IP %s, Status %d, URI '%s'.\n", badrule.Name, ip, status, uri)
			break
		}
	}
	// good rules overwrite bad rules
	if isMalicious {
		for _, goodrule := range cfg.Rules.Good {
			if EvaluateExpressions(cfg.Expressions[goodrule.Name], data) {
				log.Printf("Overwrite request using good rule '%s'.\n", goodrule.Name)
				isMalicious = false
				break
			}
		}
	}
	return isMalicious
}

// private

func canReadFile(filename string, desc string) error {
	return canOpenFile(filename, desc, true)
}

func canWriteFile(filename string, desc string) error {
	return canOpenFile(filename, desc, false)
}

func canOpenFile(filename string, desc string, readonly bool) error {
	if len(filename) == 0 {
		return errors.New("missing " + desc + " filename in config")
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
