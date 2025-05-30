package config

import (
	"encoding/json"
	"log"
	"os"

	"gopkg.in/natefinch/lumberjack.v2"
)

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

func NewConfig(filename string) *Config {
	var config Config
	data, err := os.ReadFile(filename)
	if err == nil {
		err = json.Unmarshal(data, &config)
	}
	if err != nil {
		log.Printf("WARN: Failed to read config file '%s'. %s\n", filename, err.Error())
	}
	config.Expressions = make(map[string][]Expression)
	for _, goodrule := range config.Rules.Good {
		config.Expressions[goodrule.Name] = ParseCondition(goodrule.Condition)
	}
	for _, badrule := range config.Rules.Bad {
		config.Expressions[badrule.Name] = ParseCondition(badrule.Condition)
	}
	if len(config.Nginx.AccessLogFilename) == 0 {
		config.Nginx.AccessLogFilename = "/var/log/nginx/access.log"
	}
	if len(config.Database.Filename) == 0 {
		config.Database.Filename = "/var/log/goaccesslog.db"
	}
	if len(config.Logger.Filename) == 0 {
		config.Logger.Filename = "/var/log/goaccesslog.log"
	}
	log.SetOutput(&lumberjack.Logger{
		Filename: config.Logger.Filename,
		MaxSize:  config.Logger.MaxSize,
		MaxAge:   config.Logger.MaxAge,
		Compress: true})
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.Println("goaccesslog version 0.2.3")
	log.Println("-------------------------")
	log.Println("Copies nginx access log file entries into sqlite database and locks malicious IP addresses.")
	log.Println("  config file     :", filename)
	log.Println("  nginx access log:", config.Nginx.AccessLogFilename)
	log.Println("  sqlite database :", config.Database.Filename)
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
	log.Println("-------------------------")
	return &config
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
