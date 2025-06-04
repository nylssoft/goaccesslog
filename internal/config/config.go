package config

type Config interface {
	Init(filename string) error
	IsVerbose() bool
	AccessLogFilename() string
	DatabaseFilename() string
	IsMaliciousRequest(ip string, uri string, status int) bool
}

func NewConfig() Config {
	var cfg config_impl
	return &cfg
}
