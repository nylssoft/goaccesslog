package analyzer

import (
	"time"

	"github.com/nylssoft/goaccesslog/internal/config"
	"github.com/nylssoft/goaccesslog/internal/ufw"
)

type Analyzer interface {
	Analyze(lastTimeLocal time.Time) (time.Time, error)
}

func NewAnalyzer(cfg config.Config, ufw ufw.Ufw) Analyzer {
	var analyzer analyzer_impl
	analyzer.config = cfg
	analyzer.ufw = ufw
	return &analyzer
}
