package app

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/nylssoft/goaccesslog/internal/analyzer"
	"github.com/nylssoft/goaccesslog/internal/config"
	"github.com/nylssoft/goaccesslog/internal/executer"
	"github.com/nylssoft/goaccesslog/internal/ufw"
)

func Run(configFilename string, shutdown chan bool) int {
	cfg := config.NewConfig()
	err := cfg.Init(configFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file. %v", err)
		return 2
	}
	ticker := time.NewTicker(60 * time.Second)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("FATAL: Failed to create file watcher. %v", err)
		return 3
	}
	defer watcher.Close()
	logDir := filepath.Dir(cfg.AccessLogFilename())
	executer := executer.NewExecuter()
	ufw := ufw.NewUfw(executer, "goaccesslog", time.Hour, 10)
	ufw.Init()
	ufw.ReleaseAll() // remove all previously locked IP addresses if the process did not terminate appropriately
	analyzer := analyzer.NewAnalyzer(cfg, ufw)
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
		update := false
		var lastTimeLocal time.Time
	loop:
		for {
			select {
			case sig := <-stop:
				log.Printf("Shutdown signal %v received.\n", sig)
				shutdown <- true
				break loop
			case event := <-watcher.Events:
				if !update && event.Has(fsnotify.Write) && event.Name == cfg.AccessLogFilename() {
					update = true
					if cfg.IsVerbose() {
						log.Println("Detected modified access log file. Analyze new access log entries on next schedule.")
					}
				}
			case <-ticker.C:
				if update {
					update = false
					lastTimeLocal, err = analyzer.Analyze(lastTimeLocal)
					if err != nil {
						log.Println("ERROR: Failed to analyze access log file.", err)
					}
				}
			case err := <-watcher.Errors:
				log.Println("ERROR: Failed to watch directory.", err)
			}
		}
	}()
	err = watcher.Add(logDir)
	if err != nil {
		log.Printf("FATAL: Failed to add directory to file watcher. %v", err)
		return 4
	}
	<-shutdown
	ufw.ReleaseAll()
	return 0
}
