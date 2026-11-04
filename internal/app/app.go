package app

import (
	"context"
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
	"github.com/nylssoft/goaccesslog/internal/rce"
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
	defer ticker.Stop()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("FATAL: Failed to create file watcher. %v", err)
		return 3
	}
	defer watcher.Close()
	logDir := filepath.Dir(cfg.AccessLogFilename())
	if err := watcher.Add(logDir); err != nil {
		log.Printf("FATAL: Failed to add directory to file watcher. %v", err)
		return 4
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	monitor, err := rce.New(ctx, cfg.RCEProtection())
	if err != nil {
		log.Printf("FATAL: Failed to initialize RCE protection. %v", err)
		return 5
	}
	if err := monitor.Check(ctx); err != nil {
		log.Printf("FATAL: RCE protection startup check failed. %v", err)
		return 5
	}
	executer := executer.NewExecuter()
	ufw := ufw.NewUfw(executer, "goaccesslog", time.Hour, 10)
	ufw.Init()
	if !monitor.Locked() {
		ufw.ReleaseAll()
	}
	analyzer := analyzer.NewAnalyzer(cfg, ufw)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		monitor.Run(ctx)
	}()
	defer func() {
		cancel()
		<-monitorDone
		if !monitor.Locked() {
			ufw.ReleaseAll()
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	update := false
	var lastTimeLocal time.Time
	for {
		select {
		case <-shutdown:
			return 0
		case sig := <-stop:
			log.Printf("Shutdown signal %v received.\n", sig)
			return 0
		case event, open := <-watcher.Events:
			if !open {
				return 0
			}
			if !update && event.Has(fsnotify.Write) && event.Name == cfg.AccessLogFilename() {
				update = true
				if cfg.IsVerbose() {
					log.Println("Detected modified access log file. Analyze new access log entries on next schedule.")
				}
			}
		case <-ticker.C:
			if update && !monitor.Locked() {
				update = false
				lastTimeLocal, err = analyzer.Analyze(lastTimeLocal)
				if err != nil {
					log.Println("ERROR: Failed to analyze access log file.", err)
				}
			}
		case err, open := <-watcher.Errors:
			if !open {
				return 0
			}
			log.Println("ERROR: Failed to watch directory.", err)
		}
	}
}
