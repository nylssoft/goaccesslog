package main

import (
	"flag"
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

var flagConfig = flag.String("config", "", "config file")

func main() {
	flag.Parse()
	if len(*flagConfig) == 0 {
		fmt.Println("Usage: goaccesslog -config <config-file>")
		os.Exit(1)
	}
	cfg := config.NewConfig()
	err := cfg.Init(*flagConfig)
	if err != nil {
		log.Fatal(err)
	}
	ticker := time.NewTicker(60 * time.Second)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("Failed to create file watcher.", err)
	}
	defer watcher.Close()
	logDir := filepath.Dir(cfg.AccessLogFilename())
	shutdown := make(chan bool, 1)
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
		log.Fatal("Failed to add directory to file watcher.", err)
	}
	<-shutdown
	ufw.ReleaseAll()
}
