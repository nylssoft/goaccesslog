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
	"github.com/nylssoft/goaccesslog/internal/config"
	"github.com/nylssoft/goaccesslog/internal/database"
	"github.com/nylssoft/goaccesslog/internal/ufw"
)

var flagConfig = flag.String("config", "", "config file")

func main() {
	flag.Parse()
	if len(*flagConfig) == 0 {
		fmt.Println("Usage: goaccesslog -config <config-file>")
		os.Exit(1)
	}
	cfg, err := config.NewConfig(*flagConfig)
	if err != nil {
		fmt.Println("ERROR: ", err)
		os.Exit(1)
	}
	ticker := time.NewTicker(60 * time.Second)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal("Failed to create file watcher.", err)
	}
	defer watcher.Close()
	logDir := filepath.Dir(cfg.Nginx.AccessLogFilename)
	shutdown := make(chan bool, 1)
	locks := ufw.NewLocks()
	// remove all previously locked IP addresses if the process did not terminate appropriately
	locks.UnlockAll()
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
				if !update && event.Has(fsnotify.Write) && event.Name == cfg.Nginx.AccessLogFilename {
					update = true
					if cfg.Logger.Verbose {
						log.Println("Detected modified log file. Update database on next schedule.")
					}
				}
			case <-ticker.C:
				if update {
					update = false
					lastTimeLocal, err = database.Update(cfg, locks, lastTimeLocal)
					if err != nil {
						log.Println("ERROR: Failed to update database.", err)
					}
					locks.UnlockIfExpired()
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
	locks.UnlockAll()
}
