package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nylssoft/goaccesslog/internal/app"
)

var flagConfig = flag.String("config", "", "config file")

func main() {
	os.Exit(doMain())
}

func doMain() int {
	flag.Parse()
	if len(*flagConfig) == 0 {
		fmt.Println("Usage: goaccesslog -config <config-file>")
		return 1
	}
	return app.Run(*flagConfig, make(chan bool, 1))
}
