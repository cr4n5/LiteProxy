package main

import (
	"context"

	"github.com/cr4n5/liteproxy/config"
	"github.com/cr4n5/liteproxy/logger"
)

func main() {
	config.ParseArgs()
	cfg := config.GetConfig()
	// Initialize logger
	logger.Init(cfg.LogLevel)
	ctx := context.Background()

	switch cfg.Mode {
	//
	}
}
