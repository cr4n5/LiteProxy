package main

import (
	"context"

	"github.com/cr4n5/liteproxy/common"
	"github.com/cr4n5/liteproxy/config"
	"github.com/cr4n5/liteproxy/pkg/bridge"
	"github.com/cr4n5/liteproxy/pkg/client"
	"github.com/cr4n5/liteproxy/pkg/server"
)

func main() {
	config.ParseArgs()
	cfg := config.GetConfig()
	// Initialize logger
	common.LogInit(cfg.LogLevel)

	ctx := context.Background()

	switch cfg.Mode {
	case "bridge":
		bridge := bridge.NewBridge(cfg)
		bridge.Start(ctx)
	case "client":
		client := client.NewClient(cfg)
		client.Start(ctx)
	case "server":
		server := server.NewServer(cfg)
		server.Start(ctx)
	}
}
