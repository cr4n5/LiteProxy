package config

import (
	"flag"
	"fmt"
	"os"
)

type Config struct {
	Mode       string
	LogLevel   string
	BridgeAddr string
	ListenAddr string
	AccessKey  string
	ClientID   string
	Target     string
	Type       string
}

var config *Config

func registerCommonFlags(fs *flag.FlagSet) (*string, *string, *string) {
	accessKey := fs.String("K", "", "access key for authentication")
	bridgeAddr := fs.String("A", "127.0.0.1:10020", "bridge control address")
	logLevel := fs.String("loglevel", "info", "logging level (trace, debug, info, warn, error)")
	return accessKey, bridgeAddr, logLevel
}

func applyCommonConfig(accessKey, bridgeAddr, logLevel string) {
	config.AccessKey = accessKey
	config.BridgeAddr = bridgeAddr
	config.LogLevel = logLevel
}

func ParseArgs() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: liteproxy [bridge|server|client] [flags]")
		os.Exit(1)
	}

	cmd := os.Args[1]
	config = &Config{}

	switch cmd {
	case "bridge":
		bridgeCmd := flag.NewFlagSet("bridge", flag.ExitOnError)
		accessKey, bridgeAddr, logLevel := registerCommonFlags(bridgeCmd)
		bridgeCmd.Usage = func() {
			fmt.Println("Usage: liteproxy bridge [flags]")
			bridgeCmd.PrintDefaults()
		}
		bridgeCmd.Parse(os.Args[2:])
		config.Mode = "bridge"
		applyCommonConfig(*accessKey, *bridgeAddr, *logLevel)

	case "server":
		serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
		accessKey, bridgeAddr, logLevel := registerCommonFlags(serverCmd)
		listenAddr := serverCmd.String("listen", "0.0.0.0:8080", "listen address for external connections")
		clientID := serverCmd.String("id", "client1", "target client ID")
		target := serverCmd.String("target", "127.0.0.1", "internal target host")
		typeFlag := serverCmd.String("type", "", "server type")
		serverCmd.Usage = func() {
			fmt.Println("Usage: liteproxy server [flags]")
			serverCmd.PrintDefaults()
		}
		serverCmd.Parse(os.Args[2:])
		config.Mode = "server"
		applyCommonConfig(*accessKey, *bridgeAddr, *logLevel)
		config.ListenAddr = *listenAddr
		config.ClientID = *clientID
		config.Target = *target
		config.Type = *typeFlag

	case "client":
		clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
		accessKey, bridgeAddr, logLevel := registerCommonFlags(clientCmd)
		clientID := clientCmd.String("id", "client1", "client identifier")
		clientCmd.Usage = func() {
			fmt.Println("Usage: liteproxy client [flags]")
			clientCmd.PrintDefaults()
		}
		clientCmd.Parse(os.Args[2:])
		config.Mode = "client"
		applyCommonConfig(*accessKey, *bridgeAddr, *logLevel)
		config.ClientID = *clientID

	default:
		fmt.Println("Unknown command:", cmd)
		fmt.Println("Available commands: bridge, server, client")
		os.Exit(1)
	}

	if config.AccessKey == "" {
		fmt.Println("Access key cannot be empty")
		os.Exit(1)
	}
}

func GetConfig() *Config {
	return config
}
