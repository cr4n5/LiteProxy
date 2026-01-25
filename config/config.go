package config

import (
	"flag"
	"fmt"
	"os"
)

type BaseConfig struct {
	BridgeAddr string
	AccessKey  string
}

type BridgeConfig struct {
	BaseConfig
}

type ServerConfig struct {
	BaseConfig
	ListenAddr string
	ClientID   string
	Target     string
	Type       string
}

type ClientConfig struct {
	BaseConfig
	ClientID string
}

type Config struct {
	Mode     string
	LogLevel string
	Bridge   *BridgeConfig
	Server   *ServerConfig
	Client   *ClientConfig
}

var config *Config

func ParseArgs() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: liteproxy [bridge|server|client] [flags]")
		os.Exit(1)
	}

	cmd := os.Args[1]
	accessKey := flag.String("accesskey", "", "access key for authentication")
	logLevel := flag.String("loglevel", "info", "logging level (trace, debug, info, warn, error)")
	bridgeAddr := flag.String("bridge", "127.0.0.1:10020", "bridge control address")
	baseConfig := BaseConfig{
		BridgeAddr: *bridgeAddr,
		AccessKey:  *accessKey,
	}
	config = &Config{
		LogLevel: *logLevel,
	}

	switch cmd {
	case "bridge":
		bridgeCmd := flag.NewFlagSet("bridge", flag.ExitOnError)
		bridgeCmd.Usage = func() {
			fmt.Println("Usage: liteproxy bridge [flags]")
			flag.PrintDefaults()
			bridgeCmd.PrintDefaults()
		}
		bridgeCmd.Parse(os.Args[2:])
		config.Mode = "bridge"
		config.Bridge = &BridgeConfig{BaseConfig: baseConfig}

	case "server":
		serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
		listenAddr := serverCmd.String("listen", "0.0.0.0:8080", "listen address for external connections")
		clientID := serverCmd.String("client", "client1", "target client ID")
		target := serverCmd.String("target", "127.0.0.1", "internal target host")
		typeFlag := serverCmd.String("type", "", "server type")
		serverCmd.Usage = func() {
			fmt.Println("Usage: liteproxy server [flags]")
			flag.PrintDefaults()
			serverCmd.PrintDefaults()
		}
		serverCmd.Parse(os.Args[2:])
		config.Mode = "server"
		config.Server = &ServerConfig{
			BaseConfig: baseConfig,
			ListenAddr: *listenAddr,
			ClientID:   *clientID,
			Target:     *target,
			Type:       *typeFlag,
		}

	case "client":
		clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
		clientID := clientCmd.String("client", "client1", "client identifier")
		clientCmd.Usage = func() {
			fmt.Println("Usage: liteproxy client [flags]")
			flag.PrintDefaults()
			clientCmd.PrintDefaults()
		}
		clientCmd.Parse(os.Args[2:])
		config.Mode = "client"
		config.Client = &ClientConfig{BaseConfig: baseConfig, ClientID: *clientID}

	default:
		fmt.Println("Unknown command:", cmd)
		fmt.Println("Available commands: bridge, server, client")
		os.Exit(1)
	}

	if *accessKey == "" {
		fmt.Println("Access key cannot be empty")
		os.Exit(1)
	}
}

func GetConfig() *Config {
	return config
}
