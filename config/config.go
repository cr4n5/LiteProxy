package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cr4n5/liteproxy/common"
)

type RouteConfig struct {
	Protocol        string // tcp, udp, ptcp, pudp
	LocalIP         string // default 0.0.0.0
	LocalPort       string // default local port
	ClientLocalHost string // default 127.0.0.1
	ClientLocalPort string // default client local port
	LocalAddr       string // full local listen address (IP:port)
	ClientAddr      string // full client address (IP:port)
}

type Config struct {
	Mode         string
	LogLevel     string
	BridgeAddr   string
	AccessKey    string
	ClientID     string
	Routes       []RouteConfig // route configuration list
	StunServer   string
	PprofEnabled bool
}

var config *Config

func registerCommonFlags(fs *flag.FlagSet) (*string, *string, *string, *bool) {
	accessKey := fs.String("K", "", "access key for authentication")
	bridgeAddr := fs.String("A", "127.0.0.1:10020", "bridge control address")
	logLevel := fs.String("log", "info", "logging level (trace, debug, info, warn, error)")
	pprofFlag := fs.Bool("pprof", false, "enable pprof profiling")
	return accessKey, bridgeAddr, logLevel, pprofFlag
}

func applyCommonConfig(accessKey, bridgeAddr, logLevel string, pprofEnabled bool) {
	config.AccessKey = accessKey
	config.BridgeAddr = bridgeAddr
	config.LogLevel = logLevel
	config.PprofEnabled = pprofEnabled
}

// parseRoute  -R ：PROTOCOL://LOCAL_IP:LOCAL_PORT@CLIENT_LOCAL_HOST:CLIENT_LOCAL_PORT
// Examples:
//
//	udp://:10053@:53          -> protocol=udp, localIP=0.0.0.0, localPort=10053, clientHost=127.0.0.1, clientPort=53
//	tcp://:10800@:1080        -> protocol=tcp, localIP=0.0.0.0, localPort=10800, clientHost=127.0.0.1, clientPort=1080
//	:8080@:80                 -> protocol=tcp(default), localIP=0.0.0.0, localPort=8080, clientHost=127.0.0.1, clientPort=80
func parseRoute(routeStr string) (RouteConfig, error) {
	route := RouteConfig{}
	protocol := "tcp" // default protocol
	// Check if protocol header is present
	if strings.Contains(routeStr, "://") {
		parts := strings.SplitN(routeStr, "://", 2)
		protocol = strings.ToLower(parts[0])
		routeStr = parts[1]
		// Validate protocol
		if protocol != "tcp" && protocol != "udp" && protocol != "ptcp" && protocol != "pudp" {
			return route, fmt.Errorf("unsupported protocol: %s", protocol)
		}
	}
	// Separate local part and client part (LOCAL:PORT@CLIENT_HOST:PORT)
	if !strings.Contains(routeStr, "@") {
		return route, fmt.Errorf("invalid route format, missing '@' separator: %s", routeStr)
	}

	parts := strings.SplitN(routeStr, "@", 2)
	localPart := parts[0]
	clientPart := parts[1]

	// Parse local part
	localIP := "0.0.0.0"
	localPort := ""
	if strings.Contains(localPart, ":") {
		ipPort := strings.SplitN(localPart, ":", 2)
		if ipPort[0] != "" {
			localIP = ipPort[0]
		}
		localPort = ipPort[1]
	} else {
		localPort = localPart
	}

	if localPort == "" {
		return route, fmt.Errorf("invalid route format, local port cannot be empty: %s", routeStr)
	}

	// Parse client part
	clientHost := "127.0.0.1"
	clientPort := ""
	if strings.Contains(clientPart, ":") {
		hostPort := strings.SplitN(clientPart, ":", 2)
		if hostPort[0] != "" {
			clientHost = hostPort[0]
		}
		clientPort = hostPort[1]
	} else {
		clientPort = clientPart
	}

	if clientPort == "" {
		return route, fmt.Errorf("invalid route format, client port cannot be empty: %s", routeStr)
	}

	// Validate port numbers
	if _, err := net.LookupPort("tcp", localPort); err != nil {
		return route, fmt.Errorf("invalid local port: %s", localPort)
	}
	if _, err := net.LookupPort("tcp", clientPort); err != nil {
		return route, fmt.Errorf("invalid client port: %s", clientPort)
	}

	route.Protocol = protocol
	route.LocalIP = localIP
	route.LocalPort = localPort
	route.ClientLocalHost = clientHost
	route.ClientLocalPort = clientPort
	route.LocalAddr = net.JoinHostPort(localIP, localPort)
	route.ClientAddr = net.JoinHostPort(clientHost, clientPort)

	return route, nil
}

func ParseArgs() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: liteproxy [bridge|server|client|version] [flags]")
		os.Exit(1)
	}

	cmd := os.Args[1]
	config = &Config{}

	switch cmd {
	case "version":
		fmt.Printf("LiteProxy Version: %s\n", common.Version)
		os.Exit(0)
	case "bridge":
		config.Mode = "bridge"

		bridgeCmd := flag.NewFlagSet("bridge", flag.ExitOnError)
		accessKey, bridgeAddr, logLevel, pprofFlag := registerCommonFlags(bridgeCmd)

		bridgeCmd.Usage = func() {
			fmt.Println("Usage: liteproxy bridge [flags]")
			bridgeCmd.PrintDefaults()
		}

		bridgeCmd.Parse(os.Args[2:])
		applyCommonConfig(*accessKey, *bridgeAddr, *logLevel, *pprofFlag)

	case "server":
		config.Mode = "server"

		serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
		accessKey, bridgeAddr, logLevel, pprofFlag := registerCommonFlags(serverCmd)
		clientID := serverCmd.String("id", "client1", "target client ID")
		stunServer := serverCmd.String("stun", "stun.easyvoip.com:3478", "STUN server address")
		// Support multiple -R flags
		var routeStrs []string
		serverCmd.Func("R", "route configuration (can be used multiple times)", func(s string) error {
			routeStrs = append(routeStrs, s)
			return nil
		})

		serverCmd.Usage = func() {
			fmt.Println("Usage: liteproxy server [flags]")
			fmt.Println("  -R ROUTE                      Route configuration (supports multiple)")
			fmt.Println("       Format: [PROTOCOL://]LOCAL_IP:LOCAL_PORT@CLIENT_LOCAL_HOST:CLIENT_LOCAL_PORT")
			fmt.Println("       Protocol: tcp, udp, ptcp, pudp (default: tcp)")
			fmt.Println("       LOCAL_IP: empty defaults to 0.0.0.0")
			fmt.Println("       CLIENT_LOCAL_HOST: empty defaults to 127.0.0.1")
			fmt.Println("       Examples:")
			fmt.Println("         -R 'udp://:10053@:53'")
			fmt.Println("         -R 'tcp://:10800@:1080'")
			fmt.Println("         -R ':8080@:80'")
			serverCmd.PrintDefaults()
		}

		serverCmd.Parse(os.Args[2:])
		applyCommonConfig(*accessKey, *bridgeAddr, *logLevel, *pprofFlag)
		config.ClientID = *clientID
		config.StunServer = *stunServer
		config.Routes = make([]RouteConfig, 0)
		// If -R parameter is provided, use the parsed route configurations
		if len(routeStrs) > 0 {
			for _, routeStr := range routeStrs {
				route, err := parseRoute(routeStr)
				if err != nil {
					fmt.Printf("Error parsing route '%s': %v\n", routeStr, err)
					os.Exit(1)
				}
				config.Routes = append(config.Routes, route)
			}
		} else {
			fmt.Println("At least one -R route configuration is required for server mode")
			os.Exit(1)
		}

	case "client":
		config.Mode = "client"

		clientCmd := flag.NewFlagSet("client", flag.ExitOnError)
		accessKey, bridgeAddr, logLevel, pprofFlag := registerCommonFlags(clientCmd)
		clientID := clientCmd.String("id", "client1", "client identifier")
		stunServer := clientCmd.String("stun", "stun.easyvoip.com:3478", "STUN server address")

		clientCmd.Usage = func() {
			fmt.Println("Usage: liteproxy client [flags]")
			clientCmd.PrintDefaults()
		}

		clientCmd.Parse(os.Args[2:])
		applyCommonConfig(*accessKey, *bridgeAddr, *logLevel, *pprofFlag)
		config.ClientID = *clientID
		config.StunServer = *stunServer

	default:
		fmt.Println("Unknown command:", cmd)
		fmt.Println("Available commands: bridge, server, client, version")
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
