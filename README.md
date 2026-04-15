# LiteProxy

A lightweight, QUIC-based port forwarding proxy with P2P NAT traversal support.

[中文文档](README_zh.md)

## Features

- **QUIC Transport** - All connections encrypted via QUIC with TLS 1.3, multiplexed streams for efficient forwarding
- **TCP & UDP Forwarding** - Forward both TCP and UDP ports through a central bridge relay
- **P2P NAT Traversal** - Direct peer-to-peer connections via STUN discovery and NAT hole punching, bypassing the bridge for data transfer
- **Cross-Platform** - Supports Windows, Linux, macOS (Intel & Apple Silicon), and Android

## Why LiteProxy?

| | LiteProxy | frp | nps |
|---|---|---|---|
| **P2P UDP** | Supported (`pudp`) | Not supported | Supported |
| **P2P Multiplexing** | QUIC multiplexed streams over a single P2P connection | N/A | Single connection per tunnel |
| **Forwarding Control** | Server-side defines routes — Client is a passive agent | Client-side specifies services to expose | Dashboard configuration |

### Server-Side Control

In frp, the **client** decides which local services to expose. In LiteProxy, the **Server** defines all routes (`-R`), and the Client simply acts as a passive agent — it doesn't need to know what will be forwarded. This makes deployment on the Client side minimal and configuration centralized.

### No Ports Exposed on the Public Server

With the Bridge-Server-Client three-tier design, the Bridge only handles QUIC signaling and relay — **no service ports are opened on the public server**. The services being forwarded are never directly reachable from the internet, making it a naturally private proxy.

### P2P with UDP and Multiplexing

frp does not support UDP over P2P. nps supports P2P but uses a single connection per tunnel. LiteProxy uses QUIC for P2P, providing both UDP forwarding (`pudp`) and multiplexed streams over a single NAT-traversed connection, reducing latency and connection overhead.

## How It Works

LiteProxy uses a **Bridge-Server-Client** architecture:

```
[Local Port] --> Server --> Bridge --> Client --> [Target Service]
```

| Component | Role |
|-----------|------|
| **Bridge** | Central relay that authenticates and routes connections between Server and Client |
| **Server** | Listens on local ports and forwards traffic through the Bridge to the Client |
| **Client** | Receives forwarded traffic and connects to local target services |

With P2P protocols (`ptcp`/`pudp`), the Server and Client establish a direct QUIC connection via NAT hole punching, using the Bridge only for signaling.

## Installation

### Download

Download pre-built binaries from [Releases](https://github.com/cr4n5/liteproxy/releases).

### Build from Source

Requires Go 1.24+.

```bash
go build -o liteproxy ./cmd/liteproxy
```

Cross-compile:

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o liteproxy ./cmd/liteproxy

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o liteproxy ./cmd/liteproxy

# Windows
GOOS=windows GOARCH=amd64 go build -o liteproxy.exe ./cmd/liteproxy
```

## Usage

### 1. Start the Bridge

```bash
liteproxy bridge -K "your_access_key" -A "0.0.0.0:10020"
```

### 2. Start the Client

```bash
liteproxy client -K "your_access_key" -A "bridge_host:10020" -id "my_client"
```

### 3. Start the Server

```bash
liteproxy server -K "your_access_key" -A "bridge_host:10020" -id "my_client" \
  -R "tcp://:8080@:80" \
  -R "udp://:10053@:53"
```

This forwards:
- TCP port `8080` on the Server to port `80` on the Client
- UDP port `10053` on the Server to port `53` on the Client

### Route Format

```
[PROTOCOL://][LOCAL_IP]:LOCAL_PORT@[CLIENT_HOST]:CLIENT_PORT
```

| Field | Default | Description |
|-------|---------|-------------|
| `PROTOCOL` | `tcp` | `tcp`, `udp`, `ptcp` (P2P TCP), `pudp` (P2P UDP) |
| `LOCAL_IP` | `0.0.0.0` | Address to listen on (Server side) |
| `CLIENT_HOST` | `127.0.0.1` | Target address (Client side) |

**Examples:**

```bash
-R "tcp://:8080@:80"            # TCP: Server:8080 -> Client:80
-R "udp://:10053@:53"           # UDP: Server:10053 -> Client:53
-R ":8080@:80"                  # Same as tcp://:8080@:80
-R "ptcp://:8080@:80"           # P2P TCP: direct connection, bridge only for signaling
-R "192.168.1.1:8080@10.0.0.1:80"  # Specify bind and target addresses
```

### Common Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-K` | (required) | Access key for authentication |
| `-A` | `127.0.0.1:10020` | Bridge address |
| `-id` | `client1` | Client identifier (Server and Client must match) |
| `-log` | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `-stun` | `stun.easyvoip.com:3478` | STUN server for P2P |
| `-pprof` | `false` | Enable pprof profiling on `localhost:6060` |

### Example: Forward SSH and DNS

```bash
# Bridge (on public server)
liteproxy bridge -K "secret" -A "0.0.0.0:10020"

# Client (on target machine with SSH and DNS)
liteproxy client -K "secret" -A "bridge.example.com:10020" -id "office"

# Server (on your local machine)
liteproxy server -K "secret" -A "bridge.example.com:10020" -id "office" \
  -R "tcp://:2222@:22" \
  -R "udp://:5353@:53"

# Now access SSH: ssh -p 2222 localhost
# And DNS: dig @localhost -p 5353 example.com
```

## License

[Apache License 2.0](LICENSE)
