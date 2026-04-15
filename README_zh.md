# LiteProxy

轻量级、基于 QUIC 的端口转发代理，支持 P2P NAT 穿透。

[English](README.md)

## 特性

- **QUIC 传输** - 所有连接通过 QUIC + TLS 1.3 加密，多路复用流实现高效转发
- **TCP & UDP 转发** - 通过中心化 Bridge 中继转发 TCP 和 UDP 端口
- **P2P NAT 穿透** - 通过 STUN 发现和 NAT 打洞建立点对点直连，数据传输绕过 Bridge
- **跨平台** - 支持 Windows、Linux、macOS（Intel 和 Apple Silicon）、Android

## 为什么选择 LiteProxy？

| | LiteProxy | frp | nps |
|---|---|---|---|
| **P2P UDP** | 支持（`pudp`） | 不支持 | 支持 |
| **P2P 多路复用** | 单条 P2P 连接上的 QUIC 多路复用流 | N/A | 每隧道单连接 |
| **转发控制** | Server 端定义路由 — Client 是被动代理 | Client 端指定要暴露的服务 | 面板配置 |

### Server 端控制

frp 中，由 **客户端** 决定暴露哪些本地服务。而 LiteProxy 中，由 **Server** 定义所有路由（`-R`），Client 只是一个被动代理 — 无需知道将要转发什么。这使得 Client 端部署极简，配置集中管理。

### 公网服务器零端口暴露

得益于 Bridge-Server-Client 三端设计，Bridge 仅处理 QUIC 信令和中继 — **公网服务器不开放任何服务端口**。被转发的服务永远无法从互联网直接访问，天然实现私密代理。

### P2P 支持 UDP 与多路复用

frp 的 P2P 不支持 UDP 转发。nps 支持 P2P 但每条隧道使用单独连接。LiteProxy 的 P2P 基于 QUIC，同时支持 UDP 转发（`pudp`）和在单条 NAT 穿透连接上的多路复用流，降低延迟和连接开销。

## 工作原理

LiteProxy 采用 **Bridge-Server-Client** 架构：

```
[本地端口] --> Server --> Bridge --> Client --> [目标服务]
```

| 组件 | 角色 |
|------|------|
| **Bridge** | 中心中继，负责认证和路由 Server 与 Client 之间的连接 |
| **Server** | 监听本地端口，将流量通过 Bridge 转发到 Client |
| **Client** | 接收转发的流量，连接到本地目标服务 |

使用 P2P 协议（`ptcp`/`pudp`）时，Server 和 Client 通过 NAT 打洞建立直接的 QUIC 连接，Bridge 仅用于信令交换。

## 安装

### 下载

从 [Releases](https://github.com/cr4n5/liteproxy/releases) 下载预编译的二进制文件。

### 从源码编译

需要 Go 1.24+。

```bash
go build -o liteproxy ./cmd/liteproxy
```

交叉编译：

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o liteproxy ./cmd/liteproxy

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o liteproxy ./cmd/liteproxy

# Windows
GOOS=windows GOARCH=amd64 go build -o liteproxy.exe ./cmd/liteproxy
```

## 使用方法

### 1. 启动 Bridge

```bash
liteproxy bridge -K "your_access_key" -A "0.0.0.0:10020"
```

### 2. 启动 Client

```bash
liteproxy client -K "your_access_key" -A "bridge_host:10020" -id "my_client"
```

### 3. 启动 Server

```bash
liteproxy server -K "your_access_key" -A "bridge_host:10020" -id "my_client" \
  -R "tcp://:8080@:80" \
  -R "udp://:10053@:53"
```

以上配置实现：
- Server 的 TCP 端口 `8080` 转发到 Client 的端口 `80`
- Server 的 UDP 端口 `10053` 转发到 Client 的端口 `53`

### 路由格式

```
[PROTOCOL://][LOCAL_IP]:LOCAL_PORT@[CLIENT_HOST]:CLIENT_PORT
```

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `PROTOCOL` | `tcp` | 可选：`tcp`、`udp`、`ptcp`（P2P TCP）、`pudp`（P2P UDP） |
| `LOCAL_IP` | `0.0.0.0` | Server 端监听地址 |
| `CLIENT_HOST` | `127.0.0.1` | Client 端目标地址 |

**示例：**

```bash
-R "tcp://:8080@:80"            # TCP：Server:8080 -> Client:80
-R "udp://:10053@:53"           # UDP：Server:10053 -> Client:53
-R ":8080@:80"                  # 等同于 tcp://:8080@:80
-R "ptcp://:8080@:80"           # P2P TCP：直连模式，Bridge 仅用于信令
-R "192.168.1.1:8080@10.0.0.1:80"  # 指定绑定地址和目标地址
```

### 通用参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-K` | （必填） | 认证密钥 |
| `-A` | `127.0.0.1:10020` | Bridge 地址 |
| `-id` | `client1` | 客户端标识（Server 和 Client 必须一致） |
| `-log` | `info` | 日志级别：`trace`、`debug`、`info`、`warn`、`error` |
| `-stun` | `stun.easyvoip.com:3478` | P2P 使用的 STUN 服务器 |
| `-pprof` | `false` | 启用 pprof 性能分析，监听 `localhost:6060` |

### 示例：转发 SSH 和 DNS

```bash
# Bridge（部署在公网服务器上）
liteproxy bridge -K "secret" -A "0.0.0.0:10020"

# Client（部署在有 SSH 和 DNS 服务的目标机器上）
liteproxy client -K "secret" -A "bridge.example.com:10020" -id "office"

# Server（部署在你的本地机器上）
liteproxy server -K "secret" -A "bridge.example.com:10020" -id "office" \
  -R "tcp://:2222@:22" \
  -R "udp://:5353@:53"

# 现在可以访问 SSH：ssh -p 2222 localhost
# 以及 DNS：dig @localhost -p 5353 example.com
```

## 许可证

[Apache License 2.0](LICENSE)
