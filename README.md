# IPv6动态代理

一个支持动态IPv6/IPv4出口的多协议代理服务器，可以为每个请求随机选择一个出口IP地址。

## 功能特点

- 同时支持SOCKS5和HTTP代理协议
- 支持用户名/密码认证
- 每个请求使用随机IP作为出口IP
- 支持通过CIDR范围指定可用IP池
- 自动从CIDR范围内生成随机IP作为出口IP
- 支持同时指定多个CIDR范围
- 支持选择启用单一协议或同时启用两种协议
- 详细的日志输出选项

## 安装

### 从源代码构建

```bash
# 克隆仓库
git clone https://github.com/seongminhwan/ipv6-dynamic-proxy.git
cd ipv6-dynamic-proxy

# 构建项目
go build -o ipv6-proxy .
```

### 使用go install安装

```bash
go install github.com/seongminhwan/ipv6-dynamic-proxy@latest
```

## 使用方法

### 基本用法

```bash
# 使用默认配置启动代理服务器（监听127.0.0.1:1080）
./ipv6-proxy

# 指定监听地址和端口
./ipv6-proxy --listen 0.0.0.0:8888

# 启用详细日志
./ipv6-proxy --verbose
```

### 使用CIDR范围

```bash
# 指定单个IPv6 CIDR范围
./ipv6-proxy --cidr 2001:db8::/64

# 指定多个CIDR范围（同时支持IPv4和IPv6）
./ipv6-proxy --cidr 2001:db8::/64 --cidr 192.168.1.0/24
```

### 启用认证

```bash
# 启用用户名/密码认证
./ipv6-proxy --auth --username myuser --password mypassword
```

## 命令行参数

```
参数                      简写      说明
--listen, -l              -l       SOCKS5代理服务器监听地址 (默认 "127.0.0.1:1080")
--http-listen, -H         -H       HTTP代理服务器监听地址 (默认 "127.0.0.1:8080")
--cidr, -c                -c       CIDR范围列表，例如: 2001:db8::/64 (可指定多个)
--username, -u            -u       认证用户名
--password, -p            -p       认证密码
--auth, -a                -a       启用用户名/密码认证
--verbose, -v             -v       启用详细日志
--type, -t                -t       代理类型: socks5, http 或 both (默认"both")
--auto-detect-ips, -A     -A       自动检测系统IP并使用它们作为出口IP
--include-private-ips     无        在自动检测时包含局域网IP地址 (默认排除)
--help, -h                -h       显示帮助信息
```

## 注意事项

- **平台支持**: 本项目仅支持Linux和macOS操作系统，不支持Windows平台
- 要使用IPv6或自定义出口IP，您的系统必须支持在同一网络接口上绑定多个IP地址
- 在某些操作系统上，可能需要管理员/root权限才能绑定自定义IP
- 如果没有指定CIDR范围，将使用系统默认IP作为出口IP
- 默认情况下同时启用SOCKS5和HTTP代理，可以通过--type参数选择特定代理类型
- 使用--auto-detect-ips参数可以自动使用系统上已配置的IP地址，无需手动指定CIDR
- 默认情况下自动检测会排除局域网IP（可使用--include-private-ips参数包含它们）

## 示例用例

### 使用自动检测IP功能

```bash
# 自动检测系统上所有可用公网IP并使用它们作为出口（默认排除局域网IP）
./ipv6-proxy --auto-detect-ips --listen 0.0.0.0:1080 --http-listen 0.0.0.0:8080 --verbose

# 自动检测系统上所有IP，包括局域网IP
./ipv6-proxy --auto-detect-ips --include-private-ips --verbose

# 使用Docker和自动检测IP
docker run -d --name ipv6-proxy \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy \
  --auto-detect-ips \
  --listen 0.0.0.0:1080 \
  --http-listen 0.0.0.0:8080 \
  --verbose

# 在具有Tunnelbroker等虚拟网卡的系统上使用
docker run -d --name ipv6-proxy \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy \
  --auto-detect-ips \
  --verbose
```

### 局域网IP处理说明

默认情况下，自动检测模式会排除以下IP地址：
- IPv4局域网: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
- IPv6局域网: fc00::/7 (唯一本地地址)
- 回环地址: 127.0.0.0/8, ::1/128
- IPv6链路本地地址: fe80::/10

如果您需要包含这些局域网IP（例如在内网代理场景），可以使用`--include-private-ips`参数。

### 使用SOCKS5代理

```bash
# 启动代理服务器
./ipv6-proxy --cidr 2001:db8::/64 --listen 127.0.0.1:1080

# 使用curl通过SOCKS5代理访问网站
curl --socks5 127.0.0.1:1080 https://ipinfo.io
```

### 使用HTTP代理

```bash
# 启动代理服务器
./ipv6-proxy --cidr 2001:db8::/64 --http-listen 127.0.0.1:8080

# 使用curl通过HTTP代理访问网站
curl -x http://127.0.0.1:8080 https://ipinfo.io
```

### 只启用HTTP代理

```bash
# 只启动HTTP代理服务器
./ipv6-proxy --cidr 2001:db8::/64 --type http
```

### 只启用SOCKS5代理

```bash
# 只启动SOCKS5代理服务器
./ipv6-proxy --cidr 2001:db8::/64 --type socks5
```

### 同时启用两种代理（默认）

```bash
# 同时启动SOCKS5和HTTP代理服务器
./ipv6-proxy --cidr 2001:db8::/64 --type both
```

### 在Docker中运行

```bash
# 同时启用SOCKS5和HTTP代理（默认模式）
docker run -d --name ipv6-proxy \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy \
  --cidr 2001:db8::/64 \
  --listen 0.0.0.0:1080 \
  --http-listen 0.0.0.0:8080 \
  --verbose

# 只启用SOCKS5代理
docker run -d --name ipv6-proxy-socks \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy \
  --cidr 2001:db8::/64 \
  --listen 0.0.0.0:1080 \
  --type socks5

# 只启用HTTP代理
docker run -d --name ipv6-proxy-http \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy \
  --cidr 2001:db8::/64 \
  --http-listen 0.0.0.0:8080 \
  --type http

# 启用认证
docker run -d --name ipv6-proxy-auth \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy \
  --cidr 2001:db8::/64 \
  --listen 0.0.0.0:1080 \
  --http-listen 0.0.0.0:8080 \
  --auth --username myuser --password mypassword
```

### 关于Docker网络模式

**本应用必须使用host网络模式运行Docker容器**，原因如下：

1. **直接访问网络接口**：为了实现随机IP出口功能，应用需要直接访问和绑定主机网络接口上的多个IP地址
2. **IPv6地址绑定**：在默认的bridge网络模式下，容器无法直接访问和绑定主机网络接口的IPv6地址
3. **网络栈共享**：使用`--network host`选项让容器直接使用主机的网络栈，包括所有网络接口和IP地址
4. **套接字操作**：应用程序使用底层套接字操作来绑定特定IP，这需要直接访问主机网络

如果不使用host网络模式，以下功能将无法正常工作：
- 无法从CIDR范围内随机选择IP作为出口
- 无法绑定到主机上的IPv6地址
- 网络请求将使用容器默认IP而非指定的随机IP

### Docker安全注意事项

由于需要host网络和NET_ADMIN权限，在生产环境中使用时应注意：

- 容器有权访问主机所有网络接口和端口
- 建议在专用主机或受限网络环境中运行
- 使用非root用户运行容器内应用（Dockerfile已配置）
- 限制容器的其他权限，仅授予必要的网络相关权限

## 许可证

MIT