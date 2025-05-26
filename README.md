# IPv6动态代理

一个支持动态IPv6/IPv4出口的SOCKS5代理服务器，可以为每个请求随机选择一个出口IP地址。

## 功能特点

- 支持SOCKS5代理协议
- 支持用户名/密码认证
- 每个请求使用随机IP作为出口IP
- 支持通过CIDR范围指定可用IP池
- 自动从CIDR范围内生成随机IP作为出口IP
- 支持同时指定多个CIDR范围
- 详细的日志输出选项

## 安装

### 从源代码构建

```bash
# 克隆仓库
git clone https://github.com/jpanda/ipv6-dynamic-proxy.git
cd ipv6-dynamic-proxy

# 构建项目
go build -o ipv6-proxy .
```

### 使用go install安装

```bash
go install github.com/jpanda/ipv6-dynamic-proxy@latest
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
参数                    简写      说明
--listen, -l            -l       代理服务器监听地址 (默认 "127.0.0.1:1080")
--cidr, -c              -c       CIDR范围列表，例如: 2001:db8::/64 (可指定多个)
--username, -u          -u       认证用户名
--password, -p          -p       认证密码
--auth, -a              -a       启用用户名/密码认证
--verbose, -v           -v       启用详细日志
--help, -h              -h       显示帮助信息
```

## 注意事项

- 要使用IPv6或自定义出口IP，您的系统必须支持在同一网络接口上绑定多个IP地址
- 在某些操作系统上，可能需要管理员/root权限才能绑定自定义IP
- 如果没有指定CIDR范围，将使用系统默认IP作为出口IP

## 示例用例

### 作为HTTP客户端的出口代理

```bash
# 启动代理服务器
./ipv6-proxy --cidr 2001:db8::/64 --listen 127.0.0.1:1080

# 使用curl通过代理访问网站
curl --socks5 127.0.0.1:1080 https://ipinfo.io
```

### 在Docker中运行

```bash
docker run -d --name ipv6-proxy \
  --network host \
  --cap-add=NET_ADMIN \
  -v /path/to/config:/config \
  jpanda/ipv6-dynamic-proxy \
  --cidr 2001:db8::/64 --listen 0.0.0.0:1080
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