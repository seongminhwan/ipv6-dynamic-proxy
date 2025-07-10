# IPv6动态代理

[![可执行文件](https://github.com/seongminhwan/ipv6-dynamic-proxy/actions/workflows/build.yml/badge.svg)](https://github.com/seongminhwan/ipv6-dynamic-proxy/actions/workflows/build.yml)
[![Docker镜像](https://github.com/seongminhwan/ipv6-dynamic-proxy/actions/workflows/docker.yml/badge.svg)](https://github.com/seongminhwan/ipv6-dynamic-proxy/actions/workflows/docker.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/seongminhwan/ipv6-dynamic-proxy)

一个支持动态IPv6/IPv4出口的多协议代理服务器，可以为每个请求随机选择一个出口IP地址。

> ⚠️ **安全警告**: 本项目需要较高的系统权限才能正常工作。在生产环境中使用前，请务必阅读[安全指南](SECURITY.md)文档，了解潜在风险和安全最佳实践。

## 项目地址

- **GitHub仓库**: https://github.com/seongminhwan/ipv6-dynamic-proxy
- **发布页面**: https://github.com/seongminhwan/ipv6-dynamic-proxy/releases/
- **Docker镜像**: `ghcr.io/seongminhwan/ipv6-dynamic-proxy:latest`

## 功能特点

- 同时支持SOCKS5和HTTP代理协议
- 支持用户名/密码认证
- 每个请求使用随机IP作为出口IP
- 支持通过CIDR范围指定可用IP池
- 自动从CIDR范围内生成随机IP作为出口IP
- 支持同时指定多个CIDR范围
- 支持通过用户名参数指定固定出口IP索引
- 支持选择启用单一协议或同时启用两种协议
- 详细的日志输出选项

## 安装

### 下载预编译文件

可以直接从GitHub Releases页面下载预编译的二进制文件：

```bash
# 下载Linux AMD64版本
wget https://github.com/seongminhwan/ipv6-dynamic-proxy/releases/download/v0.2.3/ipv6-dynamic-proxy-linux-amd64.tar.gz

# 解压文件
tar -zxvf ipv6-dynamic-proxy-linux-amd64.tar.gz

# 运行程序
./ipv6-dynamic-proxy
```

支持的平台和架构：

- Linux: amd64, arm64
- macOS: amd64, arm64

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

### 使用Docker镜像

```bash
# 拉取Docker镜像
docker pull ghcr.io/seongminhwan/ipv6-dynamic-proxy:latest
```

## 使用方法

### 基本用法

```bash
# 使用默认配置启动代理服务器（监听127.0.0.1:20808）
./ipv6-proxy

# 指定监听地址和端口
./ipv6-proxy --listen 0.0.0.0:8888

# 启用详细日志
./ipv6-proxy --verbose

# 使用固定IP索引（强制使用第2个IP）
./ipv6-proxy --cidr 2001:db8::/64 --cidr 2001:db9::/64 --ip-index 1
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

```ini
参数                      简写      说明
--listen, -l              -l       SOCKS5代理服务器监听地址 (默认 "127.0.0.1:20808")
--http-listen, -H         -H       HTTP代理服务器监听地址 (默认 "127.0.0.1:38080")
--cidr, -c                -c       CIDR范围列表，例如: 2001:db8::/64 (可指定多个)
--username, -u            -u       认证用户名
--password, -p            -p       认证密码
--auth, -a                -a       启用用户名/密码认证（未提供用户名密码时自动生成）
--verbose, -v             -v       启用详细日志
--type, -t                -t       代理类型: socks5, http 或 both (默认"both")
--auto-detect-ips, -A     -A       自动检测所有系统IP并使用它们作为出口IP
--auto-detect-ipv4        无       仅自动检测系统IPv4地址并使用它们作为出口IP
--auto-detect-ipv6        无       仅自动检测系统IPv6地址并使用它们作为出口IP
--include-private-ips     无       在自动检测时包含局域网IP地址 (默认排除)
--port-mapping            无       启用端口到固定出口IP的映射功能
--start-port              无       端口映射的起始端口 (默认 10086)
--end-port                无       端口映射的结束端口 (默认等于起始端口)
--username-separator, -s  -s       用户名参数分隔符 (默认 "%")
--ip-index                无       固定使用指定索引的出口IP（-1表示随机选择，优先级高于用户名参数）
--auto-config, -C         -C       自动配置网络环境（IPv4和IPv6非本地绑定和本地路由）
--skip-network-check      无       跳过网络配置检查
--help, -h                -h       显示帮助信息
```

**注意**:

- `--auto-detect-ips`, `--auto-detect-ipv4`, `--auto-detect-ipv6` 这三个参数不能同时使用。
- 启用端口映射功能后，将优先使用IPv4地址作为出口IP，其次才是IPv6地址。
- `--auto-config`参数需要root权限才能正常工作。
- `--ip-index`参数的优先级高于用户名参数中的索引指定。

## 安全注意事项

- __需要高级权限__: 本工具需要host网络模式和NET_ADMIN权限才能正常工作
- **认证建议**: 始终启用`--auth`选项并提供强密码，避免使用自动生成的凭据
- **网络隔离**: 在隔离的环境中运行此服务，限制可访问的网络范围
- **监听地址**: 除非必要，不要在公网接口上监听（避免使用0.0.0.0）
- **安全详情**: 查看[安全指南](SECURITY.md)获取完整的风险评估和最佳实践

## 一般注意事项

- **平台支持**: 本项目仅支持Linux和macOS操作系统，不支持Windows平台
- 要使用IPv6或自定义出口IP，您的系统必须支持在同一网络接口上绑定多个IP地址
- 在某些操作系统上，可能需要管理员/root权限才能绑定自定义IP
- 如果没有指定CIDR范围，将使用系统默认IP作为出口IP
- 默认情况下同时启用SOCKS5和HTTP代理，可以通过--type参数选择特定代理类型
- 使用自动检测参数可以自动使用系统上已配置的IP地址，无需手动指定CIDR：
   - `--auto-detect-ips`/-A: 同时检测IPv4和IPv6地址
   - `--auto-detect-ipv4`: 只检测IPv4地址
   - `--auto-detect-ipv6`: 只检测IPv6地址

- 默认情况下自动检测会排除局域网IP（可使用--include-private-ips参数包含它们）
- 使用`--auth`参数但不提供用户名/密码时，会自动生成随机凭据并在日志中显示

## 示例用例

### 使用自动检测IP功能

```bash
# 自动检测系统上所有可用公网IP并使用它们作为出口（默认排除局域网IP）
./ipv6-proxy --auto-detect-ips --listen 0.0.0.0:20808 --http-listen 0.0.0.0:38080 --verbose

# 只检测IPv4地址
./ipv6-proxy --auto-detect-ipv4 --listen 0.0.0.0:20808 --http-listen 0.0.0.0:38080 --verbose

# 只检测IPv6地址（适用于IPv6优先场景）
./ipv6-proxy --auto-detect-ipv6 --listen 0.0.0.0:20808 --http-listen 0.0.0.0:38080 --verbose

# 自动检测系统上所有IP，包括局域网IP
./ipv6-proxy --auto-detect-ips --include-private-ips --verbose

# 使用Docker和自动检测IPv6
docker run -d --name ipv6-proxy \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy:latest \
  --auto-detect-ipv6 \
  --listen 0.0.0.0:20808 \
  --http-listen 0.0.0.0:38080 \
  --verbose

# 在具有Tunnelbroker等虚拟网卡的系统上使用
docker run -d --name ipv6-proxy \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy:latest \
  --auto-detect-ipv6 \
  --verbose
```

### 使用自动生成的认证凭据

```bash
# 启用认证但不指定用户名密码，系统将自动生成随机凭据
./ipv6-proxy --auto-detect-ips --auth --verbose

# 日志中会显示类似以下内容：
# 已生成随机凭据 - 用户名: Ax7cRpMN, 密码: bWF4RGtkNnByVnc
```

## 通过用户名参数指定出口IP索引

本代理服务器支持通过特殊格式的用户名来指定使用固定的出口IP索引，这在需要保持IP稳定性的场景非常有用。

**重要特性**：即使在没有开启认证的情况下，HTTP代理仍然可以通过Proxy-Authorization头中的用户名参数来传递出口IP索引。这意味着您可以在不启用`--auth`参数的情况下，仍然通过标准的HTTP代理认证头来控制出口IP选择。

### 无认证模式下的IP索引传递

这是一个非常实用的功能：即使代理服务器没有启用认证（未使用`--auth`参数），您仍然可以通过HTTP代理的Proxy-Authorization头来传递出口IP索引。

#### 工作原理

1. **解析认证头**：代理服务器会解析HTTP请求中的Proxy-Authorization头
2. **提取用户名参数**：从认证信息中提取用户名部分，并解析其中的IP索引
3. **应用IP选择**：根据解析出的索引选择对应的出口IP
4. **无需验证**：由于未启用认证，不会验证用户名和密码的正确性

#### 使用示例

```bash
# 启动代理服务器（注意：没有使用--auth参数）
./ipv6-proxy --cidr 2001:db8::/64 --cidr 2001:db9::/64 --cidr 192.168.1.0/24

# 通过HTTP代理使用索引1的IP（2001:db9::/64）
curl -x http://anyuser%1:anypass@127.0.0.1:38080 https://ipinfo.io

# 通过HTTP代理使用索引0的IP（2001:db8::/64）
curl -x http://test%0:dummy@127.0.0.1:38080 https://ipinfo.io

# 在Python中使用
import requests
proxies = {
    'http': 'http://user%2:pass@127.0.0.1:38080',
    'https': 'http://user%2:pass@127.0.0.1:38080'
}
response = requests.get('https://ipinfo.io', proxies=proxies)
```

**注意事项**：

- 用户名和密码可以是任意值，因为不会进行验证
- 只有用户名中的索引部分会被解析和使用
- 如果索引超出范围或格式错误，将回退到随机IP选择
- 此功能同样适用于SOCKS5代理

### 用户名参数格式

格式：`用户名%索引`

其中：

- `用户名` 是您设置的真实用户名，用于认证
- `%` 是分隔符（默认，可通过`--username-separator`参数修改）
- `索引` 是您想使用的IP索引，对应CIDR列表中的位置（从0开始）

**重要限制**：

- **用户名中不能包含分隔符**，否则会导致解析错误
- 如果指定的索引超出可用IP范围，系统会忽略此参数并回退到随机选择IP
- 仍然需要正确的用户名和密码才能通过认证

### 使用示例

假设您已经启动了代理服务器，并指定了以下CIDR：

```bash
./ipv6-proxy --cidr 2001:db8::/64 --cidr 2001:db9::/64 --cidr 192.168.1.0/24 --auth --username myuser --password mypass
```

#### SOCKS5代理示例

```bash
# 使用CIDR列表中第0个IP（2001:db8::/64）
curl --socks5 127.0.0.1:20808 --socks5-basicauth 'myuser%0:mypass' https://ipinfo.io

# 使用CIDR列表中第2个IP（192.168.1.0/24）
curl --socks5 127.0.0.1:20808 --socks5-basicauth 'myuser%2:mypass' https://ipinfo.io
```

#### HTTP代理示例

```bash
# 使用CIDR列表中第1个IP（2001:db9::/64）
curl -x http://myuser%1:mypass@127.0.0.1:38080 https://ipinfo.io
```

#### 在各种客户端中配置

1. **在Chrome浏览器使用Proxy SwitchyOmega扩展**：

   - SOCKS5代理设置中，用户名填写：`myuser%0`
   - 密码填写您的实际密码

2. **在Firefox浏览器中**：

   - 网络设置中，SOCKS代理用户名填写：`myuser%0`
   - 密码填写您的实际密码

3. **在Python请求中**：

```python
import requests

proxies = {
    'http': 'http://myuser%0:mypass@127.0.0.1:38080',
    'https': 'http://myuser%0:mypass@127.0.0.1:38080'
}

response = requests.get('https://ipinfo.io', proxies=proxies)
print(response.text)
```

### 与端口映射功能的区别

本功能与`--port-mapping`参数的区别：

1. **用户名参数指定IP索引**：

   - 适用于需要临时或动态指定固定出口IP的场景
   - 可以在客户端级别控制，无需重启代理服务器
   - 适用于特定会话需要固定IP的情况

2. **端口映射功能**：

   - 根据目标端口自动选择固定的出口IP
   - 服务器级别的配置，适用于所有连接
   - 适用于特定应用或服务需要固定IP的情况

### IP索引选择的优先级

系统支持多种方式指定出口IP索引，优先级从高到低如下：

1. **`--ip-index`命令行参数**：最高优先级，强制使用指定索引的IP
2. **用户名参数中的索引**：通过`用户名%索引`格式指定的IP索引
3. **端口映射功能**：根据目标端口自动选择固定的出口IP
4. **随机选择**：如果以上都不适用，将随机选择一个IP

### 组合使用多种功能

您可以同时启用多种功能，系统会按照上述优先级进行选择：

```bash
# 同时启用多种功能的示例
./ipv6-proxy --cidr 2001:db8::/64 --cidr 2001:db9::/64 \
  --auth --username myuser --password mypass \
  --port-mapping --start-port 10086 --end-port 10090 \
  --ip-index 0
```

在上述配置中：

- `--ip-index 0`将强制所有连接使用第一个IP（2001:db8::/64）
- 如果移除`--ip-index`参数，则可以通过用户名参数指定：`myuser%1`
- 如果用户名中没有指定索引，将根据端口映射选择IP
- 如果端口映射也不适用，将随机选择IP

## 使用IPv6环境自动配置

为了使IPv6随机出口功能正常工作，系统需要进行特定的网络配置。从v0.2.0版本开始，本项目支持自动配置IPv6环境，无需手动执行系统命令。

### 功能说明

IPv6环境自动配置功能主要解决两个关键问题：

1. __允许绑定非本地IPv6地址__：设置`net.ipv6.ip_nonlocal_bind=1`，允许程序绑定到不在本地网络接口上的IPv6地址
2. **添加IPv6本地路由**：将IPv6 CIDR范围添加到本地回环接口，使系统能够正确路由随机生成的IPv6地址

### 使用方法

```bash
# 启用网络环境自动配置（需要root权限）
./ipv6-proxy --auto-detect-ipv6 --auto-config --verbose

# 如果已经手动配置了环境，可以跳过检查
./ipv6-proxy --auto-detect-ipv6 --skip-network-check --verbose
```

### 权限要求

使用`--auto-config`参数需要root权限，因为它需要：

- 修改系统内核参数（使用sysctl命令）
- 添加IPv6路由（使用ip命令）

如果没有足够的权限，程序会提供友好的错误信息和手动配置指南。

### 实际使用示例

**在Linux服务器上自动配置IPv6环境**：

```bash
# 使用sudo运行以获取足够权限
sudo ./ipv6-proxy --auto-detect-ipv6 --auto-config --auth --verbose

# 或者在Docker中运行（需要--cap-add=NET_ADMIN）
docker run -d --name ipv6-proxy \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy:latest \
  --auto-detect-ipv6 \
  --auto-config \
  --auth --username myuser --password mypassword \
  --verbose
```

**在HE Tunnelbroker环境中使用**：

```bash
# 特别适合使用Tunnelbroker等IPv6隧道的环境
sudo ./ipv6-proxy --auto-detect-ipv6 --auto-config --auth --verbose
```

### 参数组合建议

- **全自动配置**：`--auto-detect-ipv6 --auto-config`
- **手动配置环境**：`--auto-detect-ipv6 --skip-network-check`
- **仅IPv4模式**：`--auto-detect-ipv4`（不需要特殊配置）

### 常见问题排查

1. **权限不足错误**：

   - 错误信息：`配置IPv6环境失败: 权限不足`
   - 解决方案：使用sudo或root用户运行程序

2. **绑定地址失败**：

   - 错误信息：`bind: cannot assign requested address`
   - 解决方案：检查`net.ipv6.ip_nonlocal_bind`是否成功设置为1

3. **连接超时**：

   - 错误信息：`i/o timeout`
   - 解决方案：检查IPv6路由配置，确保已添加正确的本地路由

## 系统网络参数配置

如果您不想使用自动配置功能，也可以手动调整系统的网络参数。以下是一些重要的系统配置：

### Linux系统网络参数

#### 1. IP转发设置

对于需要转发数据包的代理服务器，需要启用IP转发功能：

```bash
# 临时启用IPv4转发
sudo sysctl -w net.ipv4.ip_forward=1

# 临时启用IPv6转发
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# 永久启用IP转发（需重启生效）
sudo sh -c 'echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf'
```

#### 2. 非本地绑定配置

允许绑定到非本地IP地址（对使用指定CIDR范围内的IP作为出口IP非常重要）：

```bash
# 允许绑定到非本地IPv4地址
sudo sysctl -w net.ipv4.ip_nonlocal_bind=1

# 允许绑定到非本地IPv6地址
sudo sysctl -w net.ipv6.ip_nonlocal_bind=1

# 永久配置
sudo sh -c 'echo "net.ipv4.ip_nonlocal_bind=1" >> /etc/sysctl.conf'
sudo sh -c 'echo "net.ipv6.ip_nonlocal_bind=1" >> /etc/sysctl.conf'
```

#### 3. 连接跟踪相关参数

对于高负载场景，可能需要增加连接跟踪表的大小：

```bash
# 增加连接跟踪表大小
sudo sysctl -w net.netfilter.nf_conntrack_max=131072

# 增加连接超时时间（适用于某些长连接场景）
sudo sysctl -w net.ipv4.netfilter.ip_conntrack_tcp_timeout_established=54000
```

#### 4. 端口范围配置

如果需要使用大量出口端口，可以扩大本地端口范围：

```bash
# 扩大临时端口范围（默认通常为32768-60999）
sudo sysctl -w net.ipv4.ip_local_port_range="10000 65000"
```

#### 5. 应用配置并验证

```bash
# 应用所有修改
sudo sysctl -p

# 验证参数是否生效
sudo sysctl net.ipv4.ip_forward
sudo sysctl net.ipv4.ip_nonlocal_bind
```

### 常见错误排查

如果遇到绑定IP相关错误，如"Cannot assign requested address"，通常是因为系统不允许绑定到非本地IP地址，请确保：

1. 已设置`net.ipv4.ip_nonlocal_bind=1`
2. 运行容器时使用了`--cap-add=NET_ADMIN`和`--network host`选项
3. 运行应用时具有足够的权限（root或具有CAP_NET_ADMIN权限）

对于Docker环境，上述系统参数需要在宿主机上配置，而非容器内部。

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
./ipv6-proxy --cidr 2001:db8::/64 --listen 127.0.0.1:20808

# 使用curl通过SOCKS5代理访问网站
curl --socks5 127.0.0.1:20808 https://ipinfo.io
```

### 使用HTTP代理

```bash
# 启动代理服务器
./ipv6-proxy --cidr 2001:db8::/64 --http-listen 127.0.0.1:38080

# 使用curl通过HTTP代理访问网站
curl -x http://127.0.0.1:38080 https://ipinfo.io
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
  ghcr.io/seongminhwan/ipv6-dynamic-proxy:latest \
  --cidr 2001:db8::/64 \
  --listen 0.0.0.0:20808 \
  --http-listen 0.0.0.0:38080 \
  --verbose

# 只启用SOCKS5代理
docker run -d --name ipv6-proxy-socks \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy:latest \
  --cidr 2001:db8::/64 \
  --listen 0.0.0.0:20808 \
  --type socks5

# 只启用HTTP代理
docker run -d --name ipv6-proxy-http \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy:latest \
  --cidr 2001:db8::/64 \
  --http-listen 0.0.0.0:38080 \
  --type http

# 启用认证
docker run -d --name ipv6-proxy-auth \
  --network host \
  --cap-add=NET_ADMIN \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy:latest \
  --cidr 2001:db8::/64 \
  --listen 0.0.0.0:20808 \
  --http-listen 0.0.0.0:38080 \
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

### Docker安全最佳实践

由于需要host网络和NET_ADMIN权限，在生产环境中使用时请遵循以下安全最佳实践：

```bash
# 安全的Docker运行示例 - 限制暴露端口，启用认证
docker run -d --name ipv6-proxy \
  --network host \
  --cap-add=NET_ADMIN \
  --security-opt=no-new-privileges \
  --read-only \
  --restart=on-failure:5 \
  ghcr.io/seongminhwan/ipv6-dynamic-proxy:latest \
  --auto-detect-ipv6 \
  --listen 127.0.0.1:20808 \
  --http-listen 127.0.0.1:38080 \
  --auth --username myuser --password mypassword
```

**关键安全措施**:

- 仅在本地接口（127.0.0.1）上监听，避免公网曝露
- 始终启用认证功能（`--auth`）并设置强密码
- 使用`--security-opt=no-new-privileges`防止权限提升
- 使用`--read-only`使容器文件系统只读
- 建议使用`latest`标签获取最新版本，或使用特定版本标签以获得更稳定的部署

更多安全建议请参考[安全指南](SECURITY.md)文档。

## 许可证

MIT
