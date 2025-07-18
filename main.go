package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
	"github.com/spf13/cobra"
)

// 配置选项
type Config struct {
	// 代理服务器监听地址
	ListenAddr string
	// HTTP代理监听地址
	HttpListenAddr string
	// CIDR范围列表
	CIDRs []string
	// 用户名
	Username string
	// 密码
	Password string
	// 是否启用验证
	EnableAuth bool
	// 是否打印详细日志
	Verbose bool
	// 代理类型 (socks5, http, both)
	ProxyType string
	// 是否自动检测系统IP
	AutoDetectIPs bool
	// 是否自动检测IPv4地址
	AutoDetectIPv4 bool
	// 是否自动检测IPv6地址
	AutoDetectIPv6 bool
	// 是否包含局域网IP
	IncludePrivateIPs bool
	// 是否启用固定端口对应固定出口IP
	EnablePortMapping bool
	// 端口映射起始端口
	StartPort int
	// 端口映射结束端口
	EndPort int
	// 当前连接请求的IP索引（用于通过用户名参数指定）
	CurrentIPIndex int
	// 固定使用的IP索引（通过命令行参数指定，优先级高于用户名参数）
	FixedIPIndex int
	// 用户名参数分隔符
	UsernameSeparator string
	// 自动配置网络环境（IPv4和IPv6非本地绑定和本地路由）
	AutoConfig bool
	// 跳过网络配置检查
	SkipNetworkCheck bool
}

// 获取随机端口号
func getRandomPort() int {
	// 使用1024-65535范围内的端口
	min := 1024
	max := 65535

	// 生成随机数
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		// 如果随机数生成失败，使用时间戳后四位
		return 10000 + int(time.Now().UnixNano()%55535)
	}

	return min + int(n.Int64())
}

// 解析用户名参数
// 支持格式: 用户名<分隔符>数字
// 例如: myuser%5 表示使用索引为5的IP，实际用户名为myuser
func parseUsernameParams(username string, separator string, maxIndex int, verbose bool) (realUsername string, ipIndex int) {
	ipIndex = -1 // 默认-1表示用户未指定

	// 基本输入验证
	if username == "" {
		return username, ipIndex
	}

	if len(username) > 100 {
		if verbose {
			log.Printf("警告: 用户名长度超过限制: %d", len(username))
		}
		return username, ipIndex
	}

	if maxIndex <= 0 {
		if verbose {
			log.Printf("警告: 无效的最大索引值: %d", maxIndex)
		}
		return username, ipIndex
	}

	// 检查分隔符是否有效
	if separator == "" {
		if verbose {
			log.Printf("警告: 分隔符为空")
		}
		return username, ipIndex
	}

	// 检查是否包含分隔符
	if !strings.Contains(username, separator) {
		// 没有分隔符，直接返回原始用户名
		realUsername = username
		return
	}

	// 使用分隔符分割用户名
	parts := strings.SplitN(username, separator, 2)
	if len(parts) != 2 {
		if verbose {
			log.Printf("警告: 分隔用户名失败，parts长度: %d", len(parts))
		}
		realUsername = username
		return
	}

	// 检查分割后的部分是否有效
	if parts[0] == "" {
		if verbose {
			log.Printf("警告: 用户名部分为空")
		}
		realUsername = username
		return
	}

	if parts[1] == "" {
		if verbose {
			log.Printf("警告: 索引部分为空")
		}
		realUsername = username
		return
	}

	// 尝试解析索引
	idx, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		if verbose {
			log.Printf("警告: 无法解析IP索引 '%s': %v", parts[1], err)
		}
		realUsername = username
		return
	}

	// 边界检查
	if idx < 0 {
		if verbose {
			log.Printf("警告: IP索引不能为负数: %d", idx)
		}
		realUsername = username
		return
	}

	if idx >= maxIndex {
		if verbose {
			log.Printf("警告: IP索引超出范围: %d (最大: %d)", idx, maxIndex-1)
		}
		realUsername = username
		return
	}

	// 成功解析
	realUsername = strings.TrimSpace(parts[0])
	ipIndex = idx

	if verbose {
		log.Printf("成功解析用户名参数: 用户名='%s', IP索引=%d", realUsername, ipIndex)
	}
	return
}

// 判断IP是否为私有/局域网IP
func isPrivateIP(ip net.IP) bool {
	// 检查IPv4私有地址
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (链路本地)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		return false
	}

	// 检查IPv6私有地址
	// fc00::/7 (唯一本地地址)
	if ip[0] == 0xfc || ip[0] == 0xfd {
		return true
	}

	return false
}

// 生成随机用户名和密码，确保不包含指定的分隔符
func generateRandomCredentials(separator string) (string, string) {
	// 使用Base64编码
	username := generateRandomString(12)
	password := generateRandomString(16)
	// 确保用户名不包含分隔符
	username = replaceSeparatorStr(separator, username)
	return username, password
}

func replaceSeparatorStr(separator, text string) string {
	// 确保用户名不包含分隔符
	defaultReplacedValue := "_"
	if separator != "" && strings.Contains(text, separator) {
		// 如果包含分隔符，替换为下划线(或许)
		if defaultReplacedValue == separator {
			defaultReplacedValue = "-"
		}
		return strings.ReplaceAll(text, separator, defaultReplacedValue)
	}
	return text
}

func generateRandomString(length int) string {
	// 生成16字节的随机数据用于密码
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Printf("生成随机用户名失败: %v，使用默认值", err)
		return "default_" + fmt.Sprint(time.Now().Unix())
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// 获取系统网络接口上配置的IP地址
// ipVersion: 0=全部, 4=仅IPv4, 6=仅IPv6
func getSystemIPs(includePrivateIPs bool, ipVersion int) ([]string, error) {
	// 分别存储IPv4和IPv6地址，确保IPv4在前
	var ipv4s []string
	var ipv6s []string

	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败: %v", err)
	}

	// 遍历所有网络接口
	for _, iface := range interfaces {
		// 忽略关闭的接口
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 获取接口的所有地址
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// 遍历所有地址
		for _, addr := range addrs {
			// 将地址转换为IP网络
			switch v := addr.(type) {
			case *net.IPNet:
				// 忽略回环地址
				if v.IP.IsLoopback() {
					continue
				}

				isIPv4 := v.IP.To4() != nil

				// 根据ipVersion过滤IP
				if (ipVersion == 4 && !isIPv4) || (ipVersion == 6 && isIPv4) {
					continue
				}

				// 忽略IPv6本地链路地址
				if !isIPv4 && v.IP.IsLinkLocalUnicast() {
					continue
				}

				// 如果不包含局域网IP且当前IP是局域网IP，则跳过
				if !includePrivateIPs && isPrivateIP(v.IP) {
					continue
				}

				if isIPv4 {
					// IPv4地址总是使用/32表示单个地址
					ipv4s = append(ipv4s, fmt.Sprintf("%s/32", v.IP.String()))
				} else {
					// IPv6地址保留原始网络前缀
					maskSize, _ := v.Mask.Size()
					// 如果无法获取掩码大小或掩码为0，使用默认值/64（常见的IPv6子网大小）
					if maskSize == 0 {
						maskSize = 64
					}
					ipv6s = append(ipv6s, fmt.Sprintf("%s/%d", v.IP.String(), maskSize))
				}
			}
		}
	}

	// 合并结果，确保IPv4地址在前
	ips := append(ipv4s, ipv6s...)

	// 输出详细日志
	log.Printf("系统IP扫描结果: IPv4=%d个, IPv6=%d个, 总计=%d个",
		len(ipv4s), len(ipv6s), len(ips))

	return ips, nil
}

// 从CIDR范围生成随机IP
func generateRandomIP(cidr string) (net.IP, error) {
	// 解析CIDR
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("无法解析CIDR %s: %v", cidr, err)
	}

	// 获取网络和掩码
	maskSize, bits := ipNet.Mask.Size()

	// 检查是否为IPv6地址
	isIPv6 := bits == 128

	// 生成随机IP
	ip := make([]byte, len(ipNet.IP))
	copy(ip, ipNet.IP)

	if isIPv6 {
		// IPv6特殊处理：限制随机化范围避免溢出
		// 对于IPv6地址，无论前缀如何，都限制随机化范围
		// 只随机化最后8个字节(64位)，这提供了足够的随机性
		// 即使是/64的网络，我们也只使用很小一部分空间

		// 计算随机起始位置，从第8字节开始（IPv6有16字节）
		randomStart := 8

		// 如果前缀长度大于64，则尊重原始前缀
		if maskSize > 64 {
			randomStart = maskSize / 8
			if maskSize%8 != 0 {
				randomStart++
			}
		}

		// 确保随机起始位置在合理范围内
		if randomStart >= len(ip) {
			randomStart = len(ip) - 1
		}

		// 对第一个随机字节可能需要保留一些位
		if randomStart < len(ip) && maskSize%8 != 0 && maskSize > 64 {
			preserveBits := maskSize % 8
			mask := byte(0xFF) << (8 - preserveBits)

			// 使用加密安全的随机数
			randNum, err := rand.Int(rand.Reader, big.NewInt(256))
			if err != nil {
				return nil, fmt.Errorf("生成随机数失败: %v", err)
			}
			randByte := byte(randNum.Int64())

			ip[randomStart] = (ip[randomStart] & mask) | (randByte & ^mask)
			randomStart++
		}

		// 生成完全随机的其余字节
		for i := randomStart; i < len(ip); i++ {
			randNum, err := rand.Int(rand.Reader, big.NewInt(256))
			if err != nil {
				return nil, fmt.Errorf("生成随机数失败: %v", err)
			}
			ip[i] = byte(randNum.Int64())
		}
	} else {
		// IPv4地址处理维持原有逻辑
		if bits-maskSize > 32 {
			// 对于大型网络，我们限制生成范围，避免过大的随机数
			maskSize = bits - 32
		}

		// 计算需要随机化的字节数
		randomBytes := (bits - maskSize + 7) / 8
		randomStart := len(ip) - randomBytes

		// 生成随机字节
		for i := randomStart; i < len(ip); i++ {
			// 保留网络部分不变，只修改主机部分
			if i == randomStart && (bits-maskSize)%8 != 0 {
				preserveBits := 8 - (bits-maskSize)%8
				mask := byte(0xFF) << preserveBits

				// 使用加密安全的随机数
				randNum, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return nil, fmt.Errorf("生成随机数失败: %v", err)
				}
				randByte := byte(randNum.Int64())

				ip[i] = (ip[i] & mask) | (randByte & ^mask)
			} else {
				// 完全随机的字节
				randNum, err := rand.Int(rand.Reader, big.NewInt(256))
				if err != nil {
					return nil, fmt.Errorf("生成随机数失败: %v", err)
				}
				ip[i] = byte(randNum.Int64())
			}
		}
	}

	return ip, nil
}

// 创建一个自定义的Dialer，用于使用随机IP作为源IP
// forceRandom参数强制每次生成新的随机IP，无视所有IP索引配置
// specificIPIndex参数指定特定的IP索引（-1表示未指定）
// IP选择优先级：specificIPIndex > config.CurrentIPIndex > 随机选择
func createDialer(cidrList []string, config Config, forceRandom bool, specificIPIndex int) *net.Dialer {
	// 如果没有指定CIDR，使用默认Dialer
	if len(cidrList) == 0 {
		if config.Verbose {
			log.Println("未指定CIDR，使用默认Dialer")
		}
		return &net.Dialer{
			Timeout: 30 * time.Second,
		}
	}

	// 确定最终使用的IP索引，实现正确的优先级逻辑
	finalIPIndex := -1 // -1表示随机选择
	ipSelectionMode := "随机模式"

	if forceRandom {
		// 强制随机模式，忽略所有索引配置
		ipSelectionMode = "强制随机模式"
		finalIPIndex = -1
	} else if specificIPIndex >= 0 && specificIPIndex < len(cidrList) {
		// 优先级1：用户通过用户名指定的IP索引
		finalIPIndex = specificIPIndex
		ipSelectionMode = fmt.Sprintf("用户指定索引模式[%d]", specificIPIndex)
	} else if config.CurrentIPIndex >= 0 && config.CurrentIPIndex < len(cidrList) {
		// 优先级2：全局默认IP索引（启动时配置）
		finalIPIndex = config.CurrentIPIndex
		ipSelectionMode = fmt.Sprintf("全局默认索引模式[%d]", config.CurrentIPIndex)
	}

	if config.Verbose {
		log.Printf("IP选择策略: %s (specificIndex=%d, globalIndex=%d, forceRandom=%v)",
			ipSelectionMode, specificIPIndex, config.CurrentIPIndex, forceRandom)
	}

	// 分离IPv4和IPv6 CIDR，避免重复计算
	var ipv4CIDRs []string
	var ipv6CIDRs []string
	for _, c := range cidrList {
		ip, _, _ := net.ParseCIDR(c)
		if ip.To4() != nil {
			ipv4CIDRs = append(ipv4CIDRs, c)
		} else {
			ipv6CIDRs = append(ipv6CIDRs, c)
		}
	}

	// 创建一个在每次连接时动态生成随机IP的Dialer
	return &net.Dialer{
		Timeout: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			// 每次连接都重新生成随机IP
			var cidr string
			var sourceIP net.IP
			var ipGenerated bool = false

			// 如果确定了具体的IP索引，使用指定的CIDR
			if finalIPIndex >= 0 && finalIPIndex < len(cidrList) {
				cidr = cidrList[finalIPIndex]

				// 生成指定CIDR的IP
				var err error
				sourceIP, err = generateRandomIP(cidr)
				if err != nil {
					if config.Verbose {
						log.Printf("生成指定索引(%d)的IP失败: %v，回退到随机选择", finalIPIndex, err)
					}
					// 如果生成失败，继续使用随机IP选择方式
				} else {
					if config.Verbose {
						log.Printf("命中指定索引出口IP: 索引=%d, CIDR=%s, IP=%s",
							finalIPIndex, cidr, sourceIP.String())
					}
					ipGenerated = true
				}
			}

			// 如果还没有生成IP且启用了端口映射功能，尝试使用端口映射
			if !ipGenerated && config.EnablePortMapping {
				// 注意：这里只用startPort模拟，实际的端口映射在连接时进行
				portOffset := config.StartPort % max(1, len(cidrList))

				// 优先使用IPv6地址
				if len(ipv6CIDRs) > 0 {
					cidrIndex := portOffset % len(ipv6CIDRs)
					cidr = ipv6CIDRs[cidrIndex]
					if config.Verbose {
						log.Printf("端口映射: 使用IPv6 CIDR: %s", cidr)
					}
				} else if len(ipv4CIDRs) > 0 {
					cidrIndex := portOffset % len(ipv4CIDRs)
					cidr = ipv4CIDRs[cidrIndex]
					if config.Verbose {
						log.Printf("端口映射: 未找到IPv6地址，使用IPv4 CIDR: %s", cidr)
					}
				}

				// 根据CIDR生成IP
				var err error
				sourceIP, err = generateRandomIP(cidr)
				if err != nil {
					if config.Verbose {
						log.Printf("为端口映射生成IP失败: %v，尝试其他方式", err)
					}
				} else {
					if config.Verbose {
						log.Printf("端口映射: CIDR %s -> IP %s", cidr, sourceIP.String())
					}
					ipGenerated = true
				}
			}

			// 如果仍然没有生成IP，使用随机方式，优先IPv6
			if !ipGenerated {
				// 优先使用IPv6地址
				var selectedCIDR string

				if len(ipv6CIDRs) > 0 {
					// 使用IPv6地址
					randNum, err := rand.Int(rand.Reader, big.NewInt(int64(len(ipv6CIDRs))))
					if err != nil {
						if config.Verbose {
							log.Printf("生成随机数失败: %v，使用默认IPv6 CIDR选择", err)
						}
						randNum = big.NewInt(int64(time.Now().Nanosecond() % len(ipv6CIDRs)))
					}
					selectedCIDR = ipv6CIDRs[randNum.Int64()]
					if config.Verbose {
						log.Printf("随机选择IPv6 CIDR: %s", selectedCIDR)
					}
				} else if len(ipv4CIDRs) > 0 {
					// 使用IPv4地址
					randNum, err := rand.Int(rand.Reader, big.NewInt(int64(len(ipv4CIDRs))))
					if err != nil {
						if config.Verbose {
							log.Printf("生成随机数失败: %v，使用默认IPv4 CIDR选择", err)
						}
						randNum = big.NewInt(int64(time.Now().Nanosecond() % len(ipv4CIDRs)))
					}
					selectedCIDR = ipv4CIDRs[randNum.Int64()]
					if config.Verbose {
						log.Printf("随机选择IPv4 CIDR: %s", selectedCIDR)
					}
				} else {
					// 回退到原始逻辑：从所有CIDR中随机选择
					randNum, err := rand.Int(rand.Reader, big.NewInt(int64(len(cidrList))))
					if err != nil {
						if config.Verbose {
							log.Printf("生成随机数失败: %v，使用默认CIDR选择", err)
						}
						randNum = big.NewInt(int64(time.Now().Nanosecond() % len(cidrList)))
					}
					selectedCIDR = cidrList[randNum.Int64()]
					if config.Verbose {
						log.Printf("随机选择任意CIDR: %s", selectedCIDR)
					}
				}

				cidr = selectedCIDR
				var err error
				sourceIP, err = generateRandomIP(cidr)
				if err != nil {
					if config.Verbose {
						log.Printf("生成随机IP失败: %v，使用默认IP", err)
					}
					return err
				}
			}

			if config.Verbose {
				log.Printf("每次连接生成新IP: %s (来自CIDR: %s)", sourceIP.String(), cidr)
			}

			// 使用Control函数在每次连接时设置源IP
			return c.Control(func(fd uintptr) {
				// 根据网络类型和IP类型设置源IP地址
				if sourceIP.To4() != nil {
					// IPv4地址
					addr := &syscall.SockaddrInet4{
						Port: 0,
					}
					copy(addr.Addr[:], sourceIP.To4())

					err := syscall.Bind(int(fd), addr)
					if err != nil && config.Verbose {
						log.Printf("绑定IPv4源IP失败: %v", err)
					}
				} else {
					// IPv6地址
					addr := &syscall.SockaddrInet6{
						Port: 0,
					}
					copy(addr.Addr[:], sourceIP.To16())

					err := syscall.Bind(int(fd), addr)
					if err != nil && config.Verbose {
						log.Printf("绑定IPv6源IP失败: %v", err)
					}
				}
			})
		},
	}
}

// 自定义认证器
type CredentialStore struct {
	Username string
	Password string
	Config   *Config // 添加对配置的引用
}

func (c *CredentialStore) Valid(user, password string) bool {
	// URL解码用户名，处理可能的URL编码
	decodedUser, err := url.QueryUnescape(user)
	if err != nil {
		// 如果解码失败，使用原始用户名
		decodedUser = user
		if c.Config.Verbose {
			log.Printf("SOCKS5: URL解码用户名失败: %v，使用原始用户名", err)
		}
	}

	// 解析用户名参数
	realUser, userSpecifiedIPIndex := parseUsernameParams(decodedUser, c.Config.UsernameSeparator, len(c.Config.CIDRs), c.Config.Verbose)

	if c.Config.Verbose && userSpecifiedIPIndex >= 0 {
		log.Printf("SOCKS5用户指定IP索引: %d", userSpecifiedIPIndex)
	}

	// 使用实际用户名验证
	return realUser == c.Username && password == c.Password
}

// HTTP代理服务器实现
type HttpProxy struct {
	// 随机IP拨号器
	dialer *net.Dialer
	// 认证信息
	auth     bool
	username string
	password string
	// 日志设置
	verbose bool
	// 配置引用
	config *Config
}

func NewHttpProxy(dialer *net.Dialer, auth bool, username, password string, verbose bool, config *Config) *HttpProxy {
	return &HttpProxy{
		dialer:   dialer,
		auth:     auth,
		username: username,
		password: password,
		verbose:  verbose,
		config:   config,
	}
}

func (p *HttpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 验证认证信息和检查用户名参数
	hasUserSpecifiedIndex := false

	// 检查是否存在认证头，无论是否启用认证
	authHeader := r.Header.Get("Proxy-Authorization")
	username := ""
	password := ""
	ipIndex := -1
	if authHeader != "" {
		// 尝试解析认证信息
		authParts := strings.SplitN(authHeader, " ", 2)
		if len(authParts) == 2 && authParts[0] == "Basic" {
			decoded, err := base64.StdEncoding.DecodeString(authParts[1])
			if err == nil {
				credentials := strings.SplitN(string(decoded), ":", 2)
				if len(credentials) == 2 {
					// URL解码用户名，处理可能的URL编码
					decodedUsername := credentials[0]
					password = credentials[1]
					// 解析用户名参数，获取实际用户名和IP索引
					username, ipIndex = parseUsernameParams(decodedUsername, p.config.UsernameSeparator, len(p.config.CIDRs), p.config.Verbose)

					if p.verbose {
						log.Printf("解析用户名参数: 原始=%s, 解码=%s, 实际=%s, 索引=%d, 分隔符=%s",
							credentials[0], decodedUsername, username, ipIndex, p.config.UsernameSeparator)
					}

					// ✅ 架构重构：不再修改全局config.CurrentIPIndex
					// 改为设置局部变量标识用户指定了IP索引
					if ipIndex >= 0 {
						hasUserSpecifiedIndex = true
						if p.verbose {
							log.Printf("HTTP代理: 用户指定IP索引: %d (用户名: %s, 分隔符: %s)",
								ipIndex, decodedUsername, p.config.UsernameSeparator)
						}
					}
				}
			}
		}
	}

	// 如果启用了认证，则验证用户名和密码
	if p.auth {
		if username != p.username || password != p.password {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Access to proxy\"")
			http.Error(w, "认证失败", http.StatusProxyAuthRequired)
			return
		}
	}

	// ✅ 架构重构：移除全局状态修改
	// 不再修改p.config.CurrentIPIndex，改为传递参数

	// 处理CONNECT请求（HTTPS）
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r, hasUserSpecifiedIndex, ipIndex)
		return
	}

	// 处理普通HTTP请求
	p.handleHTTP(w, r, hasUserSpecifiedIndex, ipIndex)
}

func (p *HttpProxy) handleConnect(w http.ResponseWriter, r *http.Request, hasUserSpecifiedIndex bool, userSpecifiedIPIndex int) {
	startTime := time.Now()
	if p.verbose {
		log.Printf("处理CONNECT请求: %s", r.Host)
	}

	// 为CONNECT请求创建临时拨号器，传递用户指定的IP索引
	// 使用新的参数传递架构，避免修改全局配置
	connectDialer := createDialer(p.config.CIDRs, *p.config, !hasUserSpecifiedIndex, userSpecifiedIPIndex)

	if p.verbose && hasUserSpecifiedIndex {
		log.Printf("CONNECT请求使用用户指定索引: %d, CIDRs总数: %d",
			userSpecifiedIPIndex, len(p.config.CIDRs))
	} else if p.verbose {
		log.Printf("CONNECT请求使用随机IP")
	}

	// 建立到目标服务器的连接
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	targetConn, err := connectDialer.DialContext(ctx, "tcp", r.Host)
	if err != nil {
		http.Error(w, fmt.Sprintf("无法连接到目标服务器: %v", err), http.StatusServiceUnavailable)
		return
	}
	defer targetConn.Close()

	// 设置连接超时
	if tcpConn, ok := targetConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// 获取客户端连接
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "不支持连接劫持", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, fmt.Sprintf("连接劫持失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// 设置客户端连接超时
	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// 发送200连接已建立响应
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Printf("向客户端写入响应失败: %v", err)
		return
	}

	// 在客户端和目标服务器之间复制数据
	var wg sync.WaitGroup
	wg.Add(2)

	// 客户端 -> 目标服务器
	go func() {
		defer wg.Done()
		io.Copy(targetConn, clientConn)
		if tcpConn, ok := targetConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	// 目标服务器 -> 客户端
	go func() {
		defer wg.Done()
		io.Copy(clientConn, targetConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
	if p.verbose {
		elapsed := time.Since(startTime)
		log.Printf("CONNECT连接已完成: %s, 总耗时: %v", r.Host, elapsed)
	}
}

func (p *HttpProxy) handleHTTP(w http.ResponseWriter, r *http.Request, hasUserSpecifiedIndex bool, userSpecifiedIPIndex int) {
	startTime := time.Now()
	if p.verbose {
		log.Printf("处理HTTP请求: %s %s", r.Method, r.URL)
	}

	// ✅ 架构重构：不再创建Config副本或修改全局状态
	// 直接使用原始配置，通过参数传递用户选择

	// 创建到目标服务器的请求
	req := &http.Request{
		Method:     r.Method,
		URL:        r.URL,
		Proto:      r.Proto,
		ProtoMajor: r.ProtoMajor,
		ProtoMinor: r.ProtoMinor,
		Header:     make(http.Header),
		Body:       r.Body,
		Host:       r.Host,
	}

	// 复制原始请求头
	for k, vv := range r.Header {
		if k != "Proxy-Authorization" && k != "Proxy-Connection" {
			for _, v := range vv {
				req.Header.Add(k, v)
			}
		}
	}

	// 设置X-Forwarded-For头
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	// 为当前请求创建新的拨号器，传递用户指定的IP索引
	// 使用新的参数传递架构，避免修改全局配置
	currentDialer := createDialer(p.config.CIDRs, *p.config, !hasUserSpecifiedIndex, userSpecifiedIPIndex)

	if p.verbose && hasUserSpecifiedIndex {
		log.Printf("HTTP请求使用用户指定索引: %d, CIDRs总数: %d",
			userSpecifiedIPIndex, len(p.config.CIDRs))
	} else if p.verbose {
		log.Printf("HTTP请求使用随机IP")
	}

	// 使用随机IP拨号器创建HTTP客户端，禁用保持连接以确保每次请求都使用新的IP
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:           currentDialer.DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			DisableKeepAlives:     true, // 禁用连接重用
			MaxIdleConnsPerHost:   -1,   // 禁用连接池
			IdleConnTimeout:       0,    // 禁用空闲连接超时
			ExpectContinueTimeout: 5 * time.Second,
		},
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("请求失败: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// 复制响应体
	written, _ := io.Copy(w, resp.Body)

	if p.verbose {
		elapsed := time.Since(startTime)
		log.Printf("HTTP请求已完成: %s %s, 状态: %d, 响应大小: %d字节, 总耗时: %v",
			r.Method, r.URL, resp.StatusCode, written, elapsed)
	}
}

func main() {
	var config Config

	// 定义根命令
	rootCmd := &cobra.Command{
		Use:   "ipv6-dynamic-proxy",
		Short: "一个支持动态IPv6/IPv4出口的代理服务器",
		Long: `一个支持SOCKS5和HTTP协议的代理服务器，支持使用随机IPv6/IPv4地址作为出口。
可以通过指定CIDR范围来定义可用的IP地址池，或使用--auto-detect-ips自动检测系统IP。`,
		Run: func(cmd *cobra.Command, args []string) {
			// 检查命令行参数冲突
			autoDetectFlags := 0
			if config.AutoDetectIPs {
				autoDetectFlags++
			}
			if config.AutoDetectIPv4 {
				autoDetectFlags++
			}
			if config.AutoDetectIPv6 {
				autoDetectFlags++
			}

			if autoDetectFlags > 1 {
				log.Fatalf("错误: --auto-detect-ips, --auto-detect-ipv4, --auto-detect-ipv6 不能同时使用")
			}

			// 配置日志
			if config.Verbose {
				log.SetFlags(log.LstdFlags | log.Lshortfile)
				log.Println("详细日志模式已启用")
				log.Printf("配置: %+v", config)
			}
			config.EnableAuth = config.EnableAuth || config.Username != "" || config.Password != ""

			// 如果启用了认证但未提供用户名密码，则生成随机凭据
			if config.EnableAuth {
				if config.Username == "" {
					config.Username = generateRandomString(12)
					config.Username = replaceSeparatorStr(config.UsernameSeparator, config.Username)
				}

				if config.Password == "" {
					config.Password = generateRandomString(16)
				}
				log.Printf("访问凭据 - 用户名: %s, 密码: %s", config.Username, config.Password)
			}

			// 如果启用了自动检测IP，获取系统IP列表
			if config.AutoDetectIPs || config.AutoDetectIPv4 || config.AutoDetectIPv6 {
				var systemIPs []string
				var err error

				if config.AutoDetectIPv4 {
					// 只检测IPv4地址
					systemIPs, err = getSystemIPs(config.IncludePrivateIPs, 4)
				} else if config.AutoDetectIPv6 {
					// 只检测IPv6地址
					systemIPs, err = getSystemIPs(config.IncludePrivateIPs, 6)
				} else {
					// 检测所有地址
					systemIPs, err = getSystemIPs(config.IncludePrivateIPs, 0)
				}
				if err != nil {
					log.Fatalf("自动检测系统IP失败: %v", err)
				}

				if len(systemIPs) == 0 {
					log.Println("警告: 未检测到有效的系统IP")
					if config.AutoDetectIPv4 {
						log.Println("未检测到IPv4地址")
					} else if config.AutoDetectIPv6 {
						log.Println("未检测到IPv6地址")
					}

					if !config.IncludePrivateIPs {
						log.Println("提示: 您可以使用--include-private-ips选项包含局域网IP，或检查网络配置")
					}
				} else {
					// 使用检测到的IP替换配置的CIDR
					config.CIDRs = systemIPs
					if config.Verbose {
						ipTypeStr := "IP"
						if config.AutoDetectIPv4 {
							ipTypeStr = "IPv4"
						} else if config.AutoDetectIPv6 {
							ipTypeStr = "IPv6"
						}
						log.Printf("检测到%d个系统%s: %v", len(systemIPs), ipTypeStr, systemIPs)
					}
				}
			}
			// 验证CIDR范围的有效性
			for _, cidr := range config.CIDRs {
				if _, _, err := net.ParseCIDR(cidr); err != nil {
					log.Fatalf("无效的CIDR范围: %s, 错误: %v", cidr, err)
				}
			}

			// 如果通过命令行参数指定了固定IP索引，则设置为当前IP索引
			if config.FixedIPIndex >= 0 {
				if config.FixedIPIndex < len(config.CIDRs) {
					config.CurrentIPIndex = config.FixedIPIndex
					if config.Verbose {
						log.Printf("使用命令行指定的固定IP索引: %d", config.FixedIPIndex)
					}
				} else {
					log.Printf("警告: 指定的IP索引 %d 超出范围（可用范围: 0-%d），将使用随机IP",
						config.FixedIPIndex, len(config.CIDRs)-1)
					config.CurrentIPIndex = -1
				}
			} else {
				// 如果没有指定固定索引，默认使用随机IP（-1）
				config.CurrentIPIndex = -1
			}

			// 如果启用了自动配置网络环境，则根据检测到的IP类型配置相应环境
			if config.AutoConfig {
				if err := configureNetworkEnvironment(config); err != nil {
					log.Printf("警告: 网络环境自动配置失败: %v", err)
					log.Println("您可以手动执行以下命令配置网络环境:")
					log.Println("对于IPv4: sudo sysctl -w net.ipv4.ip_nonlocal_bind=1")
					log.Println("对于IPv4转发: sudo sysctl -w net.ipv4.ip_forward=1")
					log.Println("对于IPv6: sudo sysctl -w net.ipv6.ip_nonlocal_bind=1")
					log.Println("对于IPv6转发: sudo sysctl -w net.ipv6.conf.all.forwarding=1")
					log.Println("对于IPv6 CIDR路由: sudo ip -6 route add local <IPv6前缀>/64 dev lo")
					if !config.SkipNetworkCheck {
						log.Println("如果您已手动配置环境或希望跳过检查，可以使用--skip-network-check选项")
					}
				} else {
					log.Println("网络环境已成功配置")
				}
			}

			// 创建退出信号通道
			exitChan := make(chan os.Signal, 1)
			signal.Notify(exitChan, syscall.SIGINT, syscall.SIGTERM)

			// 创建自定义拨号器，默认模式下不强制随机，允许用户通过用户名参数指定IP索引
			// 在main函数中，没有用户指定的索引，所以传递-1
			dialer := createDialer(config.CIDRs, config, false, -1)

			// 启动SOCKS5代理
			var socks5Done chan bool
			if config.ProxyType == "socks5" || config.ProxyType == "both" {
				socks5Done = make(chan bool)
				go startSocks5Server(config, dialer, socks5Done)
			}

			// 启动HTTP代理
			var httpDone chan bool
			if config.ProxyType == "http" || config.ProxyType == "both" {
				httpDone = make(chan bool)
				go startHttpServer(config, dialer, httpDone)
			}

			// 等待退出信号
			<-exitChan
			log.Println("正在关闭代理服务器...")

			// 关闭各个服务器
			if socks5Done != nil {
				close(socks5Done)
			}
			if httpDone != nil {
				close(httpDone)
			}

			log.Println("代理服务器已关闭")
		},
	}

	// 添加命令行参数
	socksPort := getRandomPort()
	httpPort := getRandomPort()
	// 确保两个端口不同
	for httpPort == socksPort {
		httpPort = getRandomPort()
	}

	rootCmd.Flags().StringVarP(&config.ListenAddr, "listen", "l", fmt.Sprintf("127.0.0.1:%d", socksPort), "SOCKS5代理服务器监听地址")
	rootCmd.Flags().StringVarP(&config.HttpListenAddr, "http-listen", "L", fmt.Sprintf("127.0.0.1:%d", httpPort), "HTTP代理服务器监听地址")
	rootCmd.Flags().StringSliceVarP(&config.CIDRs, "cidr", "c", []string{}, "CIDR范围列表，例如: 2001:db8::/64")
	rootCmd.Flags().StringVarP(&config.Username, "username", "u", "", "验证用户名")
	rootCmd.Flags().StringVarP(&config.Password, "password", "p", "", "验证密码")
	rootCmd.Flags().BoolVarP(&config.EnableAuth, "auth", "a", false, "启用用户名/密码验证，如未提供用户名密码则自动生成")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "启用详细日志")
	rootCmd.Flags().StringVarP(&config.ProxyType, "type", "t", "both", "代理类型: socks5, http 或 both (同时启用两种代理)")
	rootCmd.Flags().BoolVarP(&config.AutoDetectIPs, "auto-detect-ips", "A", false, "自动检测系统IP并使用它们作为出口IP")
	rootCmd.Flags().BoolVar(&config.AutoDetectIPv4, "auto-detect-ipv4", false, "自动检测系统IPv4地址并使用它们作为出口IP")
	rootCmd.Flags().BoolVar(&config.AutoDetectIPv6, "auto-detect-ipv6", false, "自动检测系统IPv6地址并使用它们作为出口IP")
	rootCmd.Flags().BoolVar(&config.IncludePrivateIPs, "include-private-ips", false, "在自动检测时包含局域网IP地址")
	rootCmd.Flags().BoolVar(&config.EnablePortMapping, "port-mapping", false, "启用端口到固定出口IP的映射功能")
	rootCmd.Flags().IntVar(&config.StartPort, "start-port", 10086, "端口映射的起始端口")
	rootCmd.Flags().IntVar(&config.EndPort, "end-port", 0, "端口映射的结束端口（可选，默认等于起始端口）")
	rootCmd.Flags().StringVarP(&config.UsernameSeparator, "username-separator", "s", "%", "用户名参数分隔符，用于在用户名中指定IP索引")
	rootCmd.Flags().IntVar(&config.FixedIPIndex, "ip-index", -1, "固定使用指定索引的出口IP（-1表示随机选择，优先级高于用户名参数）")

	// 添加网络环境自动配置相关参数
	rootCmd.Flags().BoolVarP(&config.AutoConfig, "auto-config", "C", false, "自动配置网络环境（IPv4和IPv6非本地绑定和本地路由）")
	rootCmd.Flags().BoolVar(&config.SkipNetworkCheck, "skip-network-check", false, "跳过网络配置检查")

	// 参数互斥分组，-A, -A4, -A6不能同时使用
	rootCmd.MarkFlagsMutuallyExclusive("auto-detect-ips", "auto-detect-ipv4", "auto-detect-ipv6")

	// 执行命令
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// 启动SOCKS5代理服务器
func startSocks5Server(config Config, dialer *net.Dialer, done chan bool) {
	// 创建SOCKS5配置
	socksConfig := &socks5.Config{
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}

	// 启用认证
	if config.EnableAuth {
		creds := &CredentialStore{
			Username: config.Username,
			Password: config.Password,
			Config:   &config, // 传递配置引用，以支持用户名参数指定IP索引
		}
		socksConfig.AuthMethods = []socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: creds}}
		log.Println("已启用SOCKS5用户名/密码认证")
	}

	// 设置自定义的拨号器，添加耗时统计和IP选择日志
	socksConfig.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		startTime := time.Now()
		if config.Verbose {
			log.Printf("SOCKS5连接开始: %s -> %s", network, addr)
		}

		// ✅ 架构重构：SOCKS5连接不再依赖全局config.CurrentIPIndex
		// SOCKS5协议本身不支持用户名参数指定IP索引，只能使用全局默认或随机
		// 这里使用全局默认配置，没有用户特定索引
		connectionDialer := createDialer(config.CIDRs, config, false, -1)

		if config.Verbose {
			if config.CurrentIPIndex >= 0 && config.CurrentIPIndex < len(config.CIDRs) {
				log.Printf("SOCKS5连接使用全局默认索引: %d", config.CurrentIPIndex)
			} else {
				log.Printf("SOCKS5连接使用随机IP")
			}
		}

		// 使用专用拨号器建立连接
		conn, err := connectionDialer.DialContext(ctx, network, addr)

		// 记录耗时和结果
		if config.Verbose {
			elapsed := time.Since(startTime)
			if err != nil {
				log.Printf("SOCKS5连接失败: %s -> %s, 耗时: %v, 错误: %v", network, addr, elapsed, err)
			} else {
				log.Printf("SOCKS5连接成功: %s -> %s, 本地地址: %s, 远程地址: %s, 耗时: %v",
					network, addr, conn.LocalAddr().String(), conn.RemoteAddr().String(), elapsed)
			}
		}

		return conn, err
	}

	// 创建SOCKS5服务器
	server, err := socks5.New(socksConfig)
	if err != nil {
		log.Fatalf("创建SOCKS5服务器失败: %v", err)
	}

	// 使用goroutine启动服务器，支持优雅关闭
	log.Printf("SOCKS5代理服务器正在监听: %s", config.ListenAddr)

	// 创建监听器
	listener, err := net.Listen("tcp", config.ListenAddr)
	if err != nil {
		log.Fatalf("SOCKS5监听端口失败: %v", err)
	}

	// 在goroutine中运行服务器
	go func() {
		if err := server.Serve(listener); err != nil {
			// 忽略关闭时的错误
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("SOCKS5服务器错误: %v", err)
			}
		}
	}()

	// 等待关闭信号
	<-done
	log.Println("正在关闭SOCKS5服务器...")
	listener.Close()
}

// 配置网络环境，智能检测IPv4和IPv6地址并分别配置相应的系统参数
func configureNetworkEnvironment(config Config) error {
	if config.Verbose {
		log.Println("正在分析网络配置...")
	}

	// 分析CIDR列表，分别收集IPv4和IPv6地址
	var ipv4CIDRs []string
	var ipv6CIDRs []string

	for _, cidr := range config.CIDRs {
		ip, _, err := net.ParseCIDR(cidr)
		if err != nil {
			if config.Verbose {
				log.Printf("警告: 无法解析CIDR %s: %v", cidr, err)
			}
			continue
		}

		if ip.To4() != nil {
			// IPv4地址
			ipv4CIDRs = append(ipv4CIDRs, cidr)
		} else {
			// IPv6地址
			ipv6CIDRs = append(ipv6CIDRs, cidr)
		}
	}

	if len(ipv4CIDRs) == 0 && len(ipv6CIDRs) == 0 {
		return fmt.Errorf("未检测到有效的IPv4或IPv6地址，无需配置网络环境")
	}

	if config.Verbose {
		log.Printf("检测到 %d 个IPv4 CIDR 和 %d 个IPv6 CIDR", len(ipv4CIDRs), len(ipv6CIDRs))
	}

	// 配置IPv4环境
	if len(ipv4CIDRs) > 0 {
		if err := configureIPv4Environment(config, ipv4CIDRs); err != nil {
			return fmt.Errorf("IPv4环境配置失败: %v", err)
		}
	}

	// 配置IPv6环境
	if len(ipv6CIDRs) > 0 {
		if err := configureIPv6EnvironmentNew(config, ipv6CIDRs); err != nil {
			return fmt.Errorf("IPv6环境配置失败: %v", err)
		}
	}

	return nil
}

// 配置IPv4环境，设置net.ipv4.ip_nonlocal_bind和IP转发
func configureIPv4Environment(config Config, ipv4CIDRs []string) error {
	if config.Verbose {
		log.Println("正在配置IPv4环境...")
	}

	// 设置net.ipv4.ip_nonlocal_bind=1
	if config.Verbose {
		log.Println("设置net.ipv4.ip_nonlocal_bind=1...")
	}

	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_nonlocal_bind=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 检查是否为权限不足错误
		if strings.Contains(string(output), "Permission denied") || strings.Contains(err.Error(), "Permission denied") {
			return fmt.Errorf("设置net.ipv4.ip_nonlocal_bind需要root权限: %v", err)
		}
		return fmt.Errorf("设置net.ipv4.ip_nonlocal_bind失败: %v, 输出: %s", err, string(output))
	}

	if config.Verbose {
		log.Println("成功设置net.ipv4.ip_nonlocal_bind=1")
	}

	// 设置IPv4转发
	if config.Verbose {
		log.Println("设置net.ipv4.ip_forward=1...")
	}

	cmd = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	output, err = cmd.CombinedOutput()
	if err != nil {
		// 检查是否为权限不足错误
		if strings.Contains(string(output), "Permission denied") || strings.Contains(err.Error(), "Permission denied") {
			return fmt.Errorf("设置net.ipv4.ip_forward需要root权限: %v", err)
		}
		return fmt.Errorf("设置net.ipv4.ip_forward失败: %v, 输出: %s", err, string(output))
	}

	if config.Verbose {
		log.Println("成功设置net.ipv4.ip_forward=1")
	}

	return nil
}

// 配置IPv6环境，设置net.ipv6.ip_nonlocal_bind和本地路由
func configureIPv6EnvironmentNew(config Config, ipv6CIDRs []string) error {
	if config.Verbose {
		log.Println("正在配置IPv6环境...")
	}

	// 设置net.ipv6.ip_nonlocal_bind=1
	if config.Verbose {
		log.Println("设置net.ipv6.ip_nonlocal_bind=1...")
	}

	cmd := exec.Command("sysctl", "-w", "net.ipv6.ip_nonlocal_bind=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 检查是否为权限不足错误
		if strings.Contains(string(output), "Permission denied") || strings.Contains(err.Error(), "Permission denied") {
			return fmt.Errorf("设置net.ipv6.ip_nonlocal_bind需要root权限: %v", err)
		}
		return fmt.Errorf("设置net.ipv6.ip_nonlocal_bind失败: %v, 输出: %s", err, string(output))
	}

	if config.Verbose {
		log.Println("成功设置net.ipv6.ip_nonlocal_bind=1")
	}

	// 设置IPv6转发
	if config.Verbose {
		log.Println("设置net.ipv6.conf.all.forwarding=1...")
	}

	cmd = exec.Command("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
	output, err = cmd.CombinedOutput()
	if err != nil {
		// 检查是否为权限不足错误
		if strings.Contains(string(output), "Permission denied") || strings.Contains(err.Error(), "Permission denied") {
			return fmt.Errorf("设置net.ipv6.conf.all.forwarding需要root权限: %v", err)
		}
		return fmt.Errorf("设置net.ipv6.conf.all.forwarding失败: %v, 输出: %s", err, string(output))
	}

	if config.Verbose {
		log.Println("成功设置net.ipv6.conf.all.forwarding=1")
	}

	// 设置NDP代理
	if config.Verbose {
		log.Println("设置net.ipv6.conf.all.proxy_ndp=1...")
	}

	cmd = exec.Command("sysctl", "-w", "net.ipv6.conf.all.proxy_ndp=1")
	output, err = cmd.CombinedOutput()
	if err != nil {
		// 检查是否为权限不足错误
		if strings.Contains(string(output), "Permission denied") || strings.Contains(err.Error(), "Permission denied") {
			return fmt.Errorf("设置net.ipv6.conf.all.proxy_ndp需要root权限: %v", err)
		}
		return fmt.Errorf("设置net.ipv6.conf.all.proxy_ndp失败: %v, 输出: %s", err, string(output))
	}

	if config.Verbose {
		log.Println("成功设置net.ipv6.conf.all.proxy_ndp=1")
	}

	// 获取网络接口名称并设置接口级别的NDP代理
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			// 跳过回环接口
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			// 只对有IPv6地址的接口设置proxy_ndp
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			hasIPv6 := false
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() == nil {
					hasIPv6 = true
					break
				}
			}

			if hasIPv6 {
				if config.Verbose {
					log.Printf("为接口 %s 设置proxy_ndp...", iface.Name)
				}

				cmd = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.proxy_ndp=1", iface.Name))
				output, err = cmd.CombinedOutput()
				if err != nil {
					if config.Verbose {
						log.Printf("警告: 设置接口 %s 的proxy_ndp失败: %v", iface.Name, err)
					}
				} else if config.Verbose {
					log.Printf("成功设置接口 %s 的proxy_ndp", iface.Name)
				}
			}
		}
	}

	// 为每个IPv6 CIDR添加本地路由
	for _, cidr := range ipv6CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			if config.Verbose {
				log.Printf("警告: 无法解析IPv6 CIDR %s: %v", cidr, err)
			}
			continue
		}

		// 获取标准的/64前缀
		maskSize, _ := ipNet.Mask.Size()
		if maskSize > 64 {
			// 如果前缀长度大于64，截断为64位
			ip := ipNet.IP.To16()
			mask := net.CIDRMask(64, 128)
			ipNet = &net.IPNet{
				IP:   ip,
				Mask: mask,
			}
		}

		routeCmd := exec.Command("ip", "-6", "route", "add", "local", ipNet.String(), "dev", "lo")
		routeOutput, err := routeCmd.CombinedOutput()
		if err != nil {
			// 检查是否为已存在路由
			if strings.Contains(string(routeOutput), "File exists") {
				if config.Verbose {
					log.Printf("IPv6路由 %s 已经存在，跳过", ipNet.String())
				}
				continue
			}

			// 检查是否为权限不足错误
			if strings.Contains(string(routeOutput), "Permission denied") || strings.Contains(err.Error(), "Permission denied") {
				return fmt.Errorf("添加IPv6本地路由需要root权限: %v", err)
			}

			return fmt.Errorf("添加IPv6本地路由失败: %v, 输出: %s", err, string(routeOutput))
		}

		if config.Verbose {
			log.Printf("成功添加IPv6本地路由: %s", ipNet.String())
		}
	}

	return nil
}

// 配置IPv6环境，支持自动设置net.ipv6.ip_nonlocal_bind和本地路由
// 保留原函数以保持向后兼容性
func configureIPv6Environment(config Config) error {
	if config.Verbose {
		log.Println("正在配置IPv6环境...")
	}

	// 检查是否有IPv6 CIDR
	var ipv6CIDRs []string
	for _, cidr := range config.CIDRs {
		ip, _, err := net.ParseCIDR(cidr)
		if err == nil && ip.To4() == nil {
			ipv6CIDRs = append(ipv6CIDRs, cidr)
		}
	}

	if len(ipv6CIDRs) == 0 {
		return fmt.Errorf("未检测到IPv6地址，无需配置IPv6环境")
	}

	return configureIPv6EnvironmentNew(config, ipv6CIDRs)
}

// 启动HTTP代理服务器
func startHttpServer(config Config, dialer *net.Dialer, done chan bool) {
	proxy := NewHttpProxy(dialer, config.EnableAuth, config.Username, config.Password, config.Verbose, &config)

	log.Printf("HTTP代理服务器正在监听: %s", config.HttpListenAddr)

	// 配置HTTP服务器
	server := &http.Server{
		Addr:         config.HttpListenAddr,
		Handler:      proxy,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
		IdleTimeout:  2 * time.Minute,
	}

	// 在goroutine中启动服务器
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("启动HTTP代理服务器失败: %v", err)
		}
	}()

	// 等待关闭信号
	<-done
	log.Println("正在关闭HTTP代理服务器...")

	// 创建5秒超时的上下文用于关闭
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("HTTP服务器关闭错误: %v", err)
	}
}
