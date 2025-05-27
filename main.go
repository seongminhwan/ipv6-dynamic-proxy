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
	"os"
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

// 生成随机用户名和密码
func generateRandomCredentials() (string, string) {
	// 生成16字节的随机数据用于用户名
	userBytes := make([]byte, 8)
	if _, err := rand.Read(userBytes); err != nil {
		log.Printf("生成随机用户名失败: %v，使用默认值", err)
		return "user_" + fmt.Sprint(time.Now().Unix()), "pass_" + fmt.Sprint(time.Now().Unix())
	}

	// 生成16字节的随机数据用于密码
	passBytes := make([]byte, 12)
	if _, err := rand.Read(passBytes); err != nil {
		log.Printf("生成随机密码失败: %v，使用默认值", err)
		return "user_" + fmt.Sprint(time.Now().Unix()), "pass_" + fmt.Sprint(time.Now().Unix())
	}

	// 使用Base64编码
	username := base64.RawURLEncoding.EncodeToString(userBytes)
	password := base64.RawURLEncoding.EncodeToString(passBytes)

	return username, password
}

// 获取系统网络接口上配置的IP地址
// ipVersion: 0=全部, 4=仅IPv4, 6=仅IPv6
func getSystemIPs(includePrivateIPs bool, ipVersion int) ([]string, error) {
	var ips []string

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

				// 构建CIDR格式: IP/32 表示单个IPv4地址，IP/128表示单个IPv6地址
				if isIPv4 {
					// IPv4地址
					ips = append(ips, fmt.Sprintf("%s/32", v.IP.String()))
				} else {
					// IPv6地址
					ips = append(ips, fmt.Sprintf("%s/128", v.IP.String()))
				}
			}
		}
	}
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
	if bits-maskSize > 32 {
		// 对于大型网络，我们限制生成范围，避免过大的随机数
		maskSize = bits - 32
	}

	// 生成随机IP
	ip := make([]byte, len(ipNet.IP))
	copy(ip, ipNet.IP)

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

	return ip, nil
}

// 创建一个自定义的Dialer，用于使用随机IP作为源IP
func createDialer(cidrList []string, config Config) *net.Dialer {
	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			if len(cidrList) == 0 {
				return nil // 如果没有指定CIDR，使用默认IP
			}

			var sourceIP net.IP

			// 如果启用了端口映射功能
			if config.EnablePortMapping {
				// 从地址中提取端口
				_, portStr, err := net.SplitHostPort(address)
				if err != nil {
					if config.Verbose {
						log.Printf("解析地址失败: %v", err)
					}
					return nil
				}

				// 将端口转换为数字
				port, err := strconv.Atoi(portStr)
				if err != nil {
					if config.Verbose {
						log.Printf("解析端口失败: %v", err)
					}
					return nil
				}

				// 确定端口范围
				endPort := config.EndPort
				if endPort <= 0 {
					endPort = config.StartPort
				}

				// 计算端口偏移量
				portOffset := 0
				if port >= config.StartPort && port <= endPort {
					portOffset = port - config.StartPort
				} else {
					// 如果端口不在指定范围内，使用默认偏移量
					portOffset = port % (endPort - config.StartPort + 1)
				}

				// 将偏移量映射到CIDR列表索引
				cidrIndex := portOffset % len(cidrList)
				cidr := cidrList[cidrIndex]

				// 分离IPv4和IPv6 CIDR
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

				// 优先使用IPv4地址
				if len(ipv4CIDRs) > 0 {
					cidrIndex = portOffset % len(ipv4CIDRs)
					cidr = ipv4CIDRs[cidrIndex]
				} else if len(ipv6CIDRs) > 0 {
					cidrIndex = portOffset % len(ipv6CIDRs)
					cidr = ipv6CIDRs[cidrIndex]
				}

				// 根据CIDR生成IP
				sourceIP, err = generateRandomIP(cidr)
				if err != nil {
					if config.Verbose {
						log.Printf("为端口 %d 生成IP失败: %v，使用默认IP", port, err)
					}
					return nil
				}

				if config.Verbose {
					log.Printf("端口映射: 端口 %d -> CIDR %s -> IP %s", port, cidr, sourceIP.String())
				}
			} else {
				// 使用常规的随机IP选择
				randNum, err := rand.Int(rand.Reader, big.NewInt(int64(len(cidrList))))
				if err != nil {
					if config.Verbose {
						log.Printf("生成随机数失败: %v，使用默认CIDR选择", err)
					}
					// 出错时退回到简单方法
					randNum = big.NewInt(int64(time.Now().Nanosecond() % len(cidrList)))
				}

				cidr := cidrList[randNum.Int64()]
				sourceIP, err = generateRandomIP(cidr)
				if err != nil {
					if config.Verbose {
						log.Printf("生成随机IP失败: %v，使用默认IP", err)
					}
					return nil
				}
			}

			if config.Verbose {
				log.Printf("使用源IP: %s 连接到: %s", sourceIP.String(), address)
			}

			// 设置源IP
			var innerErr error
			err = c.Control(func(fd uintptr) {
				// 绑定到指定的源IP
				if strings.Contains(network, "tcp6") || strings.Contains(network, "udp6") {
					innerErr = syscall.SetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, &syscall.IPv6Mreq{})
					sa := &syscall.SockaddrInet6{Port: 0}
					copy(sa.Addr[:], sourceIP.To16())
					innerErr = syscall.Bind(int(fd), sa)
				} else {
					sa := &syscall.SockaddrInet4{Port: 0}
					copy(sa.Addr[:], sourceIP.To4())
					innerErr = syscall.Bind(int(fd), sa)
				}
			})

			if innerErr != nil && config.Verbose {
				log.Printf("绑定源IP失败: %v", innerErr)
			}

			return innerErr
		},
	}
}

// 自定义认证器
type CredentialStore struct {
	Username string
	Password string
}

func (c *CredentialStore) Valid(user, password string) bool {
	return user == c.Username && password == c.Password
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
}

func NewHttpProxy(dialer *net.Dialer, auth bool, username, password string, verbose bool) *HttpProxy {
	return &HttpProxy{
		dialer:   dialer,
		auth:     auth,
		username: username,
		password: password,
		verbose:  verbose,
	}
}

func (p *HttpProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 验证认证信息
	if p.auth {
		authHeader := r.Header.Get("Proxy-Authorization")
		if authHeader == "" {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Access to proxy\"")
			http.Error(w, "需要代理认证", http.StatusProxyAuthRequired)
			return
		}

		authParts := strings.SplitN(authHeader, " ", 2)
		if len(authParts) != 2 || authParts[0] != "Basic" {
			http.Error(w, "认证格式错误", http.StatusBadRequest)
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(authParts[1])
		if err != nil {
			http.Error(w, "认证格式错误", http.StatusBadRequest)
			return
		}

		credentials := strings.SplitN(string(decoded), ":", 2)
		if len(credentials) != 2 || credentials[0] != p.username || credentials[1] != p.password {
			w.Header().Set("Proxy-Authenticate", "Basic realm=\"Access to proxy\"")
			http.Error(w, "认证失败", http.StatusProxyAuthRequired)
			return
		}
	}

	// 处理CONNECT请求（HTTPS）
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// 处理普通HTTP请求
	p.handleHTTP(w, r)
}

func (p *HttpProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if p.verbose {
		log.Printf("处理CONNECT请求: %s", r.Host)
	}

	// 建立到目标服务器的连接
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	targetConn, err := p.dialer.DialContext(ctx, "tcp", r.Host)
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
		log.Printf("CONNECT连接已完成: %s", r.Host)
	}
}

func (p *HttpProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if p.verbose {
		log.Printf("处理HTTP请求: %s %s", r.Method, r.URL)
	}

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

	// 使用随机IP拨号器创建HTTP客户端
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:         p.dialer.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
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
	io.Copy(w, resp.Body)

	if p.verbose {
		log.Printf("HTTP请求已完成: %s %s, 状态: %d", r.Method, r.URL, resp.StatusCode)
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

			// 如果启用了认证但未提供用户名密码，则生成随机凭据
			if config.EnableAuth && (config.Username == "" || config.Password == "") {
				config.Username, config.Password = generateRandomCredentials()
				log.Printf("已生成随机凭据 - 用户名: %s, 密码: %s", config.Username, config.Password)
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

			// 创建退出信号通道
			exitChan := make(chan os.Signal, 1)
			signal.Notify(exitChan, syscall.SIGINT, syscall.SIGTERM)

			// 创建自定义拨号器
			dialer := createDialer(config.CIDRs, config)

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
	rootCmd.Flags().StringVarP(&config.ListenAddr, "listen", "l", "127.0.0.1:1080", "SOCKS5代理服务器监听地址")
	rootCmd.Flags().StringVarP(&config.HttpListenAddr, "http-listen", "H", "127.0.0.1:8080", "HTTP代理服务器监听地址")
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
		}
		socksConfig.AuthMethods = []socks5.Authenticator{socks5.UserPassAuthenticator{Credentials: creds}}
		log.Println("已启用SOCKS5用户名/密码认证")
	}

	// 设置自定义的拨号器
	socksConfig.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
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

// 启动HTTP代理服务器
func startHttpServer(config Config, dialer *net.Dialer, done chan bool) {
	proxy := NewHttpProxy(dialer, config.EnableAuth, config.Username, config.Password, config.Verbose)

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
