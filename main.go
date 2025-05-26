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
func createDialer(cidrList []string, verbose bool) *net.Dialer {
	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			if len(cidrList) == 0 {
				return nil // 如果没有指定CIDR，使用默认IP
			}

			// 随机选择一个CIDR
			cidr := cidrList[os.Getpid()%len(cidrList)]
			sourceIP, err := generateRandomIP(cidr)
			if err != nil {
				if verbose {
					log.Printf("生成随机IP失败: %v，使用默认IP", err)
				}
				return nil
			}

			if verbose {
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

			if innerErr != nil && verbose {
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

	var d net.Dialer
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
可以通过指定CIDR范围来定义可用的IP地址池。`,
		Run: func(cmd *cobra.Command, args []string) {
			// 配置日志
			if config.Verbose {
				log.SetFlags(log.LstdFlags | log.Lshortfile)
				log.Println("详细日志模式已启用")
				log.Printf("配置: %+v", config)
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
			dialer := createDialer(config.CIDRs, config.Verbose)

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
	rootCmd.Flags().BoolVarP(&config.EnableAuth, "auth", "a", false, "启用用户名/密码验证")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "启用详细日志")
	rootCmd.Flags().StringVarP(&config.ProxyType, "type", "t", "both", "代理类型: socks5, http 或 both (同时启用两种代理)")

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
		if config.Username == "" || config.Password == "" {
			log.Fatal("启用认证时必须提供用户名和密码")
		}
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
