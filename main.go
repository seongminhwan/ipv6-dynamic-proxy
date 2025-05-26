package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/armon/go-socks5"
	"github.com/spf13/cobra"
)

// 配置选项
type Config struct {
	// 代理服务器监听地址
	ListenAddr string
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
			randByte := byte(os.Getpid() * os.Getppid() % 256)
			ip[i] = (ip[i] & mask) | (randByte & ^mask)
		} else {
			// 完全随机的字节
			ip[i] = byte(os.Getpid() * os.Getppid() * (i + 1) % 256)
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
					innerErr = syscall.SetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, syscall.IPv6Mreq{})
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

func main() {
	var config Config

	// 定义根命令
	rootCmd := &cobra.Command{
		Use:   "ipv6-dynamic-proxy",
		Short: "一个支持动态IPv6/IPv4出口的代理服务器",
		Long: `一个SOCKS5代理服务器，支持使用随机IPv6/IPv4地址作为出口。
可以通过指定CIDR范围来定义可用的IP地址池。`,
		Run: func(cmd *cobra.Command, args []string) {
			// 配置日志
			if config.Verbose {
				log.SetFlags(log.LstdFlags | log.Lshortfile)
				log.Println("详细日志模式已启用")
				log.Printf("配置: %+v", config)
			}

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
				log.Println("已启用用户名/密码认证")
			}

			// 设置自定义的拨号器
			dialer := createDialer(config.CIDRs, config.Verbose)
			socksConfig.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			}

			// 创建SOCKS5服务器
			server, err := socks5.New(socksConfig)
			if err != nil {
				log.Fatalf("创建SOCKS5服务器失败: %v", err)
			}

			// 启动服务器
			log.Printf("SOCKS5代理服务器正在监听: %s", config.ListenAddr)
			if err := server.ListenAndServe("tcp", config.ListenAddr); err != nil {
				log.Fatalf("启动服务器失败: %v", err)
			}
		},
	}

	// 添加命令行参数
	rootCmd.Flags().StringVarP(&config.ListenAddr, "listen", "l", "127.0.0.1:1080", "代理服务器监听地址")
	rootCmd.Flags().StringSliceVarP(&config.CIDRs, "cidr", "c", []string{}, "CIDR范围列表，例如: 2001:db8::/64")
	rootCmd.Flags().StringVarP(&config.Username, "username", "u", "", "验证用户名")
	rootCmd.Flags().StringVarP(&config.Password, "password", "p", "", "验证密码")
	rootCmd.Flags().BoolVarP(&config.EnableAuth, "auth", "a", false, "启用用户名/密码验证")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "启用详细日志")

	// 执行命令
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
