# 第一阶段：构建阶段
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装构建依赖
RUN apk add --no-cache git

# 复制go.mod和go.sum
COPY go.mod go.sum* ./
# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 使用安全编译选项构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -extldflags=-static" -o ipv6-proxy .

# 第二阶段：运行阶段
FROM alpine:latest

# 安装必要的运行时依赖
RUN apk --no-cache add ca-certificates tzdata && \
    apk --no-cache upgrade

# 创建非root用户和工作目录
RUN addgroup -S appgroup && \
    adduser -S appuser -G appgroup && \
    mkdir -p /app/data && \
    chown -R appuser:appgroup /app

# 从构建阶段复制二进制文件
COPY --from=builder --chown=appuser:appgroup /app/ipv6-proxy /app/

# 设置时区
ENV TZ=Asia/Shanghai

# 添加网络相关权限
RUN apk --no-cache add iproute2 iputils 

# 工作目录
WORKDIR /app

# 添加健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ps aux | grep ipv6-proxy | grep -v grep || exit 1

# 设置安全相关环境变量
ENV GODEBUG=netdns=go
ENV HOME=/app

# 设置用户
USER appuser

# 限制容器权限
# 注意：由于应用需要NET_ADMIN权限和host网络模式，这些限制在运行时需要被覆盖
# 但我们仍然设置最小默认值，以便在不需要特权时使用
EXPOSE 20808 38080
VOLUME ["/app/data"]

# 设置入口点
ENTRYPOINT ["/app/ipv6-proxy"]

# 默认参数（同时启用SOCKS5和HTTP代理）
CMD ["--help"]

# 添加标签
LABEL maintainer="seongminhwan" \
      description="IPv6/IPv4动态多协议代理服务器" \
      version="1.0" \
      org.opencontainers.image.vendor="seongminhwan" \
      org.opencontainers.image.title="IPv6动态代理" \
      org.opencontainers.image.documentation="https://github.com/seongminhwan/ipv6-dynamic-proxy" \
      security.privileged="true" \
      security.network="host"

# 添加说明
LABEL org.opencontainers.image.description="安全警告: 此镜像需要使用host网络模式和NET_ADMIN权限才能正常工作，可能带来安全风险。在生产环境中使用前，请先阅读SECURITY.md文件了解安全最佳实践。使用示例：docker run --network host --cap-add=NET_ADMIN ghcr.io/seongminhwan/ipv6-dynamic-proxy --cidr 2001:db8::/64 --listen 127.0.0.1:20808 --http-listen 127.0.0.1:38080 --auth --username myuser --password mypassword"