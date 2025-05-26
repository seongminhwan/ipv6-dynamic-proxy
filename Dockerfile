# 第一阶段：构建阶段
FROM golang:1.21-alpine AS builder

# 设置工作目录
WORKDIR /app

# 安装构建依赖
RUN apk add --no-cache git

# 复制go.mod和go.sum
COPY go.mod ./
# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ipv6-proxy .

# 第二阶段：运行阶段
FROM alpine:latest

# 安装必要的运行时依赖
RUN apk --no-cache add ca-certificates tzdata

# 创建非root用户
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# 从构建阶段复制二进制文件
COPY --from=builder /app/ipv6-proxy /usr/local/bin/

# 设置时区
ENV TZ=Asia/Shanghai

# 添加网络相关权限
RUN apk --no-cache add iproute2 iputils 

# 设置用户
USER appuser

# 设置入口点
ENTRYPOINT ["ipv6-proxy"]

# 默认参数
CMD ["--help"]

# 添加标签
LABEL maintainer="jpanda" \
      description="IPv6动态代理服务器" \
      version="1.0"

# 添加说明
LABEL org.opencontainers.image.description="此镜像需要使用host网络模式运行，例如：docker run --network host jpanda/ipv6-dynamic-proxy"