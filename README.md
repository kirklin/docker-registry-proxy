# Docker Registry Proxy

Docker Registry Proxy 是一个高性能的Docker代理服务器，用于转发 Docker 镜像仓库的请求。
它支持多个 Docker 镜像仓库，包括 Docker Hub、Quay.io、Google Container Registry (GCR)、GitHub Container Registry (GHCR) 等。

## 特性

- 支持多个 Docker 镜像仓库
- 自定义域名路由
- 处理 Docker 镜像仓库的认证流程
- 特殊处理 Docker Hub 官方镜像
- 高性能（基于 Gin 框架）
- 可自定义配置

## 安装

确保你已经安装了 Go (版本 1.16+)。然后，按照以下步骤安装：

1. 克隆仓库：

```bash
git clone https://github.com/kirklin/docker-registry-proxy.git
```

2. 进入项目目录：

```bash
cd docker-registry-proxy
```

3. 安装依赖：

```bash
go mod tidy
```

## 使用方法

### 基本用法

1. 编译并运行程序：

```bash
go run main.go
```

2. 默认情况下，服务器将在 8080 端口启动。

### 自定义配置

你可以通过命令行参数自定义服务器的配置：

- `-port`: 指定服务器端口（默认: 8080）
- `-domain`: 指定域名后缀（默认: example.com）
- `-routes`: 自定义路由（格式: subdomain1=url1,subdomain2=url2）

例如：

```bash
go run main.go -port 9000 -domain example.com -routes "docker=https://registry-1.docker.io,custom=https://my-custom-registry.com"
```

## 配置 Docker 客户端

要使用这个代理，你需要配置 Docker 客户端。编辑 `/etc/docker/daemon.json` 文件（如果文件不存在，请创建它），添加以下内容：

```json
{
  "registry-mirrors": [
    "http://docker.example.com:8080"
  ]
}
```

将 `docker.example.com` 替换为你的代理服务器域名，`8080` 替换为你配置的端口号。

重启 Docker 守护进程以使更改生效：

```bash
sudo systemctl restart docker
```

## 开发

### 运行测试

运行单元测试：

```bash
go test -v
```