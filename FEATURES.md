# Sysbox 功能特性概览

## 项目简介

Sysbox 是一个增强型容器运行时，让普通容器能够运行系统级软件，同时提供更强的安全隔离。可以将其视为"容器增强器"，无需修改现有工作流即可部署类似虚拟机的容器。

## 核心功能

### 🔒 增强安全隔离
- **用户命名空间隔离**：容器内 root 用户在主机上无权限
- **文件系统虚拟化**：隐藏和保护主机敏感信息
- **强制命名空间**：自动启用所有 Linux 命名空间

### 🖥️ 系统级工作负载
- **Docker-in-Docker**：容器内安全运行 Docker，无需特权模式
- **Kubernetes-in-Docker**：将容器作为 K8s 节点使用
- **Systemd 支持**：容器内原生运行系统服务
- **构建工具**：支持 Buildx、Buildkit 等镜像构建工具

### ⚡ 高性能特性
- **快速启动**：几秒内完成容器启动
- **资源高效**：相比虚拟机提供 2 倍部署密度
- **原生性能**：与标准 runc 相当的运行性能

## 基本使用

### Docker 方式
```bash
# 创建系统容器
docker run --runtime=sysbox-runc -it ubuntu:20.04

# 在容器内运行 Docker
docker run --runtime=sysbox-runc -d \
  nestybox/ubuntu-bionic-systemd-docker
```

### Kubernetes 方式
```yaml
apiVersion: v1
kind: Pod
spec:
  runtimeClassName: sysbox-runc
  containers:
  - name: sys-container
    image: ubuntu:20.04
```

## 主要优势

- **无侵入性**：无需修改现有容器镜像或工作流
- **OCI 兼容**：与 Docker、Kubernetes 等标准工具集成
- **多架构支持**：支持 x86_64、ARM64 等主流架构
- **并存部署**：可与其他容器运行时同时使用

## 适用场景

- **CI/CD 安全化**：替代不安全的特权容器
- **开发环境**：轻量级虚拟机替代方案  
- **微服务隔离**：增强容器间安全边界
- **遗留应用**：将传统应用迁移到容器环境
- **学习测试**：快速搭建 Kubernetes 等环境

## 系统要求

- Linux 内核 4.18+ (推荐 5.4+)
- 支持的发行版：Ubuntu、Debian、CentOS、RHEL 等
- Docker 或 Kubernetes 环境

更多详细信息请参考 [完整文档](docs/README.md)。