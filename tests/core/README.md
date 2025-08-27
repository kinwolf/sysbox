# Sysbox 核心流程测试套件

这个目录包含了针对 Sysbox 核心功能的全面测试用例，用于验证 Sysbox 容器运行时的各个关键组件和流程。

## 测试文件概览

| 测试文件 | 测试内容 | 主要功能验证 |
|---------|----------|-------------|
| `runtime_core_test.go` | 核心容器运行时流程 | sysbox-runc 基本功能、容器生命周期、用户命名空间隔离 |
| `fs_virtualization_test.go` | 文件系统虚拟化流程 | sysbox-fs 的 procfs/sysfs 虚拟化、FUSE 文件系统性能 |
| `manager_service_test.go` | 管理服务流程 | sysbox-mgr 守护进程功能、UID/GID 映射管理、资源分配 |
| `dind_workflow_test.go` | Docker-in-Docker 核心工作流程 | 容器内运行 Docker、多层容器嵌套、Docker Compose 支持 |
| `syscall_interception_test.go` | 系统调用拦截处理流程 | 挂载/文件系统/网络系统调用处理、容器逃逸防护 |
| `security_isolation_test.go` | 安全隔离核心功能 | 用户命名空间安全、文件系统边界、多租户隔离 |
| `cgroup_management_test.go` | Cgroup 管理核心流程 | 内存/CPU/PID cgroup 管理、资源限制、容器间隔离 |
| `kind_workflow_test.go` | Kubernetes-in-Docker 核心工作流程 | K8s 集群设置、kubelet 配置、Pod 管理、服务发现 |
| `container_lifecycle_test.go` | 容器生命周期管理核心流程 | 容器创建/启动/暂停/停止/删除、健康检查、资源约束 |
| `ipc_communication_test.go` | 组件间 IPC 通信核心流程 | gRPC 通信、消息序列化、错误处理、性能监控 |

## 测试架构

### 核心组件测试覆盖

1. **sysbox-runc**: 容器运行时前端
   - 容器创建、启动、停止、删除
   - 用户命名空间配置
   - 网络和文件系统隔离
   - 安全策略执行

2. **sysbox-fs**: FUSE 文件系统守护进程
   - procfs/sysfs 虚拟化
   - 动态文件内容生成
   - 文件系统性能优化
   - 容器间文件系统隔离

3. **sysbox-mgr**: 管理服务守护进程
   - 用户/组 ID 映射管理
   - 容器注册与注销
   - 特殊挂载管理
   - 资源分配与回收

### 测试分类

#### 功能测试
- 基本功能验证
- 组件间协作
- 错误处理
- 边界条件测试

#### 性能测试
- 系统调用延迟
- 文件系统操作性能
- IPC 通信效率
- 资源使用监控

#### 安全测试
- 权限隔离验证
- 容器逃逸防护
- 多租户安全
- 敏感信息保护

#### 集成测试
- Docker-in-Docker 场景
- Kubernetes-in-Docker 场景
- 多容器并发操作
- 复杂工作负载支持

## 运行测试

### 前置条件

1. **系统要求**:
   - Linux 内核 4.18+ (推荐 5.4+)
   - Docker 引擎运行
   - Sysbox 已安装并配置

2. **依赖工具**:
   ```bash
   # 安装 Go 测试依赖
   go mod tidy
   
   # 安装必要的系统工具
   sudo apt-get update
   sudo apt-get install -y net-tools procps iproute2
   ```

3. **Sysbox 配置**:
   ```bash
   # 验证 sysbox-runc 运行时已配置
   docker info | grep sysbox-runc
   
   # 确保 sysbox 服务运行
   sudo systemctl status sysbox
   ```

### 执行单个测试文件

```bash
# 运行核心运行时测试
go test -v ./tests/core/runtime_core_test.go

# 运行文件系统虚拟化测试
go test -v ./tests/core/fs_virtualization_test.go

# 运行安全隔离测试
go test -v ./tests/core/security_isolation_test.go
```

### 执行完整测试套件

```bash
# 运行所有核心测试
go test -v ./tests/core/

# 运行特定测试模式
go test -v -run TestSysboxRuntimeCore ./tests/core/
go test -v -run TestDockerInDockerWorkflow ./tests/core/
```

### 测试配置选项

```bash
# 启用详细输出
go test -v -args -debug

# 设置测试超时
go test -timeout 30m ./tests/core/

# 并行执行测试
go test -parallel 4 ./tests/core/

# 生成测试覆盖率报告
go test -coverprofile=coverage.out ./tests/core/
go tool cover -html=coverage.out
```

## 测试数据和清理

### 测试容器管理
- 每个测试都会自动清理创建的容器
- 测试容器命名规则: `test-{功能}-{随机ID}`
- 失败测试的容器会保留用于调试

### 测试数据清理
```bash
# 清理所有测试容器
docker rm -f $(docker ps -aq --filter "name=test-")

# 清理测试镜像
docker image prune -f

# 清理测试卷
docker volume prune -f
```

## 故障排除

### 常见问题

1. **sysbox-runc 运行时未配置**:
   ```bash
   # 检查 Docker 配置
   cat /etc/docker/daemon.json
   
   # 重启 Docker
   sudo systemctl restart docker
   ```

2. **权限不足**:
   ```bash
   # 确保当前用户在 docker 组
   sudo usermod -aG docker $USER
   newgrp docker
   ```

3. **容器创建失败**:
   ```bash
   # 检查 sysbox 服务状态
   sudo systemctl status sysbox-mgr
   sudo systemctl status sysbox-fs
   
   # 查看 sysbox 日志
   sudo journalctl -u sysbox-mgr -f
   sudo journalctl -u sysbox-fs -f
   ```

4. **测试超时**:
   ```bash
   # 增加测试超时时间
   go test -timeout 60m ./tests/core/
   
   # 检查系统资源
   htop
   df -h
   ```

### 调试模式

```bash
# 启用调试输出
export DEBUG_ON=1
go test -v ./tests/core/

# 保留失败测试的容器
export KEEP_FAILED_CONTAINERS=1
go test -v ./tests/core/
```

## 测试扩展

### 添加新测试

1. **创建测试文件**:
   ```go
   package core
   
   import (
       "testing"
       "github.com/stretchr/testify/assert"
   )
   
   func TestNewFeature(t *testing.T) {
       // 测试设置
       setupNewFeatureTestEnv(t)
       defer cleanupNewFeatureTestEnv(t)
       
       // 测试用例
       t.Run("基本功能测试", func(t *testing.T) {
           testBasicFeature(t)
       })
   }
   ```

2. **遵循测试模式**:
   - 使用 `setup*TestEnv()` 和 `cleanup*TestEnv()` 函数
   - 每个测试用例独立可运行
   - 适当的断言和错误处理
   - 详细的日志输出

3. **更新文档**:
   - 在此 README 中添加新测试的描述
   - 更新测试覆盖范围说明

### 性能基准测试

```go
func BenchmarkContainerCreation(b *testing.B) {
    for i := 0; i < b.N; i++ {
        containerID := createSysboxContainer(b, "bench-container", "ubuntu:20.04", []string{"sleep", "1"})
        cleanupContainer(b, containerID)
    }
}
```

## 贡献指南

1. **代码规范**:
   - 遵循 Go 代码规范
   - 使用有意义的测试函数名
   - 添加适当的注释

2. **测试质量**:
   - 确保测试的可重复性
   - 处理所有错误情况
   - 验证测试清理完整性

3. **文档更新**:
   - 更新相关文档
   - 添加使用示例
   - 说明新功能的测试覆盖

## 许可证

本测试套件遵循与 Sysbox 项目相同的许可证条款。