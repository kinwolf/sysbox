# Sysbox 核心测试运行指南

## 测试验证结果 ✅

根据验证结果，所有测试用例都已成功创建并通过了基本验证：

### 📊 测试概览
- **测试文件数量**: 12 个
- **总代码行数**: 12,064 行  
- **总测试函数**: 12 个
- **语法检查**: ✅ 通过
- **结构验证**: ✅ 通过
- **依赖检查**: ✅ 通过

### 📁 测试文件列表

| 文件名 | 行数 | 测试函数 | 功能描述 |
|--------|------|----------|----------|
| `runtime_core_test.go` | 437 | 1 | 核心容器运行时流程测试 |
| `fs_virtualization_test.go` | 446 | 1 | 文件系统虚拟化流程测试 |
| `manager_service_test.go` | 666 | 1 | 管理服务流程测试 |
| `dind_workflow_test.go` | 804 | 1 | Docker-in-Docker 工作流程测试 |
| `syscall_interception_test.go` | 989 | 1 | 系统调用拦截处理流程测试 |
| `security_isolation_test.go` | 1,442 | 1 | 安全隔离核心功能测试 |
| `cgroup_management_test.go` | 1,365 | 1 | Cgroup 管理核心流程测试 |
| `kind_workflow_test.go` | 1,389 | 1 | Kubernetes-in-Docker 工作流程测试 |
| `container_lifecycle_test.go` | 1,384 | 1 | 容器生命周期管理测试 |
| `ipc_communication_test.go` | 1,710 | 1 | 组件间 IPC 通信测试 |
| `network_isolation_test.go` | 553 | 1 | 网络隔离核心功能测试 |
| `mount_namespace_test.go` | 879 | 1 | 挂载命名空间管理测试 |

## 🎯 测试特性

### ✅ 已验证的特性
1. **包结构正确**: 所有文件使用 `package core`
2. **导入完整**: 包含必要的 testing 和 testify 包
3. **测试函数**: 每个文件包含主测试函数
4. **环境管理**: 所有测试都有设置和清理函数
5. **资源清理**: 使用 defer 语句确保资源清理
6. **依赖管理**: go.mod 和依赖配置正确

### 🔧 测试架构特点
- **模块化设计**: 每个测试文件专注于特定功能领域
- **环境隔离**: 独立的测试环境设置和清理
- **错误处理**: 完善的错误处理和断言
- **中文注释**: 详细的中文注释和说明
- **性能考虑**: 包含性能测试和基准测试

## 🚀 运行测试

### 前置条件

1. **系统要求**:
   ```bash
   # Ubuntu 20.04+ 或兼容 Linux 发行版
   uname -a
   
   # 内核版本 4.18+（推荐 5.4+）
   uname -r
   ```

2. **Docker 安装和配置**:
   ```bash
   # 检查 Docker 安装
   docker --version
   
   # 启动 Docker 服务
   sudo systemctl start docker
   sudo systemctl enable docker
   
   # 添加用户到 docker 组
   sudo usermod -aG docker $USER
   newgrp docker
   
   # 验证 Docker 运行
   docker run hello-world
   ```

3. **Sysbox 安装**:
   ```bash
   # 下载 Sysbox（根据你的系统版本）
   wget https://github.com/nestybox/sysbox/releases/download/v0.6.4/sysbox-ce_0.6.4-0.linux_amd64.deb
   
   # 安装 Sysbox
   sudo dpkg -i sysbox-ce_0.6.4-0.linux_amd64.deb
   
   # 启动 Sysbox 服务
   sudo systemctl start sysbox
   sudo systemctl enable sysbox
   
   # 验证 Sysbox 运行时
   docker info | grep sysbox-runc
   ```

4. **Go 环境**:
   ```bash
   # 安装 Go 1.19+
   wget https://go.dev/dl/go1.21.4.linux-amd64.tar.gz
   sudo tar -C /usr/local -xzf go1.21.4.linux-amd64.tar.gz
   export PATH=$PATH:/usr/local/go/bin
   
   # 验证 Go 安装
   go version
   ```

### 环境验证

运行测试前，请确保环境正确配置：

```bash
# 1. 检查 Docker 状态
docker info

# 2. 检查 Sysbox 运行时
docker info | grep -i sysbox

# 3. 检查 Sysbox 服务
sudo systemctl status sysbox-mgr
sudo systemctl status sysbox-fs

# 4. 测试 Sysbox 容器创建
docker run --runtime=sysbox-runc --rm ubuntu:20.04 echo "Sysbox 工作正常"
```

### 运行测试

1. **进入测试目录**:
   ```bash
   cd tests/core
   ```

2. **初始化 Go 模块**（如果尚未完成）:
   ```bash
   go mod init sysbox-core-tests
   go mod tidy
   ```

3. **运行验证脚本**:
   ```bash
   ./check_tests.sh
   ```

4. **运行单个测试文件**:
   ```bash
   # 运行核心运行时测试
   go test -v -timeout 30m ./runtime_core_test.go
   
   # 运行文件系统虚拟化测试
   go test -v -timeout 30m ./fs_virtualization_test.go
   
   # 运行安全隔离测试
   go test -v -timeout 30m ./security_isolation_test.go
   ```

5. **运行特定测试函数**:
   ```bash
   # 运行特定的测试函数
   go test -v -run TestSysboxRuntimeCore -timeout 30m
   go test -v -run TestDockerInDockerWorkflow -timeout 30m
   go test -v -run TestKubernetesInDockerWorkflow -timeout 30m
   ```

6. **运行所有测试**:
   ```bash
   # 运行所有核心测试
   go test -v -timeout 60m ./...
   
   # 并行运行测试
   go test -v -parallel 4 -timeout 60m ./...
   ```

7. **生成覆盖率报告**:
   ```bash
   # 生成覆盖率报告
   go test -v -coverprofile=coverage.out -timeout 60m ./...
   go tool cover -html=coverage.out -o coverage.html
   ```

### 测试选项

```bash
# 启用详细输出
go test -v -args -debug

# 设置测试超时
go test -timeout 60m ./...

# 保留失败测试的容器（用于调试）
export KEEP_FAILED_CONTAINERS=1
go test -v ./...

# 启用调试模式
export DEBUG_ON=1
go test -v ./...
```

## 🐛 故障排除

### 常见问题

1. **Sysbox 运行时未配置**:
   ```bash
   # 检查 Docker 配置
   cat /etc/docker/daemon.json
   
   # 应该包含 sysbox-runc 运行时配置
   # 重启 Docker 服务
   sudo systemctl restart docker
   ```

2. **权限不足**:
   ```bash
   # 确保用户在 docker 组
   groups $USER | grep docker
   
   # 如果不在，添加用户到 docker 组
   sudo usermod -aG docker $USER
   newgrp docker
   ```

3. **容器创建失败**:
   ```bash
   # 检查 Sysbox 服务状态
   sudo systemctl status sysbox-mgr
   sudo systemctl status sysbox-fs
   
   # 查看 Sysbox 日志
   sudo journalctl -u sysbox-mgr -f
   sudo journalctl -u sysbox-fs -f
   ```

4. **测试超时**:
   ```bash
   # 增加测试超时时间
   go test -timeout 90m ./...
   
   # 检查系统资源
   htop
   df -h
   free -h
   ```

5. **网络问题**:
   ```bash
   # 检查 Docker 网络
   docker network ls
   
   # 重启 Docker 网络
   sudo systemctl restart docker
   ```

### 调试模式

```bash
# 启用详细调试输出
export DEBUG_ON=1
export KEEP_FAILED_CONTAINERS=1
go test -v -timeout 60m ./...

# 查看容器状态
docker ps -a | grep test-

# 检查容器日志
docker logs <container-id>

# 进入容器调试
docker exec -it <container-id> /bin/bash
```

### 清理环境

```bash
# 清理测试容器
docker rm -f $(docker ps -aq --filter "name=test-")

# 清理测试镜像
docker image prune -f

# 清理测试卷
docker volume prune -f

# 清理测试网络
docker network prune -f
```

## 📈 性能基准

### 预期性能指标

- **容器创建时间**: < 5 秒
- **文件系统操作**: < 100ms
- **网络延迟**: < 1ms（容器间）
- **IPC 通信**: < 50ms
- **测试套件总时间**: < 30 分钟

### 性能监控

```bash
# 运行性能基准测试
go test -bench=. -benchmem ./...

# 监控系统资源
htop  # CPU 和内存使用
iotop # I/O 使用
nethogs # 网络使用
```

## 🔄 持续集成

### GitHub Actions 示例

```yaml
name: Sysbox Core Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-20.04
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Go
      uses: actions/setup-go@v2
      with:
        go-version: 1.21
    
    - name: Install Sysbox
      run: |
        wget https://github.com/nestybox/sysbox/releases/download/v0.6.4/sysbox-ce_0.6.4-0.linux_amd64.deb
        sudo dpkg -i sysbox-ce_0.6.4-0.linux_amd64.deb
        sudo systemctl start sysbox
    
    - name: Run Tests
      run: |
        cd tests/core
        go test -v -timeout 60m ./...
```

## 📝 测试报告

测试完成后，你将获得：

1. **测试结果报告**: 每个测试的通过/失败状态
2. **覆盖率报告**: 代码覆盖率分析
3. **性能基准**: 性能测试结果
4. **错误日志**: 详细的错误信息和调试信息

## 🤝 贡献指南

1. **添加新测试**:
   - 遵循现有的测试模式
   - 包含设置和清理函数
   - 添加详细的中文注释
   - 更新此文档

2. **报告问题**:
   - 提供详细的错误信息
   - 包含系统环境信息
   - 提供重现步骤

3. **提交改进**:
   - 遵循代码规范
   - 运行所有测试确保不破坏现有功能
   - 更新相关文档

---

**注意**: 这些测试需要运行在支持 Sysbox 的 Linux 环境中。测试覆盖了 Sysbox 的核心功能，包括容器运行时、文件系统虚拟化、网络隔离、安全特性等。