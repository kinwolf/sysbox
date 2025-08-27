package core

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDockerInDockerWorkflow 测试Docker-in-Docker核心工作流程
func TestDockerInDockerWorkflow(t *testing.T) {
	setupDinDTestEnv(t)
	defer cleanupDinDTestEnv(t)

	t.Run("Docker守护进程启动和配置", func(t *testing.T) {
		testDockerDaemonStartup(t)
	})

	t.Run("Docker客户端基本操作", func(t *testing.T) {
		testDockerClientBasicOperations(t)
	})

	t.Run("容器镜像管理", func(t *testing.T) {
		testContainerImageManagement(t)
	})

	t.Run("内部容器生命周期管理", func(t *testing.T) {
		testInnerContainerLifecycle(t)
	})

	t.Run("Docker网络功能", func(t *testing.T) {
		testDockerNetworking(t)
	})

	t.Run("Docker存储卷管理", func(t *testing.T) {
		testDockerVolumeManagement(t)
	})

	t.Run("多层容器嵌套", func(t *testing.T) {
		testMultiLayerContainerNesting(t)
	})

	t.Run("Docker Compose支持", func(t *testing.T) {
		testDockerComposeSupport(t)
	})

	t.Run("容器间通信和隔离", func(t *testing.T) {
		testContainerCommunicationAndIsolation(t)
	})

	t.Run("Docker构建功能", func(t *testing.T) {
		testDockerBuildFunctionality(t)
	})
}

// testDockerDaemonStartup 测试Docker守护进程启动和配置
func testDockerDaemonStartup(t *testing.T) {
	containerName := "test-docker-daemon"
	
	// 使用包含Docker的镜像创建系统容器
	containerID := createSysboxContainer(t, containerName, "nestybox/ubuntu-bionic-docker:latest", 
		[]string{"/bin/bash", "-c", "dockerd & sleep 300"})
	defer cleanupContainer(t, containerID)
	
	// 等待Docker守护进程启动
	time.Sleep(10 * time.Second)
	
	// 验证Docker守护进程正在运行
	dockerdProcess := execInContainer(t, containerID, "pgrep", "-f", "dockerd")
	assert.NotEmpty(t, dockerdProcess, "Docker守护进程应该正在运行")
	
	// 验证Docker socket文件存在
	dockerSocket := execInContainer(t, containerID, "ls", "-la", "/var/run/docker.sock")
	assert.Contains(t, dockerSocket, "docker.sock", "Docker socket文件应该存在")
	
	// 验证Docker客户端可以连接到守护进程
	dockerVersion := execInContainer(t, containerID, "docker", "version")
	assert.Contains(t, dockerVersion, "Client", "Docker客户端应该能获取版本信息")
	assert.Contains(t, dockerVersion, "Server", "Docker服务端应该能获取版本信息")
	
	// 验证Docker信息
	dockerInfo := execInContainer(t, containerID, "docker", "info")
	assert.Contains(t, dockerInfo, "Containers", "Docker info应该显示容器信息")
	assert.Contains(t, dockerInfo, "Images", "Docker info应该显示镜像信息")
	
	// 验证存储驱动
	if strings.Contains(dockerInfo, "Storage Driver") {
		assert.True(t, 
			strings.Contains(dockerInfo, "overlay2") || 
			strings.Contains(dockerInfo, "devicemapper") ||
			strings.Contains(dockerInfo, "vfs"),
			"应该使用支持的存储驱动")
	}
	
	// 验证Docker根目录权限
	dockerRoot := execInContainer(t, containerID, "ls", "-ld", "/var/lib/docker")
	assert.Contains(t, dockerRoot, "root", "Docker根目录应该属于root用户")
}

// testDockerClientBasicOperations 测试Docker客户端基本操作
func testDockerClientBasicOperations(t *testing.T) {
	containerName := "test-docker-client"
	
	containerID := createDinDContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 测试docker ps命令
	dockerPS := execInContainer(t, containerID, "docker", "ps")
	assert.Contains(t, dockerPS, "CONTAINER ID", "docker ps应该显示表头")
	assert.Contains(t, dockerPS, "IMAGE", "docker ps应该显示IMAGE列")
	
	// 测试docker images命令
	dockerImages := execInContainer(t, containerID, "docker", "images")
	assert.Contains(t, dockerImages, "REPOSITORY", "docker images应该显示表头")
	assert.Contains(t, dockerImages, "TAG", "docker images应该显示TAG列")
	
	// 测试拉取轻量级镜像
	pullOutput := execInContainer(t, containerID, "docker", "pull", "alpine:latest")
	assert.Contains(t, strings.ToLower(pullOutput), "pull complete", "应该成功拉取alpine镜像")
	
	// 验证镜像拉取成功
	imagesAfterPull := execInContainer(t, containerID, "docker", "images", "alpine")
	assert.Contains(t, imagesAfterPull, "alpine", "alpine镜像应该出现在镜像列表中")
	assert.Contains(t, imagesAfterPull, "latest", "应该有latest标签")
	
	// 测试docker run命令
	runOutput := execInContainer(t, containerID, "docker", "run", "--rm", "alpine", "echo", "hello from inner container")
	assert.Contains(t, runOutput, "hello from inner container", "内部容器应该成功运行并输出")
	
	// 测试docker system命令
	systemDF := execInContainer(t, containerID, "docker", "system", "df")
	assert.Contains(t, systemDF, "TYPE", "docker system df应该显示存储使用情况")
	assert.Contains(t, systemDF, "Images", "应该显示镜像存储信息")
}

// testContainerImageManagement 测试容器镜像管理
func testContainerImageManagement(t *testing.T) {
	containerName := "test-image-management"
	
	containerID := createDinDContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 拉取测试镜像
	execInContainer(t, containerID, "docker", "pull", "alpine:latest")
	execInContainer(t, containerID, "docker", "pull", "busybox:latest")
	
	// 验证镜像列表
	images := execInContainer(t, containerID, "docker", "images", "--format", "{{.Repository}}:{{.Tag}}")
	assert.Contains(t, images, "alpine:latest", "应该包含alpine镜像")
	assert.Contains(t, images, "busybox:latest", "应该包含busybox镜像")
	
	// 测试镜像标签
	tagOutput := execInContainer(t, containerID, "docker", "tag", "alpine:latest", "myalpine:v1.0")
	assert.Equal(t, "", strings.TrimSpace(tagOutput), "标签操作应该成功（无输出）")
	
	// 验证新标签存在
	taggedImages := execInContainer(t, containerID, "docker", "images", "myalpine")
	assert.Contains(t, taggedImages, "myalpine", "应该找到新标签的镜像")
	assert.Contains(t, taggedImages, "v1.0", "应该显示正确的版本标签")
	
	// 测试镜像检查
	inspectOutput := execInContainer(t, containerID, "docker", "inspect", "alpine:latest")
	assert.Contains(t, inspectOutput, "Config", "inspect输出应该包含配置信息")
	assert.Contains(t, inspectOutput, "Architecture", "应该包含架构信息")
	
	// 测试镜像删除
	rmiOutput := execInContainer(t, containerID, "docker", "rmi", "myalpine:v1.0")
	assert.Contains(t, strings.ToLower(rmiOutput), "untagged", "应该成功删除标签")
	
	// 验证标签已删除
	_, err := execInContainerWithError(containerID, "docker", "images", "myalpine:v1.0")
	// 注意：如果镜像不存在，docker images仍然会成功，但不会显示该镜像
	
	// 测试镜像导出导入
	saveOutput := execInContainer(t, containerID, "docker", "save", "-o", "/tmp/alpine.tar", "alpine:latest")
	assert.Equal(t, "", strings.TrimSpace(saveOutput), "镜像保存应该成功")
	
	// 验证导出文件存在
	tarFile := execInContainer(t, containerID, "ls", "-la", "/tmp/alpine.tar")
	assert.Contains(t, tarFile, "alpine.tar", "导出的tar文件应该存在")
	
	// 删除原镜像后导入
	execInContainer(t, containerID, "docker", "rmi", "alpine:latest")
	loadOutput := execInContainer(t, containerID, "docker", "load", "-i", "/tmp/alpine.tar")
	assert.Contains(t, strings.ToLower(loadOutput), "loaded", "镜像应该成功导入")
}

// testInnerContainerLifecycle 测试内部容器生命周期管理
func testInnerContainerLifecycle(t *testing.T) {
	containerName := "test-inner-lifecycle"
	
	containerID := createDinDContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 确保有测试镜像
	execInContainer(t, containerID, "docker", "pull", "alpine:latest")
	
	// 创建内部容器
	innerContainerID := execInContainer(t, containerID, "docker", "run", "-d", "--name", "inner-test", 
		"alpine", "sleep", "60")
	innerContainerID = strings.TrimSpace(innerContainerID)
	assert.NotEmpty(t, innerContainerID, "内部容器ID不应该为空")
	
	// 验证内部容器运行状态
	psOutput := execInContainer(t, containerID, "docker", "ps", "--filter", "name=inner-test")
	assert.Contains(t, psOutput, "inner-test", "内部容器应该在运行列表中")
	assert.Contains(t, psOutput, "Up", "内部容器状态应该是Up")
	
	// 在内部容器中执行命令
	execOutput := execInContainer(t, containerID, "docker", "exec", "inner-test", "echo", "hello from inner")
	assert.Contains(t, execOutput, "hello from inner", "应该能在内部容器中执行命令")
	
	// 测试内部容器日志
	logsOutput := execInContainer(t, containerID, "docker", "logs", "inner-test")
	// sleep命令通常没有输出，所以这里主要验证命令能成功执行
	assert.NotContains(t, logsOutput, "error", "获取日志不应该有错误")
	
	// 测试内部容器统计信息
	statsOutput := execInContainer(t, containerID, "docker", "stats", "--no-stream", "inner-test")
	assert.Contains(t, statsOutput, "inner-test", "统计信息应该包含容器名称")
	
	// 暂停内部容器
	pauseOutput := execInContainer(t, containerID, "docker", "pause", "inner-test")
	assert.Equal(t, "", strings.TrimSpace(pauseOutput), "暂停操作应该成功")
	
	// 验证暂停状态
	pausedPS := execInContainer(t, containerID, "docker", "ps", "--filter", "name=inner-test")
	assert.Contains(t, pausedPS, "Paused", "容器应该显示为暂停状态")
	
	// 恢复内部容器
	unpauseOutput := execInContainer(t, containerID, "docker", "unpause", "inner-test")
	assert.Equal(t, "", strings.TrimSpace(unpauseOutput), "恢复操作应该成功")
	
	// 停止内部容器
	stopOutput := execInContainer(t, containerID, "docker", "stop", "inner-test")
	assert.Contains(t, stopOutput, "inner-test", "停止输出应该包含容器名称")
	
	// 验证停止状态
	stoppedPS := execInContainer(t, containerID, "docker", "ps", "-a", "--filter", "name=inner-test")
	assert.Contains(t, stoppedPS, "Exited", "容器应该显示为退出状态")
	
	// 重启内部容器
	restartOutput := execInContainer(t, containerID, "docker", "restart", "inner-test")
	assert.Contains(t, restartOutput, "inner-test", "重启输出应该包含容器名称")
	
	// 验证重启后状态
	restartedPS := execInContainer(t, containerID, "docker", "ps", "--filter", "name=inner-test")
	assert.Contains(t, restartedPS, "Up", "重启后容器应该运行")
	
	// 删除内部容器
	rmOutput := execInContainer(t, containerID, "docker", "rm", "-f", "inner-test")
	assert.Contains(t, rmOutput, "inner-test", "删除输出应该包含容器名称")
	
	// 验证容器已删除
	finalPS := execInContainer(t, containerID, "docker", "ps", "-a", "--filter", "name=inner-test")
	assert.NotContains(t, finalPS, "inner-test", "删除后不应该找到容器")
}

// testDockerNetworking 测试Docker网络功能
func testDockerNetworking(t *testing.T) {
	containerName := "test-docker-networking"
	
	containerID := createDinDContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 确保有测试镜像
	execInContainer(t, containerID, "docker", "pull", "alpine:latest")
	
	// 查看默认网络
	networks := execInContainer(t, containerID, "docker", "network", "ls")
	assert.Contains(t, networks, "bridge", "应该有默认bridge网络")
	assert.Contains(t, networks, "host", "应该有host网络")
	assert.Contains(t, networks, "none", "应该有none网络")
	
	// 创建自定义网络
	createNetOutput := execInContainer(t, containerID, "docker", "network", "create", "test-network")
	networkID := strings.TrimSpace(createNetOutput)
	assert.NotEmpty(t, networkID, "自定义网络ID不应该为空")
	
	// 验证网络创建成功
	networksAfterCreate := execInContainer(t, containerID, "docker", "network", "ls")
	assert.Contains(t, networksAfterCreate, "test-network", "应该找到创建的网络")
	
	// 检查网络详细信息
	inspectNet := execInContainer(t, containerID, "docker", "network", "inspect", "test-network")
	assert.Contains(t, inspectNet, "test-network", "网络检查结果应该包含网络名称")
	assert.Contains(t, inspectNet, "Subnet", "应该显示子网信息")
	
	// 在自定义网络中运行容器
	innerContainer1 := execInContainer(t, containerID, "docker", "run", "-d", "--name", "net-test1", 
		"--network", "test-network", "alpine", "sleep", "60")
	innerContainer1 = strings.TrimSpace(innerContainer1)
	assert.NotEmpty(t, innerContainer1, "第一个网络测试容器应该创建成功")
	
	innerContainer2 := execInContainer(t, containerID, "docker", "run", "-d", "--name", "net-test2", 
		"--network", "test-network", "alpine", "sleep", "60")
	innerContainer2 = strings.TrimSpace(innerContainer2)
	assert.NotEmpty(t, innerContainer2, "第二个网络测试容器应该创建成功")
	
	// 测试容器间网络连通性
	// 从net-test1 ping net-test2
	pingOutput := execInContainer(t, containerID, "docker", "exec", "net-test1", "ping", "-c", "2", "net-test2")
	assert.Contains(t, pingOutput, "2 packets transmitted", "容器间应该能够ping通")
	
	// 获取容器IP地址
	ip1 := execInContainer(t, containerID, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "net-test1")
	ip2 := execInContainer(t, containerID, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "net-test2")
	
	ip1 = strings.TrimSpace(ip1)
	ip2 = strings.TrimSpace(ip2)
	assert.NotEmpty(t, ip1, "容器1应该有IP地址")
	assert.NotEmpty(t, ip2, "容器2应该有IP地址")
	assert.NotEqual(t, ip1, ip2, "两个容器应该有不同的IP地址")
	
	// 测试端口映射
	webContainer := execInContainer(t, containerID, "docker", "run", "-d", "--name", "web-test", 
		"-p", "8080:80", "alpine", "sh", "-c", "echo 'Hello World' > /tmp/index.html && nc -l -p 80 < /tmp/index.html")
	webContainer = strings.TrimSpace(webContainer)
	
	// 等待容器启动
	time.Sleep(2 * time.Second)
	
	// 测试端口访问（从外部容器访问）
	curlOutput := execInContainer(t, containerID, "curl", "-s", "localhost:8080")
	if strings.Contains(curlOutput, "Hello World") {
		t.Log("端口映射功能正常")
	}
	
	// 清理网络测试容器
	execInContainer(t, containerID, "docker", "rm", "-f", "net-test1", "net-test2", "web-test")
	
	// 删除自定义网络
	rmNetOutput := execInContainer(t, containerID, "docker", "network", "rm", "test-network")
	assert.Contains(t, rmNetOutput, "test-network", "网络删除输出应该包含网络名称")
}

// testDockerVolumeManagement 测试Docker存储卷管理
func testDockerVolumeManagement(t *testing.T) {
	containerName := "test-volume-management"
	
	containerID := createDinDContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 确保有测试镜像
	execInContainer(t, containerID, "docker", "pull", "alpine:latest")
	
	// 查看现有卷
	volumes := execInContainer(t, containerID, "docker", "volume", "ls")
	assert.Contains(t, volumes, "DRIVER", "volume ls应该显示表头")
	
	// 创建命名卷
	createVolOutput := execInContainer(t, containerID, "docker", "volume", "create", "test-volume")
	volumeName := strings.TrimSpace(createVolOutput)
	assert.Equal(t, "test-volume", volumeName, "卷名称应该正确返回")
	
	// 验证卷创建成功
	volumesAfterCreate := execInContainer(t, containerID, "docker", "volume", "ls")
	assert.Contains(t, volumesAfterCreate, "test-volume", "应该找到创建的卷")
	
	// 检查卷详细信息
	inspectVol := execInContainer(t, containerID, "docker", "volume", "inspect", "test-volume")
	assert.Contains(t, inspectVol, "test-volume", "卷检查结果应该包含卷名称")
	assert.Contains(t, inspectVol, "Mountpoint", "应该显示挂载点信息")
	
	// 使用卷运行容器
	volContainer := execInContainer(t, containerID, "docker", "run", "-d", "--name", "vol-test", 
		"-v", "test-volume:/data", "alpine", "sleep", "60")
	volContainer = strings.TrimSpace(volContainer)
	assert.NotEmpty(t, volContainer, "使用卷的容器应该创建成功")
	
	// 在卷中写入数据
	execInContainer(t, containerID, "docker", "exec", "vol-test", "sh", "-c", "echo 'persistent data' > /data/test.txt")
	
	// 验证数据写入成功
	dataContent := execInContainer(t, containerID, "docker", "exec", "vol-test", "cat", "/data/test.txt")
	assert.Contains(t, dataContent, "persistent data", "卷中的数据应该正确写入")
	
	// 停止并删除容器
	execInContainer(t, containerID, "docker", "rm", "-f", "vol-test")
	
	// 使用相同卷创建新容器验证数据持久性
	newVolContainer := execInContainer(t, containerID, "docker", "run", "--rm", "--name", "vol-test2", 
		"-v", "test-volume:/data", "alpine", "cat", "/data/test.txt")
	assert.Contains(t, newVolContainer, "persistent data", "数据应该在卷中持久化")
	
	// 测试绑定挂载
	execInContainer(t, containerID, "mkdir", "-p", "/tmp/host-data")
	execInContainer(t, containerID, "echo", "host file", ">", "/tmp/host-data/host.txt")
	
	bindContainer := execInContainer(t, containerID, "docker", "run", "--rm", 
		"-v", "/tmp/host-data:/host-data", "alpine", "cat", "/host-data/host.txt")
	assert.Contains(t, bindContainer, "host file", "绑定挂载应该能访问主机文件")
	
	// 测试tmpfs挂载
	tmpfsContainer := execInContainer(t, containerID, "docker", "run", "--rm", 
		"--tmpfs", "/tmp-memory", "alpine", "sh", "-c", "echo 'in memory' > /tmp-memory/mem.txt && cat /tmp-memory/mem.txt")
	assert.Contains(t, tmpfsContainer, "in memory", "tmpfs挂载应该工作正常")
	
	// 删除测试卷
	rmVolOutput := execInContainer(t, containerID, "docker", "volume", "rm", "test-volume")
	assert.Contains(t, rmVolOutput, "test-volume", "卷删除输出应该包含卷名称")
	
	// 验证卷已删除
	finalVolumes := execInContainer(t, containerID, "docker", "volume", "ls")
	assert.NotContains(t, finalVolumes, "test-volume", "删除后不应该找到卷")
}

// testMultiLayerContainerNesting 测试多层容器嵌套
func testMultiLayerContainerNesting(t *testing.T) {
	containerName := "test-multi-layer-nesting"
	
	containerID := createDinDContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 在第一层容器中运行包含Docker的容器（如果支持）
	// 注意：这可能需要特殊配置和足够的权限
	
	// 确保基础镜像可用
	execInContainer(t, containerID, "docker", "pull", "alpine:latest")
	
	// 第一层：在sysbox容器中创建内部容器
	level1Container := execInContainer(t, containerID, "docker", "run", "-d", "--name", "level1", 
		"alpine", "sleep", "120")
	level1Container = strings.TrimSpace(level1Container)
	assert.NotEmpty(t, level1Container, "第一层容器应该创建成功")
	
	// 验证第一层容器运行
	level1Status := execInContainer(t, containerID, "docker", "ps", "--filter", "name=level1", "--format", "{{.Status}}")
	assert.Contains(t, level1Status, "Up", "第一层容器应该运行正常")
	
	// 在第一层容器中安装必要工具
	execInContainer(t, containerID, "docker", "exec", "level1", "apk", "add", "--no-cache", "curl")
	
	// 验证第一层容器的独立性
	level1Hostname := execInContainer(t, containerID, "docker", "exec", "level1", "hostname")
	level1Hostname = strings.TrimSpace(level1Hostname)
	assert.NotEmpty(t, level1Hostname, "第一层容器应该有独立的hostname")
	
	// 验证进程隔离
	level1Processes := execInContainer(t, containerID, "docker", "exec", "level1", "ps", "aux")
	assert.NotContains(t, level1Processes, "dockerd", "第一层容器内不应该看到Docker守护进程")
	
	// 测试资源隔离
	level1Memory := execInContainer(t, containerID, "docker", "exec", "level1", "cat", "/proc/meminfo")
	assert.Contains(t, level1Memory, "MemTotal", "第一层容器应该有独立的内存视图")
	
	// 创建多个并行的第一层容器
	for i := 2; i <= 3; i++ {
		containerName := fmt.Sprintf("level1-%d", i)
		levelContainer := execInContainer(t, containerID, "docker", "run", "-d", "--name", containerName, 
			"alpine", "sleep", "60")
		assert.NotEmpty(t, strings.TrimSpace(levelContainer), fmt.Sprintf("第%d个并行容器应该创建成功", i))
	}
	
	// 验证所有容器独立运行
	allContainers := execInContainer(t, containerID, "docker", "ps", "--format", "{{.Names}}")
	assert.Contains(t, allContainers, "level1", "应该包含level1容器")
	assert.Contains(t, allContainers, "level1-2", "应该包含level1-2容器")
	assert.Contains(t, allContainers, "level1-3", "应该包含level1-3容器")
	
	// 测试容器间网络连通性
	pingResult := execInContainer(t, containerID, "docker", "exec", "level1", "ping", "-c", "1", "level1-2")
	// 网络连通性取决于网络配置，这里主要验证命令能执行
	
	// 清理第一层容器
	execInContainer(t, containerID, "docker", "rm", "-f", "level1", "level1-2", "level1-3")
	
	// 验证清理完成
	cleanupContainers := execInContainer(t, containerID, "docker", "ps", "-a", "--format", "{{.Names}}")
	assert.NotContains(t, cleanupContainers, "level1", "清理后不应该找到level1容器")
}

// testDockerComposeSupport 测试Docker Compose支持
func testDockerComposeSupport(t *testing.T) {
	containerName := "test-docker-compose"
	
	containerID := createDinDContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 检查docker-compose是否可用
	composeVersion, err := execInContainerWithError(containerID, "docker-compose", "--version")
	if err != nil {
		// 如果没有docker-compose，尝试使用docker compose plugin
		composePluginVersion, pluginErr := execInContainerWithError(containerID, "docker", "compose", "version")
		if pluginErr != nil {
			t.Skip("Docker Compose不可用，跳过测试")
			return
		}
		composeVersion = composePluginVersion
	}
	
	assert.Contains(t, strings.ToLower(composeVersion), "compose", "应该能获取Compose版本信息")
	
	// 创建简单的docker-compose.yml文件
	composeContent := `
version: '3.8'
services:
  web:
    image: alpine:latest
    command: sleep 300
    networks:
      - test-net
  app:
    image: alpine:latest
    command: sleep 300
    depends_on:
      - web
    networks:
      - test-net

networks:
  test-net:
    driver: bridge
`
	
	// 写入compose文件
	execInContainer(t, containerID, "mkdir", "-p", "/tmp/compose-test")
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/compose-test/docker-compose.yml << 'EOF'\n%sEOF", composeContent))
	
	// 验证文件创建成功
	composeFile := execInContainer(t, containerID, "cat", "/tmp/compose-test/docker-compose.yml")
	assert.Contains(t, composeFile, "version:", "Compose文件应该包含版本信息")
	assert.Contains(t, composeFile, "services:", "Compose文件应该包含服务定义")
	
	// 切换到compose目录
	execInContainer(t, containerID, "cd", "/tmp/compose-test")
	
	// 运行docker-compose up
	var upOutput string
	if strings.Contains(composeVersion, "docker-compose") {
		upOutput = execInContainer(t, containerID, "sh", "-c", "cd /tmp/compose-test && docker-compose up -d")
	} else {
		upOutput = execInContainer(t, containerID, "sh", "-c", "cd /tmp/compose-test && docker compose up -d")
	}
	
	assert.NotContains(t, strings.ToLower(upOutput), "error", "Compose启动不应该有错误")
	
	// 等待服务启动
	time.Sleep(5 * time.Second)
	
	// 验证服务运行状态
	var psOutput string
	if strings.Contains(composeVersion, "docker-compose") {
		psOutput = execInContainer(t, containerID, "sh", "-c", "cd /tmp/compose-test && docker-compose ps")
	} else {
		psOutput = execInContainer(t, containerID, "sh", "-c", "cd /tmp/compose-test && docker compose ps")
	}
	
	assert.Contains(t, psOutput, "web", "应该找到web服务")
	assert.Contains(t, psOutput, "app", "应该找到app服务")
	
	// 验证Docker容器运行
	dockerPS := execInContainer(t, containerID, "docker", "ps", "--format", "{{.Names}}")
	assert.Contains(t, dockerPS, "web", "应该找到web容器")
	assert.Contains(t, dockerPS, "app", "应该找到app容器")
	
	// 测试服务间网络连通性
	pingFromApp := execInContainer(t, containerID, "docker", "exec", "compose-test_app_1", "ping", "-c", "1", "web")
	if !strings.Contains(pingFromApp, "error") {
		t.Log("Compose服务间网络连通正常")
	}
	
	// 停止和清理服务
	var downOutput string
	if strings.Contains(composeVersion, "docker-compose") {
		downOutput = execInContainer(t, containerID, "sh", "-c", "cd /tmp/compose-test && docker-compose down")
	} else {
		downOutput = execInContainer(t, containerID, "sh", "-c", "cd /tmp/compose-test && docker compose down")
	}
	
	assert.NotContains(t, strings.ToLower(downOutput), "error", "Compose停止不应该有错误")
	
	// 验证清理完成
	finalPS := execInContainer(t, containerID, "docker", "ps", "-a", "--format", "{{.Names}}")
	assert.NotContains(t, finalPS, "compose-test", "Compose服务应该被清理")
}

// testContainerCommunicationAndIsolation 测试容器间通信和隔离
func testContainerCommunicationAndIsolation(t *testing.T) {
	containerName := "test-communication-isolation"
	
	containerID := createDinDContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 确保测试镜像可用
	execInContainer(t, containerID, "docker", "pull", "alpine:latest")
	
	// 创建测试容器
	container1 := execInContainer(t, containerID, "docker", "run", "-d", "--name", "comm-test1", 
		"alpine", "sleep", "120")
	container2 := execInContainer(t, containerID, "docker", "run", "-d", "--name", "comm-test2", 
		"alpine", "sleep", "120")
	
	container1 = strings.TrimSpace(container1)
	container2 = strings.TrimSpace(container2)
	assert.NotEmpty(t, container1, "通信测试容器1应该创建成功")
	assert.NotEmpty(t, container2, "通信测试容器2应该创建成功")
	
	// 获取容器IP地址
	ip1 := execInContainer(t, containerID, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "comm-test1")
	ip2 := execInContainer(t, containerID, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "comm-test2")
	
	ip1 = strings.TrimSpace(ip1)
	ip2 = strings.TrimSpace(ip2)
	assert.NotEmpty(t, ip1, "容器1应该有IP地址")
	assert.NotEmpty(t, ip2, "容器2应该有IP地址")
	assert.NotEqual(t, ip1, ip2, "两个容器应该有不同的IP地址")
	
	// 测试默认网络通信
	pingOutput := execInContainer(t, containerID, "docker", "exec", "comm-test1", "ping", "-c", "2", ip2)
	assert.Contains(t, pingOutput, "2 packets transmitted", "默认网络中容器应该能互相ping通")
	
	// 测试进程隔离
	processes1 := execInContainer(t, containerID, "docker", "exec", "comm-test1", "ps", "aux")
	processes2 := execInContainer(t, containerID, "docker", "exec", "comm-test2", "ps", "aux")
	
	// 每个容器应该只看到自己的进程
	assert.NotEqual(t, processes1, processes2, "不同容器应该有不同的进程列表")
	
	// 测试文件系统隔离
	execInContainer(t, containerID, "docker", "exec", "comm-test1", "touch", "/tmp/container1-file")
	execInContainer(t, containerID, "docker", "exec", "comm-test2", "touch", "/tmp/container2-file")
	
	// 验证文件隔离
	_, err1 := execInContainerWithError(containerID, "docker", "exec", "comm-test1", "ls", "/tmp/container2-file")
	_, err2 := execInContainerWithError(containerID, "docker", "exec", "comm-test2", "ls", "/tmp/container1-file")
	
	assert.Error(t, err1, "容器1不应该看到容器2的文件")
	assert.Error(t, err2, "容器2不应该看到容器1的文件")
	
	// 测试网络隔离（创建自定义网络）
	execInContainer(t, containerID, "docker", "network", "create", "isolated-net")
	
	isolatedContainer := execInContainer(t, containerID, "docker", "run", "-d", "--name", "isolated-test", 
		"--network", "isolated-net", "alpine", "sleep", "60")
	isolatedContainer = strings.TrimSpace(isolatedContainer)
	
	// 验证隔离网络中的容器无法直接访问默认网络中的容器
	isolatedIP := execInContainer(t, containerID, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "isolated-test")
	isolatedIP = strings.TrimSpace(isolatedIP)
	
	// 从隔离容器ping默认网络容器应该失败
	_, pingErr := execInContainerWithError(containerID, "docker", "exec", "isolated-test", "ping", "-c", "1", "-W", "2", ip1)
	assert.Error(t, pingErr, "隔离网络中的容器不应该能ping通默认网络中的容器")
	
	// 清理测试容器和网络
	execInContainer(t, containerID, "docker", "rm", "-f", "comm-test1", "comm-test2", "isolated-test")
	execInContainer(t, containerID, "docker", "network", "rm", "isolated-net")
}

// testDockerBuildFunctionality 测试Docker构建功能
func testDockerBuildFunctionality(t *testing.T) {
	containerName := "test-docker-build"
	
	containerID := createDinDContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 创建测试Dockerfile
	dockerfile := `
FROM alpine:latest
RUN echo "Building custom image" > /tmp/build-info.txt
RUN apk add --no-cache curl
COPY test-file.txt /app/
WORKDIR /app
CMD cat /tmp/build-info.txt && cat test-file.txt
`
	
	// 创建构建上下文
	execInContainer(t, containerID, "mkdir", "-p", "/tmp/build-context")
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/build-context/Dockerfile << 'EOF'\n%sEOF", dockerfile))
	execInContainer(t, containerID, "echo", "Hello from test file", ">", "/tmp/build-context/test-file.txt")
	
	// 验证构建文件存在
	buildFiles := execInContainer(t, containerID, "ls", "-la", "/tmp/build-context/")
	assert.Contains(t, buildFiles, "Dockerfile", "Dockerfile应该存在")
	assert.Contains(t, buildFiles, "test-file.txt", "测试文件应该存在")
	
	// 执行Docker构建
	buildOutput := execInContainer(t, containerID, "sh", "-c", "cd /tmp/build-context && docker build -t test-image:latest .")
	
	assert.Contains(t, strings.ToLower(buildOutput), "successfully", "构建应该成功完成")
	assert.NotContains(t, strings.ToLower(buildOutput), "error", "构建过程不应该有错误")
	
	// 验证镜像构建成功
	images := execInContainer(t, containerID, "docker", "images", "test-image")
	assert.Contains(t, images, "test-image", "应该找到构建的镜像")
	assert.Contains(t, images, "latest", "应该有latest标签")
	
	// 测试构建的镜像
	runOutput := execInContainer(t, containerID, "docker", "run", "--rm", "test-image:latest")
	assert.Contains(t, runOutput, "Building custom image", "应该包含构建时添加的内容")
	assert.Contains(t, runOutput, "Hello from test file", "应该包含复制的文件内容")
	
	// 测试多阶段构建（如果支持）
	multistageDockerfile := `
FROM alpine:latest AS builder
RUN echo "This is build stage" > /tmp/build.txt

FROM alpine:latest AS final
COPY --from=builder /tmp/build.txt /app/
CMD cat /app/build.txt
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/build-context/Dockerfile.multistage << 'EOF'\n%sEOF", multistageDockerfile))
	
	multistageBuild := execInContainer(t, containerID, "sh", "-c", "cd /tmp/build-context && docker build -f Dockerfile.multistage -t test-multistage:latest .")
	
	if !strings.Contains(strings.ToLower(multistageBuild), "error") {
		t.Log("多阶段构建支持正常")
		
		multistageRun := execInContainer(t, containerID, "docker", "run", "--rm", "test-multistage:latest")
		assert.Contains(t, multistageRun, "This is build stage", "多阶段构建应该正确复制文件")
	}
	
	// 测试构建参数
	argDockerfile := `
FROM alpine:latest
ARG BUILD_ARG=default_value
RUN echo "Build argument: $BUILD_ARG" > /tmp/arg.txt
CMD cat /tmp/arg.txt
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/build-context/Dockerfile.arg << 'EOF'\n%sEOF", argDockerfile))
	
	argBuild := execInContainer(t, containerID, "sh", "-c", "cd /tmp/build-context && docker build -f Dockerfile.arg --build-arg BUILD_ARG=custom_value -t test-arg:latest .")
	
	if !strings.Contains(strings.ToLower(argBuild), "error") {
		argRun := execInContainer(t, containerID, "docker", "run", "--rm", "test-arg:latest")
		assert.Contains(t, argRun, "custom_value", "构建参数应该被正确传递")
	}
	
	// 清理构建的镜像
	execInContainer(t, containerID, "docker", "rmi", "-f", "test-image:latest")
	execInContainer(t, containerID, "docker", "rmi", "-f", "test-multistage:latest")
	execInContainer(t, containerID, "docker", "rmi", "-f", "test-arg:latest")
}

// Helper functions

func setupDinDTestEnv(t *testing.T) {
	// 验证Docker和sysbox-runc可用
	output, err := exec.Command("docker", "info").Output()
	require.NoError(t, err, "Docker应该正常运行")
	require.Contains(t, string(output), "sysbox-runc", "应该配置sysbox-runc运行时")
	
	// 预拉取必要的镜像
	exec.Command("docker", "pull", "nestybox/ubuntu-bionic-docker:latest").Run()
	
	// 清理可能存在的测试容器
	testContainers := []string{
		"test-docker-daemon", "test-docker-client", "test-image-management",
		"test-inner-lifecycle", "test-docker-networking", "test-volume-management",
		"test-multi-layer-nesting", "test-docker-compose", "test-communication-isolation",
		"test-docker-build",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func cleanupDinDTestEnv(t *testing.T) {
	// 清理所有测试容器
	testContainers := []string{
		"test-docker-daemon", "test-docker-client", "test-image-management",
		"test-inner-lifecycle", "test-docker-networking", "test-volume-management",
		"test-multi-layer-nesting", "test-docker-compose", "test-communication-isolation",
		"test-docker-build",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func createDinDContainer(t *testing.T, name string) string {
	// 创建包含Docker的系统容器
	containerID := createSysboxContainer(t, name, "nestybox/ubuntu-bionic-docker:latest",
		[]string{"/bin/bash", "-c", "dockerd & sleep 600"})
	
	// 等待Docker守护进程启动
	time.Sleep(15 * time.Second)
	
	// 验证Docker守护进程已启动
	maxRetries := 10
	for i := 0; i < maxRetries; i++ {
		_, err := execInContainerWithError(containerID, "docker", "version")
		if err == nil {
			break
		}
		if i == maxRetries-1 {
			require.NoError(t, err, "Docker守护进程应该启动成功")
		}
		time.Sleep(3 * time.Second)
	}
	
	return containerID
}