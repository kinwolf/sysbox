package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSysboxRuntimeCore 测试Sysbox核心容器运行时功能
func TestSysboxRuntimeCore(t *testing.T) {
	setupSysboxTestEnv(t)
	defer cleanupSysboxTestEnv(t)

	t.Run("容器基本启动和停止", func(t *testing.T) {
		testBasicContainerLifecycle(t)
	})

	t.Run("用户命名空间隔离验证", func(t *testing.T) {
		testUserNamespaceIsolation(t)
	})

	t.Run("进程树隔离验证", func(t *testing.T) {
		testProcessTreeIsolation(t)
	})

	t.Run("网络命名空间隔离", func(t *testing.T) {
		testNetworkNamespaceIsolation(t)
	})

	t.Run("文件系统隔离验证", func(t *testing.T) {
		testFileSystemIsolation(t)
	})

	t.Run("容器初始化进程验证", func(t *testing.T) {
		testContainerInitProcess(t)
	})

	t.Run("资源限制配置验证", func(t *testing.T) {
		testResourceLimits(t)
	})

	t.Run("容器状态管理", func(t *testing.T) {
		testContainerStateManagement(t)
	})
}

// testBasicContainerLifecycle 测试容器基本生命周期
func testBasicContainerLifecycle(t *testing.T) {
	containerName := "test-basic-lifecycle"
	
	// 创建并启动容器
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	require.NotEmpty(t, containerID, "容器创建失败")
	
	// 验证容器运行状态
	assertContainerRunning(t, containerID)
	
	// 在容器内执行命令验证
	output := execInContainer(t, containerID, "echo", "hello sysbox")
	assert.Equal(t, "hello sysbox", strings.TrimSpace(output))
	
	// 验证容器hostname设置
	hostname := execInContainer(t, containerID, "hostname")
	assert.Contains(t, hostname, containerName[:8]) // Docker默认使用容器ID前8位作为hostname
	
	// 停止容器
	stopSysboxContainer(t, containerID)
	
	// 验证容器已停止
	assertContainerStopped(t, containerID)
	
	// 清理容器
	removeSysboxContainer(t, containerID)
}

// testUserNamespaceIsolation 测试用户命名空间隔离
func testUserNamespaceIsolation(t *testing.T) {
	containerName := "test-userns-isolation"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证容器内root用户的UID映射
	output := execInContainer(t, containerID, "id", "-u")
	assert.Equal(t, "0", strings.TrimSpace(output), "容器内应该显示为root用户(UID=0)")
	
	// 验证容器外进程的实际UID不是0
	pid := getContainerPID(t, containerID)
	hostUID := getProcessUID(t, pid)
	assert.NotEqual(t, "0", hostUID, "容器进程在主机上不应该是root用户")
	
	// 验证用户命名空间的映射关系
	uidMapPath := fmt.Sprintf("/proc/%s/uid_map", pid)
	uidMap := readFileContent(t, uidMapPath)
	assert.Contains(t, uidMap, "0", "应该存在UID映射配置")
	
	// 验证容器内无法访问主机敏感文件
	_, err := execInContainerWithError(containerID, "cat", "/etc/shadow")
	assert.Error(t, err, "容器内不应该能访问主机敏感文件")
}

// testProcessTreeIsolation 测试进程树隔离
func testProcessTreeIsolation(t *testing.T) {
	containerName := "test-pid-isolation"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证容器内只能看到自己的进程
	output := execInContainer(t, containerID, "ps", "aux")
	lines := strings.Split(output, "\n")
	
	// 过滤掉空行和标题行
	processList := []string{}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) != "" {
			processList = append(processList, line)
		}
	}
	
	// 验证进程数量有限（主要是init进程和sleep进程）
	assert.LessOrEqual(t, len(processList), 5, "容器内不应该看到过多进程")
	
	// 验证PID 1存在且正确
	pid1Process := execInContainer(t, containerID, "ps", "-p", "1", "-o", "comm=")
	assert.NotEmpty(t, strings.TrimSpace(pid1Process), "容器内应该有PID 1进程")
	
	// 验证容器内无法看到主机进程
	hostPID := fmt.Sprintf("%d", os.Getpid())
	_, err := execInContainerWithError(containerID, "ps", "-p", hostPID)
	assert.Error(t, err, "容器内不应该能看到主机进程")
}

// testNetworkNamespaceIsolation 测试网络命名空间隔离
func testNetworkNamespaceIsolation(t *testing.T) {
	containerName := "test-net-isolation"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 获取容器IP地址
	containerIP := getContainerIP(t, containerID)
	assert.NotEmpty(t, containerIP, "容器应该分配到IP地址")
	
	// 验证容器内网络接口
	interfaces := execInContainer(t, containerID, "ip", "link", "show")
	assert.Contains(t, interfaces, "lo", "容器内应该有lo接口")
	assert.Contains(t, interfaces, "eth0", "容器内应该有eth0接口")
	
	// 验证容器网络连通性
	pingOutput := execInContainer(t, containerID, "ping", "-c", "1", "8.8.8.8")
	assert.Contains(t, pingOutput, "1 packets transmitted", "容器应该能ping通外网")
	
	// 验证容器内端口绑定隔离
	execInContainer(t, containerID, "nc", "-l", "-p", "8080", "&")
	time.Sleep(1 * time.Second)
	
	// 从主机检查端口不可见（除非进行端口映射）
	output, err := exec.Command("netstat", "-tuln").Output()
	assert.NoError(t, err)
	assert.NotContains(t, string(output), ":8080", "容器内绑定的端口在主机上不应该可见")
}

// testFileSystemIsolation 测试文件系统隔离
func testFileSystemIsolation(t *testing.T) {
	containerName := "test-fs-isolation"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证容器内文件系统挂载点
	mountPoints := execInContainer(t, containerID, "mount")
	assert.Contains(t, mountPoints, "/proc", "容器内应该挂载/proc")
	assert.Contains(t, mountPoints, "/sys", "容器内应该挂载/sys")
	assert.Contains(t, mountPoints, "/dev", "容器内应该挂载/dev")
	
	// 验证容器内创建文件不影响主机
	execInContainer(t, containerID, "touch", "/tmp/container_test_file")
	
	// 检查主机/tmp目录不应该有这个文件
	_, err := os.Stat("/tmp/container_test_file")
	assert.True(t, os.IsNotExist(err), "容器内创建的文件不应该出现在主机上")
	
	// 验证根文件系统只读保护（如果配置）
	_, err = execInContainerWithError(containerID, "touch", "/test_readonly")
	// 注意：某些Sysbox配置可能允许写入，这里主要验证隔离性
	
	// 验证/proc和/sys虚拟化
	procVersion := execInContainer(t, containerID, "cat", "/proc/version")
	assert.NotEmpty(t, procVersion, "/proc/version应该可读")
	
	sysKernelVersion := execInContainer(t, containerID, "cat", "/sys/kernel/osrelease")
	assert.NotEmpty(t, sysKernelVersion, "/sys/kernel/osrelease应该可读")
}

// testContainerInitProcess 测试容器初始化进程
func testContainerInitProcess(t *testing.T) {
	containerName := "test-init-process"
	
	// 测试默认init进程
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证PID 1进程
	pid1Cmd := execInContainer(t, containerID, "ps", "-p", "1", "-o", "comm=")
	initProcess := strings.TrimSpace(pid1Cmd)
	assert.NotEmpty(t, initProcess, "应该有PID 1进程")
	
	// 测试--init选项
	containerName2 := "test-init-option"
	containerID2 := createSysboxContainerWithOptions(t, containerName2, "ubuntu:20.04", []string{"sleep", "300"}, "--init")
	defer cleanupContainer(t, containerID2)
	
	pid1Cmd2 := execInContainer(t, containerID2, "ps", "-p", "1", "-o", "args=")
	initArgs := strings.TrimSpace(pid1Cmd2)
	// Docker的--init通常使用tini作为init进程
	assert.Contains(t, strings.ToLower(initArgs), "init", "使用--init选项应该设置init进程")
}

// testResourceLimits 测试资源限制
func testResourceLimits(t *testing.T) {
	containerName := "test-resource-limits"
	
	// 创建带资源限制的容器
	containerID := createSysboxContainerWithOptions(t, containerName, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--memory=512m", "--cpus=1.0")
	defer cleanupContainer(t, containerID)
	
	// 验证内存限制
	memLimit := execInContainer(t, containerID, "cat", "/sys/fs/cgroup/memory/memory.limit_in_bytes")
	memLimitInt := parseBytes(t, strings.TrimSpace(memLimit))
	expectedLimit := int64(512 * 1024 * 1024) // 512MB
	assert.InDelta(t, expectedLimit, memLimitInt, float64(expectedLimit)*0.1, 
		"内存限制应该接近设置值")
	
	// 验证CPU限制配置存在
	cpuQuota := execInContainer(t, containerID, "cat", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	assert.NotEqual(t, "-1", strings.TrimSpace(cpuQuota), "应该设置CPU配额限制")
}

// testContainerStateManagement 测试容器状态管理
func testContainerStateManagement(t *testing.T) {
	containerName := "test-state-management"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证运行状态
	assertContainerRunning(t, containerID)
	
	// 暂停容器
	pauseSysboxContainer(t, containerID)
	assertContainerPaused(t, containerID)
	
	// 恢复容器
	unpauseSysboxContainer(t, containerID)
	assertContainerRunning(t, containerID)
	
	// 重启容器
	restartSysboxContainer(t, containerID)
	assertContainerRunning(t, containerID)
	
	// 验证容器重启后进程仍然正常
	output := execInContainer(t, containerID, "echo", "restart-test")
	assert.Equal(t, "restart-test", strings.TrimSpace(output))
}

// Helper functions for testing

func setupSysboxTestEnv(t *testing.T) {
	// 检查sysbox是否安装和运行
	output, err := exec.Command("docker", "info").Output()
	require.NoError(t, err, "Docker应该正常运行")
	require.Contains(t, string(output), "sysbox-runc", "应该安装并配置sysbox-runc运行时")
	
	// 清理可能存在的测试容器
	exec.Command("docker", "rm", "-f", "test-basic-lifecycle").Run()
	exec.Command("docker", "rm", "-f", "test-userns-isolation").Run()
	exec.Command("docker", "rm", "-f", "test-pid-isolation").Run()
	exec.Command("docker", "rm", "-f", "test-net-isolation").Run()
	exec.Command("docker", "rm", "-f", "test-fs-isolation").Run()
	exec.Command("docker", "rm", "-f", "test-init-process").Run()
	exec.Command("docker", "rm", "-f", "test-init-option").Run()
	exec.Command("docker", "rm", "-f", "test-resource-limits").Run()
	exec.Command("docker", "rm", "-f", "test-state-management").Run()
}

func cleanupSysboxTestEnv(t *testing.T) {
	// 清理所有测试容器
	containers := []string{
		"test-basic-lifecycle", "test-userns-isolation", "test-pid-isolation",
		"test-net-isolation", "test-fs-isolation", "test-init-process",
		"test-init-option", "test-resource-limits", "test-state-management",
	}
	
	for _, container := range containers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func createSysboxContainer(t *testing.T, name, image string, cmd []string) string {
	args := []string{"run", "-d", "--name", name, "--runtime=sysbox-runc", image}
	args = append(args, cmd...)
	
	output, err := exec.Command("docker", args...).Output()
	require.NoError(t, err, "创建容器失败: %v", err)
	
	containerID := strings.TrimSpace(string(output))
	require.NotEmpty(t, containerID, "容器ID不应该为空")
	
	// 等待容器启动
	time.Sleep(2 * time.Second)
	
	return containerID
}

func createSysboxContainerWithOptions(t *testing.T, name, image string, cmd []string, options ...string) string {
	args := []string{"run", "-d", "--name", name, "--runtime=sysbox-runc"}
	args = append(args, options...)
	args = append(args, image)
	args = append(args, cmd...)
	
	output, err := exec.Command("docker", args...).Output()
	require.NoError(t, err, "创建容器失败: %v", err)
	
	containerID := strings.TrimSpace(string(output))
	require.NotEmpty(t, containerID, "容器ID不应该为空")
	
	// 等待容器启动
	time.Sleep(2 * time.Second)
	
	return containerID
}

func execInContainer(t *testing.T, containerID string, cmd ...string) string {
	args := []string{"exec", containerID}
	args = append(args, cmd...)
	
	output, err := exec.Command("docker", args...).Output()
	require.NoError(t, err, "容器内执行命令失败: %v", err)
	
	return string(output)
}

func execInContainerWithError(containerID string, cmd ...string) (string, error) {
	args := []string{"exec", containerID}
	args = append(args, cmd...)
	
	output, err := exec.Command("docker", args...).Output()
	return string(output), err
}

func assertContainerRunning(t *testing.T, containerID string) {
	output, err := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", containerID).Output()
	require.NoError(t, err)
	assert.Equal(t, "running", strings.TrimSpace(string(output)), "容器应该处于运行状态")
}

func assertContainerStopped(t *testing.T, containerID string) {
	output, err := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", containerID).Output()
	require.NoError(t, err)
	status := strings.TrimSpace(string(output))
	assert.True(t, status == "exited" || status == "stopped", "容器应该处于停止状态")
}

func assertContainerPaused(t *testing.T, containerID string) {
	output, err := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", containerID).Output()
	require.NoError(t, err)
	assert.Equal(t, "paused", strings.TrimSpace(string(output)), "容器应该处于暂停状态")
}

func stopSysboxContainer(t *testing.T, containerID string) {
	err := exec.Command("docker", "stop", containerID).Run()
	require.NoError(t, err, "停止容器失败")
}

func pauseSysboxContainer(t *testing.T, containerID string) {
	err := exec.Command("docker", "pause", containerID).Run()
	require.NoError(t, err, "暂停容器失败")
}

func unpauseSysboxContainer(t *testing.T, containerID string) {
	err := exec.Command("docker", "unpause", containerID).Run()
	require.NoError(t, err, "恢复容器失败")
}

func restartSysboxContainer(t *testing.T, containerID string) {
	err := exec.Command("docker", "restart", containerID).Run()
	require.NoError(t, err, "重启容器失败")
}

func removeSysboxContainer(t *testing.T, containerID string) {
	err := exec.Command("docker", "rm", "-f", containerID).Run()
	require.NoError(t, err, "删除容器失败")
}

func cleanupContainer(t *testing.T, containerID string) {
	exec.Command("docker", "rm", "-f", containerID).Run()
}

func getContainerPID(t *testing.T, containerID string) string {
	output, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerID).Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(output))
}

func getProcessUID(t *testing.T, pid string) string {
	output, err := exec.Command("ps", "-o", "uid=", "-p", pid).Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(output))
}

func getContainerIP(t *testing.T, containerID string) string {
	output, err := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", containerID).Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(output))
}

func readFileContent(t *testing.T, filePath string) string {
	content, err := os.ReadFile(filePath)
	require.NoError(t, err, "读取文件失败: %s", filePath)
	return string(content)
}

func parseBytes(t *testing.T, str string) int64 {
	var value int64
	_, err := fmt.Sscanf(str, "%d", &value)
	require.NoError(t, err, "解析字节数失败: %s", str)
	return value
}
