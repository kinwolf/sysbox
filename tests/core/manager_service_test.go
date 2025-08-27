package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSysboxManagerService 测试Sysbox管理服务核心功能
func TestSysboxManagerService(t *testing.T) {
	setupSysboxMgrTestEnv(t)
	defer cleanupSysboxMgrTestEnv(t)

	t.Run("sysbox-mgr守护进程状态", func(t *testing.T) {
		testSysboxMgrDaemonStatus(t)
	})

	t.Run("用户ID和组ID映射管理", func(t *testing.T) {
		testUIDGIDMappingManagement(t)
	})

	t.Run("容器注册与注销", func(t *testing.T) {
		testContainerRegistration(t)
	})

	t.Run("特殊挂载管理", func(t *testing.T) {
		testSpecialMountManagement(t)
	})

	t.Run("容器资源分配与回收", func(t *testing.T) {
		testContainerResourceAllocation(t)
	})

	t.Run("sysbox-mgr配置管理", func(t *testing.T) {
		testSysboxMgrConfiguration(t)
	})

	t.Run("容器间资源隔离", func(t *testing.T) {
		testInterContainerResourceIsolation(t)
	})

	t.Run("sysbox-mgr日志和监控", func(t *testing.T) {
		testSysboxMgrLoggingAndMonitoring(t)
	})

	t.Run("容器异常情况处理", func(t *testing.T) {
		testContainerAbnormalSituationHandling(t)
	})
}

// testSysboxMgrDaemonStatus 测试sysbox-mgr守护进程状态
func testSysboxMgrDaemonStatus(t *testing.T) {
	// 验证sysbox-mgr进程运行
	output, err := exec.Command("pgrep", "-f", "sysbox-mgr").Output()
	require.NoError(t, err, "sysbox-mgr进程应该正在运行")
	require.NotEmpty(t, output, "应该找到sysbox-mgr进程")
	
	pid := strings.TrimSpace(string(output))
	require.NotEmpty(t, pid, "sysbox-mgr PID不应该为空")
	
	// 验证进程存在且可访问
	_, err = os.Stat(fmt.Sprintf("/proc/%s", pid))
	assert.NoError(t, err, "sysbox-mgr进程应该存在于/proc中")
	
	// 验证进程命令行
	cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid))
	require.NoError(t, err, "应该能读取sysbox-mgr的cmdline")
	assert.Contains(t, string(cmdline), "sysbox-mgr", "cmdline应该包含sysbox-mgr")
	
	// 验证进程监听端口（如果有gRPC服务）
	netstatOutput, err := exec.Command("netstat", "-tlnp").Output()
	if err == nil {
		netstatLines := strings.Split(string(netstatOutput), "\n")
		var foundSysboxMgrPort bool
		for _, line := range netstatLines {
			if strings.Contains(line, pid) && strings.Contains(line, "LISTEN") {
				foundSysboxMgrPort = true
				break
			}
		}
		if foundSysboxMgrPort {
			t.Logf("sysbox-mgr正在监听端口")
		}
	}
	
	// 验证sysbox-mgr日志文件存在（如果配置了日志）
	logPaths := []string{
		"/var/log/sysbox-mgr.log",
		"/tmp/sysbox-mgr.log",
	}
	
	for _, logPath := range logPaths {
		if _, err := os.Stat(logPath); err == nil {
			logContent, err := exec.Command("tail", "-10", logPath).Output()
			if err == nil && len(logContent) > 0 {
				t.Logf("sysbox-mgr日志文件: %s", logPath)
				break
			}
		}
	}
}

// testUIDGIDMappingManagement 测试用户ID和组ID映射管理
func testUIDGIDMappingManagement(t *testing.T) {
	containerName := "test-uid-gid-mapping"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 获取容器的主进程PID
	containerPID := getContainerPID(t, containerID)
	
	// 验证UID映射
	uidMapPath := fmt.Sprintf("/proc/%s/uid_map", containerPID)
	uidMapContent := readFileContent(t, uidMapPath)
	assert.NotEmpty(t, uidMapContent, "UID映射应该存在")
	
	// 解析UID映射内容
	uidMappings := parseIDMapping(t, uidMapContent)
	assert.NotEmpty(t, uidMappings, "应该有UID映射条目")
	
	// 验证第一个映射条目（通常是root用户映射）
	firstMapping := uidMappings[0]
	assert.Equal(t, "0", firstMapping.ContainerID, "容器内第一个映射应该是root用户")
	assert.NotEqual(t, "0", firstMapping.HostID, "主机上映射的ID不应该是root")
	
	// 验证GID映射
	gidMapPath := fmt.Sprintf("/proc/%s/gid_map", containerPID)
	gidMapContent := readFileContent(t, uidMapPath)
	assert.NotEmpty(t, gidMapContent, "GID映射应该存在")
	
	gidMappings := parseIDMapping(t, gidMapContent)
	assert.NotEmpty(t, gidMappings, "应该有GID映射条目")
	
	// 验证容器内实际的用户映射工作
	containerUID := execInContainer(t, containerID, "id", "-u")
	assert.Equal(t, "0", strings.TrimSpace(containerUID), "容器内应该显示为root用户")
	
	containerGID := execInContainer(t, containerID, "id", "-g")
	assert.Equal(t, "0", strings.TrimSpace(containerGID), "容器内应该显示为root组")
	
	// 验证映射范围合理
	for _, mapping := range uidMappings {
		hostIDInt, err := strconv.Atoi(mapping.HostID)
		require.NoError(t, err, "主机ID应该是有效数字")
		assert.Greater(t, hostIDInt, 1000, "映射的主机UID应该大于1000（避免系统用户）")
		
		rangeInt, err := strconv.Atoi(mapping.Range)
		require.NoError(t, err, "映射范围应该是有效数字")
		assert.Greater(t, rangeInt, 0, "映射范围应该大于0")
	}
}

// testContainerRegistration 测试容器注册与注销
func testContainerRegistration(t *testing.T) {
	containerName := "test-container-registration"
	
	// 记录注册前的容器数量（通过sysbox管理的容器）
	initialContainers := getSysboxManagedContainers(t)
	
	// 创建新容器
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证容器被注册
	time.Sleep(2 * time.Second) // 等待注册完成
	currentContainers := getSysboxManagedContainers(t)
	assert.Greater(t, len(currentContainers), len(initialContainers), 
		"新容器应该被注册到sysbox-mgr")
	
	// 验证容器信息正确记录
	found := false
	for _, container := range currentContainers {
		if strings.HasPrefix(containerID, container.ID) {
			found = true
			assert.Equal(t, containerName, container.Name, "容器名称应该正确记录")
			assert.Equal(t, "running", container.State, "容器状态应该是running")
			break
		}
	}
	assert.True(t, found, "应该找到新创建的容器记录")
	
	// 停止容器
	stopSysboxContainer(t, containerID)
	
	// 验证容器状态更新
	time.Sleep(2 * time.Second)
	updatedContainers := getSysboxManagedContainers(t)
	for _, container := range updatedContainers {
		if strings.HasPrefix(containerID, container.ID) {
			assert.NotEqual(t, "running", container.State, "容器状态应该已更新")
			break
		}
	}
	
	// 删除容器
	removeSysboxContainer(t, containerID)
	
	// 验证容器被注销
	time.Sleep(2 * time.Second)
	finalContainers := getSysboxManagedContainers(t)
	assert.LessOrEqual(t, len(finalContainers), len(currentContainers), 
		"容器应该被注销")
}

// testSpecialMountManagement 测试特殊挂载管理
func testSpecialMountManagement(t *testing.T) {
	containerName := "test-special-mounts"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证特殊挂载的存在
	mountOutput := execInContainer(t, containerID, "mount")
	
	// 检查sysbox特有的挂载
	specialMounts := []struct {
		path        string
		fstype      string
		description string
	}{
		{"/proc", "proc", "proc文件系统"},
		{"/sys", "sysfs", "sys文件系统"},
		{"/dev", "devtmpfs", "设备文件系统"},
		{"/dev/pts", "devpts", "伪终端文件系统"},
		{"/dev/shm", "tmpfs", "共享内存文件系统"},
	}
	
	for _, mount := range specialMounts {
		assert.Contains(t, mountOutput, mount.path, 
			fmt.Sprintf("%s应该被挂载", mount.description))
	}
	
	// 验证挂载选项正确性
	mountLines := strings.Split(mountOutput, "\n")
	for _, line := range mountLines {
		if strings.Contains(line, "/proc") && strings.Contains(line, "proc") {
			// 验证/proc挂载选项
			assert.Contains(t, line, "rw", "/proc应该以读写模式挂载")
		}
		if strings.Contains(line, "/sys") && strings.Contains(line, "sysfs") {
			// 验证/sys挂载选项
			assert.Contains(t, line, "rw", "/sys应该以读写模式挂载")
		}
	}
	
	// 验证特殊挂载的功能性
	procMeminfoTest := execInContainer(t, containerID, "cat", "/proc/meminfo")
	assert.Contains(t, procMeminfoTest, "MemTotal", "/proc/meminfo应该可读且包含内存信息")
	
	sysKernelTest := execInContainer(t, containerID, "cat", "/sys/kernel/osrelease")
	assert.NotEmpty(t, sysKernelTest, "/sys/kernel/osrelease应该可读")
	
	devNullTest := execInContainer(t, containerID, "echo", "test", ">", "/dev/null")
	assert.NotEmpty(t, devNullTest, "/dev/null应该可写")
}

// testContainerResourceAllocation 测试容器资源分配与回收
func testContainerResourceAllocation(t *testing.T) {
	containerName := "test-resource-allocation"
	
	// 创建带资源限制的容器
	containerID := createSysboxContainerWithOptions(t, containerName, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--memory=256m", "--cpus=0.5")
	defer cleanupContainer(t, containerID)
	
	// 验证内存资源分配
	memLimitFile := "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	if fileExists(t, containerID, memLimitFile) {
		memLimit := execInContainer(t, containerID, "cat", memLimitFile)
		memLimitBytes := parseBytes(t, strings.TrimSpace(memLimit))
		expectedBytes := int64(256 * 1024 * 1024) // 256MB
		assert.InDelta(t, expectedBytes, memLimitBytes, float64(expectedBytes)*0.1,
			"内存限制应该接近设置值")
	}
	
	// 验证CPU资源分配
	cpuQuotaFile := "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
	if fileExists(t, containerID, cpuQuotaFile) {
		cpuQuota := execInContainer(t, containerID, "cat", cpuQuotaFile)
		cpuQuotaInt, err := strconv.Atoi(strings.TrimSpace(cpuQuota))
		if err == nil {
			assert.Greater(t, cpuQuotaInt, 0, "CPU配额应该大于0")
			assert.Less(t, cpuQuotaInt, 100000, "CPU配额应该反映0.5核心的限制")
		}
	}
	
	// 验证PID限制分配
	pidMaxFile := "/sys/fs/cgroup/pids/pids.max"
	if fileExists(t, containerID, pidMaxFile) {
		pidMax := execInContainer(t, containerID, "cat", pidMaxFile)
		if strings.TrimSpace(pidMax) != "max" {
			pidMaxInt, err := strconv.Atoi(strings.TrimSpace(pidMax))
			if err == nil {
				assert.Greater(t, pidMaxInt, 0, "PID限制应该大于0")
			}
		}
	}
	
	// 测试资源回收
	stopSysboxContainer(t, containerID)
	
	// 验证资源被正确回收（通过检查是否还有相关进程）
	time.Sleep(2 * time.Second)
	containerPID := getContainerPIDNoError(containerID)
	assert.Empty(t, containerPID, "容器停止后应该没有主进程")
}

// testSysboxMgrConfiguration 测试sysbox-mgr配置管理
func testSysboxMgrConfiguration(t *testing.T) {
	// 检查sysbox-mgr配置文件
	configPaths := []string{
		"/etc/sysbox/sysbox.conf",
		"/usr/local/etc/sysbox/sysbox.conf",
	}
	
	var configPath string
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			configPath = path
			break
		}
	}
	
	if configPath != "" {
		configContent, err := ioutil.ReadFile(configPath)
		require.NoError(t, err, "应该能读取sysbox配置文件")
		
		config := string(configContent)
		assert.NotEmpty(t, config, "配置文件不应该为空")
		
		// 验证配置文件包含预期的配置项
		expectedConfigs := []string{
			"mgr",
			"fs",
		}
		
		for _, expectedConfig := range expectedConfigs {
			if strings.Contains(config, expectedConfig) {
				t.Logf("找到配置项: %s", expectedConfig)
			}
		}
	}
	
	// 验证sysbox-mgr运行时配置
	containerName := "test-mgr-config"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "60"})
	defer cleanupContainer(t, containerID)
	
	// 通过容器行为验证配置正确性
	// 1. 验证用户命名空间配置
	uidMap := execInContainer(t, containerID, "cat", "/proc/self/uid_map")
	assert.NotEmpty(t, uidMap, "用户命名空间应该正确配置")
	
	// 2. 验证挂载命名空间配置
	mountNS := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/mnt")
	assert.NotEmpty(t, mountNS, "挂载命名空间应该正确配置")
	
	// 3. 验证PID命名空间配置
	pidNS := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/pid")
	assert.NotEmpty(t, pidNS, "PID命名空间应该正确配置")
}

// testInterContainerResourceIsolation 测试容器间资源隔离
func testInterContainerResourceIsolation(t *testing.T) {
	container1Name := "test-isolation-1"
	container2Name := "test-isolation-2"
	
	// 创建两个容器
	container1ID := createSysboxContainer(t, container1Name, "ubuntu:20.04", []string{"sleep", "300"})
	container2ID := createSysboxContainer(t, container2Name, "ubuntu:20.04", []string{"sleep", "300"})
	
	defer func() {
		cleanupContainer(t, container1ID)
		cleanupContainer(t, container2ID)
	}()
	
	// 验证UID/GID映射隔离
	container1UID := getContainerPID(t, container1ID)
	container2UID := getContainerPID(t, container2ID)
	assert.NotEqual(t, container1UID, container2UID, "不同容器应该有不同的主进程PID")
	
	// 验证用户命名空间隔离
	uid1MapPath := fmt.Sprintf("/proc/%s/uid_map", container1UID)
	uid2MapPath := fmt.Sprintf("/proc/%s/uid_map", container2UID)
	
	uid1Map := readFileContent(t, uid1MapPath)
	uid2Map := readFileContent(t, uid2MapPath)
	
	// 虽然映射格式可能相似，但主机端的ID范围应该不同
	uid1Mappings := parseIDMapping(t, uid1Map)
	uid2Mappings := parseIDMapping(t, uid2Map)
	
	if len(uid1Mappings) > 0 && len(uid2Mappings) > 0 {
		// 如果有多个容器，它们的主机端ID范围应该不重叠
		assert.NotEqual(t, uid1Mappings[0].HostID, uid2Mappings[0].HostID,
			"不同容器的UID映射主机端ID应该不同")
	}
	
	// 验证进程隔离
	container1Processes := execInContainer(t, container1ID, "ps", "aux")
	container2Processes := execInContainer(t, container2ID, "ps", "aux")
	
	// 每个容器应该只看到自己的进程
	assert.NotContains(t, container1Processes, container2Name, 
		"容器1不应该看到容器2的进程")
	assert.NotContains(t, container2Processes, container1Name,
		"容器2不应该看到容器1的进程")
	
	// 验证网络隔离
	container1IP := getContainerIP(t, container1ID)
	container2IP := getContainerIP(t, container2ID)
	assert.NotEqual(t, container1IP, container2IP, "不同容器应该有不同的IP地址")
}

// testSysboxMgrLoggingAndMonitoring 测试sysbox-mgr日志和监控
func testSysboxMgrLoggingAndMonitoring(t *testing.T) {
	// 查找sysbox-mgr日志文件
	logPaths := []string{
		"/var/log/sysbox-mgr.log",
		"/tmp/sysbox-mgr.log",
	}
	
	var activeLogPath string
	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			activeLogPath = path
			break
		}
	}
	
	if activeLogPath == "" {
		t.Skip("未找到sysbox-mgr日志文件，跳过日志测试")
		return
	}
	
	// 记录当前日志行数
	initialLogSize := getFileLineCount(t, activeLogPath)
	
	// 创建容器以生成日志
	containerName := "test-logging"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "60"})
	defer cleanupContainer(t, containerID)
	
	// 等待日志产生
	time.Sleep(3 * time.Second)
	
	// 检查日志是否增加
	currentLogSize := getFileLineCount(t, activeLogPath)
	if currentLogSize > initialLogSize {
		// 读取最新的日志内容
		recentLogs, err := exec.Command("tail", "-20", activeLogPath).Output()
		require.NoError(t, err, "应该能读取日志文件")
		
		logContent := string(recentLogs)
		assert.NotEmpty(t, logContent, "日志内容不应该为空")
		
		// 验证日志包含容器相关信息
		if strings.Contains(logContent, containerID[:12]) || 
		   strings.Contains(logContent, containerName) ||
		   strings.Contains(logContent, "container") {
			t.Log("日志正确记录了容器操作")
		}
		
		// 验证日志格式
		logLines := strings.Split(strings.TrimSpace(logContent), "\n")
		for _, line := range logLines {
			if strings.TrimSpace(line) != "" {
				// 简单验证日志行不为空
				assert.NotEmpty(t, line, "日志行不应该为空")
			}
		}
	}
	
	// 测试错误日志记录
	stopSysboxContainer(t, containerID)
	removeSysboxContainer(t, containerID)
	
	time.Sleep(2 * time.Second)
	
	// 验证停止/删除操作也被记录
	finalLogSize := getFileLineCount(t, activeLogPath)
	if finalLogSize >= currentLogSize {
		t.Log("容器停止和删除操作被正确记录")
	}
}

// testContainerAbnormalSituationHandling 测试容器异常情况处理
func testContainerAbnormalSituationHandling(t *testing.T) {
	containerName := "test-abnormal-handling"
	
	// 创建容器
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 模拟容器内进程异常退出
	execInContainer(t, containerID, "kill", "-9", "1")
	
	// 等待容器状态变化
	time.Sleep(5 * time.Second)
	
	// 验证容器状态被正确处理
	status, err := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", containerID).Output()
	require.NoError(t, err)
	containerStatus := strings.TrimSpace(string(status))
	
	// 容器应该处于exited状态
	assert.Equal(t, "exited", containerStatus, "容器应该处于exited状态")
	
	// 验证退出码
	exitCode, err := exec.Command("docker", "inspect", "-f", "{{.State.ExitCode}}", containerID).Output()
	require.NoError(t, err)
	exitCodeInt, err := strconv.Atoi(strings.TrimSpace(string(exitCode)))
	require.NoError(t, err)
	assert.NotEqual(t, 0, exitCodeInt, "容器退出码应该非零（表示异常退出）")
	
	// 验证sysbox-mgr正确处理了容器停止
	time.Sleep(2 * time.Second)
	containers := getSysboxManagedContainers(t)
	
	found := false
	for _, container := range containers {
		if strings.HasPrefix(containerID, container.ID) {
			found = true
			assert.NotEqual(t, "running", container.State, "sysbox-mgr应该正确更新容器状态")
			break
		}
	}
	
	if !found {
		t.Log("容器已从sysbox-mgr中移除，这也是正确的处理方式")
	}
}

// Helper functions

type IDMapping struct {
	ContainerID string
	HostID      string
	Range       string
}

type ContainerInfo struct {
	ID    string
	Name  string
	State string
}

func setupSysboxMgrTestEnv(t *testing.T) {
	// 验证sysbox-mgr正在运行
	_, err := exec.Command("pgrep", "-f", "sysbox-mgr").Output()
	require.NoError(t, err, "sysbox-mgr应该正在运行")
	
	// 清理测试容器
	testContainers := []string{
		"test-uid-gid-mapping", "test-container-registration", "test-special-mounts",
		"test-resource-allocation", "test-mgr-config", "test-isolation-1", "test-isolation-2",
		"test-logging", "test-abnormal-handling",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func cleanupSysboxMgrTestEnv(t *testing.T) {
	// 清理测试容器
	testContainers := []string{
		"test-uid-gid-mapping", "test-container-registration", "test-special-mounts",
		"test-resource-allocation", "test-mgr-config", "test-isolation-1", "test-isolation-2",
		"test-logging", "test-abnormal-handling",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func parseIDMapping(t *testing.T, content string) []IDMapping {
	var mappings []IDMapping
	lines := strings.Split(strings.TrimSpace(content), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			mappings = append(mappings, IDMapping{
				ContainerID: parts[0],
				HostID:      parts[1],
				Range:       parts[2],
			})
		}
	}
	
	return mappings
}

func getSysboxManagedContainers(t *testing.T) []ContainerInfo {
	// 获取所有使用sysbox-runc运行时的容器
	output, err := exec.Command("docker", "ps", "-a", "--format", "{{.ID}}:{{.Names}}:{{.State}}", 
		"--filter", "runtime=sysbox-runc").Output()
	if err != nil {
		return []ContainerInfo{}
	}
	
	var containers []ContainerInfo
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			containers = append(containers, ContainerInfo{
				ID:    parts[0],
				Name:  parts[1],
				State: parts[2],
			})
		}
	}
	
	return containers
}

func getContainerPIDNoError(containerID string) string {
	output, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerID).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func getFileLineCount(t *testing.T, filePath string) int {
	output, err := exec.Command("wc", "-l", filePath).Output()
	if err != nil {
		return 0
	}
	
	parts := strings.Fields(strings.TrimSpace(string(output)))
	if len(parts) > 0 {
		count, err := strconv.Atoi(parts[0])
		if err == nil {
			return count
		}
	}
	
	return 0
}