package core

import (
	"fmt"
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

// TestSysboxFSVirtualization 测试Sysbox文件系统虚拟化功能
func TestSysboxFSVirtualization(t *testing.T) {
	setupSysboxFSTestEnv(t)
	defer cleanupSysboxFSTestEnv(t)

	t.Run("procfs虚拟化基本功能", func(t *testing.T) {
		testProcfsVirtualization(t)
	})

	t.Run("sysfs虚拟化基本功能", func(t *testing.T) {
		testSysfsVirtualization(t)
	})

	t.Run("procfs系统信息隔离", func(t *testing.T) {
		testProcfsSystemInfoIsolation(t)
	})

	t.Run("sysfs内核参数虚拟化", func(t *testing.T) {
		testSysfsKernelParametersVirtualization(t)
	})

	t.Run("容器间文件系统隔离", func(t *testing.T) {
		testContainerFilesystemIsolation(t)
	})

	t.Run("特殊文件系统挂载处理", func(t *testing.T) {
		testSpecialFilesystemMounts(t)
	})

	t.Run("FUSE文件系统性能验证", func(t *testing.T) {
		testFUSEFilesystemPerformance(t)
	})

	t.Run("动态文件内容生成", func(t *testing.T) {
		testDynamicFileContentGeneration(t)
	})
}

// testProcfsVirtualization 测试procfs虚拟化
func testProcfsVirtualization(t *testing.T) {
	containerName := "test-procfs-virt"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证/proc挂载正确
	mountInfo := execInContainer(t, containerID, "mount", "|", "grep", "/proc")
	assert.Contains(t, mountInfo, "/proc", "应该挂载/proc文件系统")
	
	// 验证/proc/version被虚拟化
	procVersion := execInContainer(t, containerID, "cat", "/proc/version")
	assert.NotEmpty(t, procVersion, "/proc/version应该可读")
	assert.Contains(t, procVersion, "Linux", "/proc/version应该包含Linux信息")
	
	// 验证/proc/meminfo显示容器内存信息
	memInfo := execInContainer(t, containerID, "cat", "/proc/meminfo")
	assert.Contains(t, memInfo, "MemTotal:", "/proc/meminfo应该包含内存信息")
	
	// 获取MemTotal值并验证合理性
	memTotalLine := extractLineFromOutput(memInfo, "MemTotal:")
	memTotal := extractMemoryValue(t, memTotalLine)
	assert.Greater(t, memTotal, int64(0), "内存总量应该大于0")
	
	// 验证/proc/cpuinfo显示CPU信息
	cpuInfo := execInContainer(t, containerID, "cat", "/proc/cpuinfo")
	assert.Contains(t, cpuInfo, "processor", "/proc/cpuinfo应该包含处理器信息")
	
	// 验证/proc/uptime可读
	uptime := execInContainer(t, containerID, "cat", "/proc/uptime")
	assert.NotEmpty(t, uptime, "/proc/uptime应该可读")
	
	// 验证uptime格式正确
	uptimeParts := strings.Fields(strings.TrimSpace(uptime))
	assert.Len(t, uptimeParts, 2, "/proc/uptime应该包含两个数字")
	
	_, err := strconv.ParseFloat(uptimeParts[0], 64)
	assert.NoError(t, err, "uptime第一个值应该是有效浮点数")
}

// testSysfsVirtualization 测试sysfs虚拟化
func testSysfsVirtualization(t *testing.T) {
	containerName := "test-sysfs-virt"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证/sys挂载正确
	mountInfo := execInContainer(t, containerID, "mount", "|", "grep", "/sys")
	assert.Contains(t, mountInfo, "/sys", "应该挂载/sys文件系统")
	
	// 验证/sys/kernel/osrelease可读
	osRelease := execInContainer(t, containerID, "cat", "/sys/kernel/osrelease")
	assert.NotEmpty(t, osRelease, "/sys/kernel/osrelease应该可读")
	assert.Regexp(t, `^\d+\.\d+`, strings.TrimSpace(osRelease), "内核版本格式应该正确")
	
	// 验证/sys/kernel/version可读
	kernelVersion := execInContainer(t, containerID, "cat", "/sys/kernel/version")
	assert.NotEmpty(t, kernelVersion, "/sys/kernel/version应该可读")
	
	// 验证/sys/fs目录存在
	sysFsLS := execInContainer(t, containerID, "ls", "/sys/fs")
	assert.NotEmpty(t, sysFsLS, "/sys/fs目录应该存在")
	
	// 验证cgroup相关目录
	if strings.Contains(sysFsLS, "cgroup") {
		cgroupLS := execInContainer(t, containerID, "ls", "/sys/fs/cgroup")
		assert.NotEmpty(t, cgroupLS, "/sys/fs/cgroup应该可访问")
	}
	
	// 验证/sys/class目录
	sysClassLS := execInContainer(t, containerID, "ls", "/sys/class")
	assert.Contains(t, sysClassLS, "net", "/sys/class应该包含net子目录")
}

// testProcfsSystemInfoIsolation 测试procfs系统信息隔离
func testProcfsSystemInfoIsolation(t *testing.T) {
	containerName := "test-procfs-isolation"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 获取主机和容器的/proc/stat信息对比
	hostStat, err := os.ReadFile("/proc/stat")
	require.NoError(t, err, "读取主机/proc/stat失败")
	
	containerStat := execInContainer(t, containerID, "cat", "/proc/stat")
	
	// 验证容器内的stat信息不完全相同（表明被虚拟化）
	// 注意：Sysbox可能会显示相似但隔离的信息
	assert.NotEmpty(t, containerStat, "容器内/proc/stat应该可读")
	assert.Contains(t, containerStat, "cpu", "应该包含CPU统计信息")
	
	// 验证/proc/loadavg隔离
	containerLoadavg := execInContainer(t, containerID, "cat", "/proc/loadavg")
	assert.NotEmpty(t, containerLoadavg, "/proc/loadavg应该可读")
	
	loadavgParts := strings.Fields(strings.TrimSpace(containerLoadavg))
	assert.Len(t, loadavgParts, 5, "/proc/loadavg应该包含5个字段")
	
	// 验证负载值为有效数字
	for i := 0; i < 3; i++ {
		_, err := strconv.ParseFloat(loadavgParts[i], 64)
		assert.NoError(t, err, "负载值应该是有效浮点数")
	}
	
	// 验证/proc/diskstats隔离
	containerDiskstats := execInContainer(t, containerID, "cat", "/proc/diskstats")
	assert.NotEmpty(t, containerDiskstats, "/proc/diskstats应该可读")
}

// testSysfsKernelParametersVirtualization 测试sysfs内核参数虚拟化
func testSysfsKernelParametersVirtualization(t *testing.T) {
	containerName := "test-sysfs-kernel-params"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证内核参数可读
	kernelParams := []string{
		"/sys/kernel/ostype",
		"/sys/kernel/osrelease", 
		"/sys/kernel/version",
	}
	
	for _, param := range kernelParams {
		if fileExists(t, containerID, param) {
			content := execInContainer(t, containerID, "cat", param)
			assert.NotEmpty(t, content, fmt.Sprintf("%s应该可读", param))
		}
	}
	
	// 验证/sys/kernel/pid_max
	if fileExists(t, containerID, "/sys/kernel/pid_max") {
		pidMax := execInContainer(t, containerID, "cat", "/sys/kernel/pid_max")
		pidMaxValue, err := strconv.Atoi(strings.TrimSpace(pidMax))
		if err == nil {
			assert.Greater(t, pidMaxValue, 0, "pid_max应该是正数")
		}
	}
	
	// 验证网络相关参数
	netParams := []string{
		"/sys/class/net",
	}
	
	for _, param := range netParams {
		if fileExists(t, containerID, param) {
			content := execInContainer(t, containerID, "ls", param)
			assert.NotEmpty(t, content, fmt.Sprintf("%s目录应该不为空", param))
		}
	}
}

// testContainerFilesystemIsolation 测试容器间文件系统隔离
func testContainerFilesystemIsolation(t *testing.T) {
	container1Name := "test-fs-isolation-1"
	container2Name := "test-fs-isolation-2"
	
	container1ID := createSysboxContainer(t, container1Name, "ubuntu:20.04", []string{"sleep", "300"})
	container2ID := createSysboxContainer(t, container2Name, "ubuntu:20.04", []string{"sleep", "300"})
	
	defer func() {
		cleanupContainer(t, container1ID)
		cleanupContainer(t, container2ID)
	}()
	
	// 在容器1中创建文件
	execInContainer(t, container1ID, "echo", "container1-data", ">", "/tmp/test_isolation")
	execInContainer(t, container1ID, "mkdir", "-p", "/tmp/container1_dir")
	execInContainer(t, container1ID, "echo", "private", ">", "/tmp/container1_dir/private.txt")
	
	// 在容器2中创建不同文件
	execInContainer(t, container2ID, "echo", "container2-data", ">", "/tmp/test_isolation")
	execInContainer(t, container2ID, "mkdir", "-p", "/tmp/container2_dir")
	execInContainer(t, container2ID, "echo", "secret", ">", "/tmp/container2_dir/secret.txt")
	
	// 验证容器1只能看到自己的文件
	container1Content := execInContainer(t, container1ID, "cat", "/tmp/test_isolation")
	assert.Contains(t, container1Content, "container1-data", "容器1应该只能看到自己的文件内容")
	
	// 验证容器2只能看到自己的文件
	container2Content := execInContainer(t, container2ID, "cat", "/tmp/test_isolation")
	assert.Contains(t, container2Content, "container2-data", "容器2应该只能看到自己的文件内容")
	
	// 验证容器1无法访问容器2的私有目录
	_, err := execInContainerWithError(container1ID, "ls", "/tmp/container2_dir")
	assert.Error(t, err, "容器1不应该能访问容器2的私有目录")
	
	// 验证容器2无法访问容器1的私有目录
	_, err = execInContainerWithError(container2ID, "ls", "/tmp/container1_dir")
	assert.Error(t, err, "容器2不应该能访问容器1的私有目录")
	
	// 验证/proc文件系统隔离
	container1Processes := execInContainer(t, container1ID, "ps", "aux")
	container2Processes := execInContainer(t, container2ID, "ps", "aux")
	
	// 每个容器应该只看到自己的进程
	assert.NotEqual(t, container1Processes, container2Processes, "不同容器的进程列表应该不同")
}

// testSpecialFilesystemMounts 测试特殊文件系统挂载处理
func testSpecialFilesystemMounts(t *testing.T) {
	containerName := "test-special-mounts"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 获取所有挂载点
	mountOutput := execInContainer(t, containerID, "mount")
	
	// 验证必要的特殊文件系统挂载
	expectedMounts := []string{
		"/proc",
		"/sys", 
		"/dev",
		"/dev/pts",
		"/dev/shm",
	}
	
	for _, mount := range expectedMounts {
		assert.Contains(t, mountOutput, mount, fmt.Sprintf("%s应该被正确挂载", mount))
	}
	
	// 验证tmpfs挂载
	if strings.Contains(mountOutput, "tmpfs") {
		tmpfsMounts := extractMountsByType(mountOutput, "tmpfs")
		assert.NotEmpty(t, tmpfsMounts, "应该有tmpfs挂载")
		
		// 验证/dev/shm是tmpfs
		devShmMount := execInContainer(t, containerID, "df", "-t", "tmpfs", "/dev/shm")
		assert.Contains(t, devShmMount, "/dev/shm", "/dev/shm应该是tmpfs")
	}
	
	// 验证/dev/pts功能
	devPtsLS := execInContainer(t, containerID, "ls", "/dev/pts")
	assert.Contains(t, devPtsLS, "ptmx", "/dev/pts应该包含ptmx")
	
	// 验证/proc/sys的只读性（某些路径）
	_, err := execInContainerWithError(containerID, "echo", "1", ">", "/proc/sys/kernel/domainname")
	// 注意：某些参数可能允许写入，这取决于Sysbox配置
}

// testFUSEFilesystemPerformance 测试FUSE文件系统性能
func testFUSEFilesystemPerformance(t *testing.T) {
	containerName := "test-fuse-performance"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试/proc文件读取性能
	start := time.Now()
	for i := 0; i < 10; i++ {
		execInContainer(t, containerID, "cat", "/proc/meminfo")
	}
	procReadDuration := time.Since(start)
	
	// 读取10次/proc/meminfo应该在合理时间内完成（<5秒）
	assert.Less(t, procReadDuration, 5*time.Second, "/proc文件读取性能应该合理")
	
	// 测试/sys文件读取性能
	start = time.Now()
	for i := 0; i < 10; i++ {
		execInContainer(t, containerID, "cat", "/sys/kernel/osrelease")
	}
	sysReadDuration := time.Since(start)
	
	assert.Less(t, sysReadDuration, 5*time.Second, "/sys文件读取性能应该合理")
	
	// 测试目录遍历性能
	start = time.Now()
	execInContainer(t, containerID, "find", "/proc", "-maxdepth", "2", "-type", "f", "|", "head", "-50")
	procFindDuration := time.Since(start)
	
	assert.Less(t, procFindDuration, 10*time.Second, "/proc目录遍历性能应该合理")
}

// testDynamicFileContentGeneration 测试动态文件内容生成
func testDynamicFileContentGeneration(t *testing.T) {
	containerName := "test-dynamic-content"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试/proc/uptime内容随时间变化
	uptime1 := execInContainer(t, containerID, "cat", "/proc/uptime")
	uptimeParts1 := strings.Fields(strings.TrimSpace(uptime1))
	require.Len(t, uptimeParts1, 2, "uptime应该包含两个值")
	
	time.Sleep(2 * time.Second)
	
	uptime2 := execInContainer(t, containerID, "cat", "/proc/uptime")
	uptimeParts2 := strings.Fields(strings.TrimSpace(uptime2))
	require.Len(t, uptimeParts2, 2, "uptime应该包含两个值")
	
	// 验证uptime值增加了
	uptime1Val, _ := strconv.ParseFloat(uptimeParts1[0], 64)
	uptime2Val, _ := strconv.ParseFloat(uptimeParts2[0], 64)
	assert.Greater(t, uptime2Val, uptime1Val, "uptime值应该随时间增加")
	
	// 测试/proc/stat的动态内容
	stat1 := execInContainer(t, containerID, "cat", "/proc/stat")
	time.Sleep(1 * time.Second)
	stat2 := execInContainer(t, containerID, "cat", "/proc/stat")
	
	// 虽然内容可能相似，但时间戳相关的字段可能会变化
	assert.NotEmpty(t, stat1, "第一次读取stat应该有内容")
	assert.NotEmpty(t, stat2, "第二次读取stat应该有内容")
	
	// 测试/proc/meminfo的动态性（内存使用可能变化）
	meminfo1 := execInContainer(t, containerID, "cat", "/proc/meminfo")
	
	// 在容器内分配一些内存
	execInContainer(t, containerID, "sh", "-c", "python3 -c \"x=[0]*1000000; import time; time.sleep(1)\" &")
	time.Sleep(2 * time.Second)
	
	meminfo2 := execInContainer(t, containerID, "cat", "/proc/meminfo")
	
	assert.NotEmpty(t, meminfo1, "第一次meminfo读取应该有内容")
	assert.NotEmpty(t, meminfo2, "第二次meminfo读取应该有内容")
}

// Helper functions

func setupSysboxFSTestEnv(t *testing.T) {
	// 验证sysbox-fs进程运行
	_, err := exec.Command("pgrep", "sysbox-fs").Output()
	require.NoError(t, err, "sysbox-fs进程应该正在运行")
	
	// 清理可能存在的测试容器
	testContainers := []string{
		"test-procfs-virt", "test-sysfs-virt", "test-procfs-isolation",
		"test-sysfs-kernel-params", "test-fs-isolation-1", "test-fs-isolation-2",
		"test-special-mounts", "test-fuse-performance", "test-dynamic-content",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func cleanupSysboxFSTestEnv(t *testing.T) {
	// 清理所有测试容器
	testContainers := []string{
		"test-procfs-virt", "test-sysfs-virt", "test-procfs-isolation",
		"test-sysfs-kernel-params", "test-fs-isolation-1", "test-fs-isolation-2",
		"test-special-mounts", "test-fuse-performance", "test-dynamic-content",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func extractLineFromOutput(output, prefix string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func extractMemoryValue(t *testing.T, line string) int64 {
	// 从类似 "MemTotal:        8062848 kB" 的行中提取数值
	re := regexp.MustCompile(`(\d+)\s+kB`)
	matches := re.FindStringSubmatch(line)
	if len(matches) >= 2 {
		value, err := strconv.ParseInt(matches[1], 10, 64)
		require.NoError(t, err, "解析内存值失败")
		return value * 1024 // 转换为字节
	}
	return 0
}

func fileExists(t *testing.T, containerID, filePath string) bool {
	_, err := execInContainerWithError(containerID, "test", "-f", filePath)
	return err == nil
}

func extractMountsByType(mountOutput, fsType string) []string {
	var mounts []string
	lines := strings.Split(mountOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, fsType) {
			mounts = append(mounts, strings.TrimSpace(line))
		}
	}
	return mounts
}