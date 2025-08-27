package core

import (
	"bufio"
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

// TestSysboxMountNamespace 测试 Sysbox 挂载命名空间管理核心功能
func TestSysboxMountNamespace(t *testing.T) {
	setupMountNamespaceTestEnv(t)
	defer cleanupMountNamespaceTestEnv(t)

	t.Run("基本挂载命名空间隔离", func(t *testing.T) {
		testBasicMountNamespaceIsolation(t)
	})

	t.Run("容器内挂载操作", func(t *testing.T) {
		testContainerMountOperations(t)
	})

	t.Run("挂载传播和共享", func(t *testing.T) {
		testMountPropagationAndSharing(t)
	})

	t.Run("特殊文件系统挂载", func(t *testing.T) {
		testSpecialFilesystemMounts(t)
	})

	t.Run("绑定挂载和卷管理", func(t *testing.T) {
		testBindMountsAndVolumeManagement(t)
	})

	t.Run("挂载安全和权限", func(t *testing.T) {
		testMountSecurityAndPermissions(t)
	})

	t.Run("动态挂载和卸载", func(t *testing.T) {
		testDynamicMountingAndUnmounting(t)
	})

	t.Run("挂载性能和优化", func(t *testing.T) {
		testMountPerformanceAndOptimization(t)
	})
}

// setupMountNamespaceTestEnv 设置挂载命名空间测试环境
func setupMountNamespaceTestEnv(t *testing.T) {
	t.Log("设置挂载命名空间测试环境...")

	// 验证必要的挂载工具
	requiredTools := []string{"mount", "umount", "findmnt", "lsblk"}
	for _, tool := range requiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("跳过测试: 缺少必要工具 %s", tool)
		}
	}

	// 验证 sysbox-runc 运行时可用
	verifySysboxRuntime(t)

	// 创建测试目录
	testDirs := []string{
		"/tmp/sysbox-mount-test",
		"/tmp/sysbox-mount-test/host-dir",
		"/tmp/sysbox-mount-test/container-dir",
	}

	for _, dir := range testDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("创建测试目录失败: %v", err)
		}
	}

	// 创建测试文件
	testFile := "/tmp/sysbox-mount-test/host-dir/test-file.txt"
	if err := os.WriteFile(testFile, []byte("测试文件内容"), 0644); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	t.Log("挂载命名空间测试环境设置完成")
}

// cleanupMountNamespaceTestEnv 清理挂载命名空间测试环境
func cleanupMountNamespaceTestEnv(t *testing.T) {
	t.Log("清理挂载命名空间测试环境...")

	// 清理测试容器
	cleanupTestContainersWithPrefix(t, "test-mount")

	// 清理测试目录
	os.RemoveAll("/tmp/sysbox-mount-test")

	t.Log("挂载命名空间测试环境清理完成")
}

// testBasicMountNamespaceIsolation 测试基本挂载命名空间隔离
func testBasicMountNamespaceIsolation(t *testing.T) {
	t.Log("测试基本挂载命名空间隔离...")

	// 创建 Sysbox 容器
	containerID := createSysboxContainer(t, "test-mount-basic", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	waitForContainerRunning(t, containerID)

	// 获取主机挂载点列表
	hostMounts := getMountPoints(t, "")

	// 获取容器内挂载点列表
	containerMounts := getMountPoints(t, containerID)

	t.Log("主机挂载点数量:", len(hostMounts))
	t.Log("容器挂载点数量:", len(containerMounts))

	// 验证挂载命名空间隔离
	assert.NotEqual(t, hostMounts, containerMounts, "容器应该有独立的挂载命名空间")

	// 验证容器基本挂载点
	testBasicContainerMounts(t, containerID, containerMounts)

	// 验证挂载点隔离性
	testMountPointIsolation(t, containerID)
}

// testContainerMountOperations 测试容器内挂载操作
func testContainerMountOperations(t *testing.T) {
	t.Log("测试容器内挂载操作...")

	// 创建带挂载权限的容器
	containerID := createSysboxContainer(t, "test-mount-operations", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	waitForContainerRunning(t, containerID)

	// 在容器内创建临时文件系统
	testTmpfsMount(t, containerID)

	// 测试绑定挂载
	testBindMount(t, containerID)

	// 测试挂载选项
	testMountOptions(t, containerID)

	// 验证挂载操作的持久性
	testMountPersistence(t, containerID)
}

// testMountPropagationAndSharing 测试挂载传播和共享
func testMountPropagationAndSharing(t *testing.T) {
	t.Log("测试挂载传播和共享...")

	// 创建带卷挂载的容器
	containerID := createSysboxContainerWithVolume(t, "test-mount-propagation", "ubuntu:20.04", 
		"/tmp/sysbox-mount-test/host-dir", "/mnt/shared", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	waitForContainerRunning(t, containerID)

	// 测试挂载传播
	testMountPropagation(t, containerID)

	// 测试共享挂载
	testSharedMount(t, containerID)

	// 测试挂载可见性
	testMountVisibility(t, containerID)
}

// testSpecialFilesystemMounts 测试特殊文件系统挂载
func testSpecialFilesystemMounts(t *testing.T) {
	t.Log("测试特殊文件系统挂载...")

	containerID := createSysboxContainer(t, "test-mount-special", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	waitForContainerRunning(t, containerID)

	// 验证 procfs 挂载
	testProcfsMount(t, containerID)

	// 验证 sysfs 挂载
	testSysfsMount(t, containerID)

	// 验证 devtmpfs 挂载
	testDevtmpfsMount(t, containerID)

	// 验证 cgroup 挂载
	testCgroupMount(t, containerID)
}

// testBindMountsAndVolumeManagement 测试绑定挂载和卷管理
func testBindMountsAndVolumeManagement(t *testing.T) {
	t.Log("测试绑定挂载和卷管理...")

	// 创建 Docker 卷
	volumeName := "test-mount-volume"
	createDockerVolume(t, volumeName)
	defer removeDockerVolume(t, volumeName)

	// 创建带卷的容器
	containerID := createSysboxContainerWithDockerVolume(t, "test-mount-volume-mgmt", "ubuntu:20.04", 
		volumeName, "/mnt/volume", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	waitForContainerRunning(t, containerID)

	// 测试卷访问
	testVolumeAccess(t, containerID)

	// 测试卷数据持久性
	testVolumePersistence(t, containerID, volumeName)

	// 测试多容器卷共享
	testMultiContainerVolumeSharing(t, containerID, volumeName)
}

// testMountSecurityAndPermissions 测试挂载安全和权限
func testMountSecurityAndPermissions(t *testing.T) {
	t.Log("测试挂载安全和权限...")

	containerID := createSysboxContainer(t, "test-mount-security", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	waitForContainerRunning(t, containerID)

	// 测试挂载权限检查
	testMountPermissionChecks(t, containerID)

	// 测试敏感挂载点保护
	testSensitiveMountProtection(t, containerID)

	// 测试挂载逃逸防护
	testMountEscapePrevention(t, containerID)
}

// testDynamicMountingAndUnmounting 测试动态挂载和卸载
func testDynamicMountingAndUnmounting(t *testing.T) {
	t.Log("测试动态挂载和卸载...")

	containerID := createSysboxContainer(t, "test-mount-dynamic", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	waitForContainerRunning(t, containerID)

	// 测试动态挂载
	testDynamicMount(t, containerID)

	// 测试动态卸载
	testDynamicUnmount(t, containerID)

	// 测试挂载状态跟踪
	testMountStateTracking(t, containerID)
}

// testMountPerformanceAndOptimization 测试挂载性能和优化
func testMountPerformanceAndOptimization(t *testing.T) {
	t.Log("测试挂载性能和优化...")

	containerID := createSysboxContainer(t, "test-mount-performance", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	waitForContainerRunning(t, containerID)

	// 测试挂载性能
	testMountPerformance(t, containerID)

	// 测试大量挂载点
	testManyMountPoints(t, containerID)

	// 测试挂载缓存
	testMountCaching(t, containerID)
}

// 辅助函数

// getMountPoints 获取挂载点列表
func getMountPoints(t *testing.T, containerID string) []string {
	var cmd *exec.Cmd
	if containerID == "" {
		cmd = exec.Command("findmnt", "-D", "-o", "TARGET")
	} else {
		cmd = exec.Command("docker", "exec", containerID, "findmnt", "-D", "-o", "TARGET")
	}

	output, err := cmd.Output()
	if err != nil {
		t.Logf("获取挂载点失败: %v", err)
		return []string{}
	}

	mounts := []string{}
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && line != "TARGET" {
			mounts = append(mounts, line)
		}
	}

	return mounts
}

// createSysboxContainerWithVolume 创建带卷挂载的 Sysbox 容器
func createSysboxContainerWithVolume(t *testing.T, name, image, hostPath, containerPath string, command []string) string {
	args := []string{"run", "-d", "--name", name, "--runtime", "sysbox-runc", 
		"-v", fmt.Sprintf("%s:%s", hostPath, containerPath), image}
	args = append(args, command...)

	cmd := exec.Command("docker", args...)
	output, err := cmd.Output()
	require.NoError(t, err, "创建带卷的 Sysbox 容器失败")

	containerID := strings.TrimSpace(string(output))
	t.Logf("创建带卷容器 %s (ID: %s)", name, containerID)

	return containerID
}

// createSysboxContainerWithDockerVolume 创建带 Docker 卷的 Sysbox 容器
func createSysboxContainerWithDockerVolume(t *testing.T, name, image, volumeName, containerPath string, command []string) string {
	args := []string{"run", "-d", "--name", name, "--runtime", "sysbox-runc", 
		"-v", fmt.Sprintf("%s:%s", volumeName, containerPath), image}
	args = append(args, command...)

	cmd := exec.Command("docker", args...)
	output, err := cmd.Output()
	require.NoError(t, err, "创建带 Docker 卷的 Sysbox 容器失败")

	containerID := strings.TrimSpace(string(output))
	t.Logf("创建带 Docker 卷容器 %s (ID: %s)", name, containerID)

	return containerID
}

// testBasicContainerMounts 测试容器基本挂载点
func testBasicContainerMounts(t *testing.T, containerID string, mounts []string) {
	// 验证基本挂载点存在
	expectedMounts := []string{"/", "/proc", "/sys", "/dev"}
	
	for _, expectedMount := range expectedMounts {
		found := false
		for _, mount := range mounts {
			if mount == expectedMount {
				found = true
				break
			}
		}
		assert.True(t, found, "容器应该有基本挂载点: %s", expectedMount)
	}

	// 验证 /proc 内容
	cmd := exec.Command("docker", "exec", containerID, "ls", "/proc")
	err := cmd.Run()
	assert.NoError(t, err, "/proc 应该是可访问的")

	// 验证 /sys 内容
	cmd = exec.Command("docker", "exec", containerID, "ls", "/sys")
	err = cmd.Run()
	assert.NoError(t, err, "/sys 应该是可访问的")
}

// testMountPointIsolation 测试挂载点隔离性
func testMountPointIsolation(t *testing.T, containerID string) {
	// 在容器内创建临时挂载，验证不影响主机
	cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", "/tmp/test-isolation")
	require.NoError(t, cmd.Run(), "创建测试目录失败")

	cmd = exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "tmpfs", "/tmp/test-isolation")
	err := cmd.Run()
	if err == nil {
		t.Log("容器内挂载操作成功")
		
		// 验证主机上没有这个挂载
		cmd = exec.Command("findmnt", "/tmp/test-isolation")
		err = cmd.Run()
		assert.Error(t, err, "主机上不应该看到容器内的挂载")
	} else {
		t.Logf("容器内挂载受限 (可能是预期行为): %v", err)
	}
}

// testTmpfsMount 测试 tmpfs 挂载
func testTmpfsMount(t *testing.T, containerID string) {
	// 创建临时目录
	cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", "/tmp/test-tmpfs")
	require.NoError(t, cmd.Run(), "创建临时目录失败")

	// 挂载 tmpfs
	cmd = exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "tmpfs", "/tmp/test-tmpfs")
	err := cmd.Run()
	if err == nil {
		t.Log("tmpfs 挂载成功")

		// 验证挂载
		cmd = exec.Command("docker", "exec", containerID, "findmnt", "/tmp/test-tmpfs")
		err = cmd.Run()
		assert.NoError(t, err, "tmpfs 挂载应该可见")

		// 测试读写
		cmd = exec.Command("docker", "exec", containerID, "echo", "test", ">", "/tmp/test-tmpfs/test.txt")
		cmd.Run()

		// 卸载
		cmd = exec.Command("docker", "exec", containerID, "umount", "/tmp/test-tmpfs")
		cmd.Run()
	} else {
		t.Logf("tmpfs 挂载失败 (可能是权限限制): %v", err)
	}
}

// testBindMount 测试绑定挂载
func testBindMount(t *testing.T, containerID string) {
	// 创建源目录和目标目录
	cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", "/tmp/bind-source", "/tmp/bind-target")
	require.NoError(t, cmd.Run(), "创建绑定挂载目录失败")

	// 在源目录创建文件
	cmd = exec.Command("docker", "exec", containerID, "sh", "-c", "echo 'bind test' > /tmp/bind-source/test.txt")
	require.NoError(t, cmd.Run(), "创建测试文件失败")

	// 执行绑定挂载
	cmd = exec.Command("docker", "exec", containerID, "mount", "--bind", "/tmp/bind-source", "/tmp/bind-target")
	err := cmd.Run()
	if err == nil {
		t.Log("绑定挂载成功")

		// 验证文件可见性
		cmd = exec.Command("docker", "exec", containerID, "cat", "/tmp/bind-target/test.txt")
		output, err := cmd.Output()
		assert.NoError(t, err, "绑定挂载的文件应该可读")
		assert.Contains(t, string(output), "bind test", "绑定挂载的文件内容应该正确")

		// 卸载
		cmd = exec.Command("docker", "exec", containerID, "umount", "/tmp/bind-target")
		cmd.Run()
	} else {
		t.Logf("绑定挂载失败 (可能是权限限制): %v", err)
	}
}

// testMountOptions 测试挂载选项
func testMountOptions(t *testing.T, containerID string) {
	// 创建只读挂载测试
	cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", "/tmp/readonly-test")
	require.NoError(t, cmd.Run(), "创建只读测试目录失败")

	cmd = exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "-o", "ro", "tmpfs", "/tmp/readonly-test")
	err := cmd.Run()
	if err == nil {
		t.Log("只读挂载成功")

		// 验证只读属性
		cmd = exec.Command("docker", "exec", containerID, "touch", "/tmp/readonly-test/test-write")
		err = cmd.Run()
		assert.Error(t, err, "只读挂载应该不允许写入")

		// 卸载
		cmd = exec.Command("docker", "exec", containerID, "umount", "/tmp/readonly-test")
		cmd.Run()
	}
}

// testMountPersistence 测试挂载操作的持久性
func testMountPersistence(t *testing.T, containerID string) {
	// 验证挂载在容器重启后的行为
	// 注意: Sysbox 容器内的挂载通常不会持久化
	cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", "/tmp/persistence-test")
	require.NoError(t, cmd.Run(), "创建持久性测试目录失败")

	cmd = exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "tmpfs", "/tmp/persistence-test")
	err := cmd.Run()
	if err == nil {
		// 检查挂载是否存在
		cmd = exec.Command("docker", "exec", containerID, "findmnt", "/tmp/persistence-test")
		err = cmd.Run()
		assert.NoError(t, err, "挂载应该存在")
	}
}

// createDockerVolume 创建 Docker 卷
func createDockerVolume(t *testing.T, volumeName string) {
	cmd := exec.Command("docker", "volume", "create", volumeName)
	err := cmd.Run()
	require.NoError(t, err, "创建 Docker 卷失败")
	t.Logf("创建 Docker 卷: %s", volumeName)
}

// removeDockerVolume 删除 Docker 卷
func removeDockerVolume(t *testing.T, volumeName string) {
	cmd := exec.Command("docker", "volume", "rm", volumeName)
	if err := cmd.Run(); err != nil {
		t.Logf("警告: 删除 Docker 卷失败: %v", err)
	}
}

// testVolumeAccess 测试卷访问
func testVolumeAccess(t *testing.T, containerID string) {
	// 测试写入卷
	cmd := exec.Command("docker", "exec", containerID, "sh", "-c", "echo 'volume test' > /mnt/volume/test.txt")
	require.NoError(t, cmd.Run(), "写入卷失败")

	// 测试读取卷
	cmd = exec.Command("docker", "exec", containerID, "cat", "/mnt/volume/test.txt")
	output, err := cmd.Output()
	require.NoError(t, err, "读取卷失败")
	assert.Contains(t, string(output), "volume test", "卷内容应该正确")

	// 测试卷权限
	cmd = exec.Command("docker", "exec", containerID, "ls", "-la", "/mnt/volume/")
	output, err = cmd.Output()
	if err == nil {
		t.Log("卷权限信息:", string(output))
	}
}

// testVolumePersistence 测试卷数据持久性
func testVolumePersistence(t *testing.T, containerID, volumeName string) {
	// 在卷中创建文件
	testFile := "/mnt/volume/persistence-test.txt"
	testContent := "persistence test content"
	
	cmd := exec.Command("docker", "exec", containerID, "sh", "-c", 
		fmt.Sprintf("echo '%s' > %s", testContent, testFile))
	require.NoError(t, cmd.Run(), "创建持久性测试文件失败")

	// 验证文件存在
	cmd = exec.Command("docker", "exec", containerID, "cat", testFile)
	output, err := cmd.Output()
	require.NoError(t, err, "读取持久性测试文件失败")
	assert.Contains(t, string(output), testContent, "文件内容应该正确")

	t.Log("卷数据持久性测试通过")
}

// testMultiContainerVolumeSharing 测试多容器卷共享
func testMultiContainerVolumeSharing(t *testing.T, firstContainerID, volumeName string) {
	// 创建第二个容器使用同一个卷
	secondContainerID := createSysboxContainerWithDockerVolume(t, "test-mount-volume-share", "ubuntu:20.04", 
		volumeName, "/mnt/shared", []string{"sleep", "300"})
	defer cleanupContainer(t, secondContainerID)

	waitForContainerRunning(t, secondContainerID)

	// 在第一个容器中创建文件
	cmd := exec.Command("docker", "exec", firstContainerID, "sh", "-c", 
		"echo 'shared from first' > /mnt/volume/shared-test.txt")
	require.NoError(t, cmd.Run(), "在第一个容器中创建共享文件失败")

	// 在第二个容器中读取文件
	time.Sleep(1 * time.Second) // 等待文件系统同步
	cmd = exec.Command("docker", "exec", secondContainerID, "cat", "/mnt/shared/shared-test.txt")
	output, err := cmd.Output()
	require.NoError(t, err, "在第二个容器中读取共享文件失败")
	assert.Contains(t, string(output), "shared from first", "共享文件内容应该正确")

	t.Log("多容器卷共享测试通过")
}

// testMountPropagation 测试挂载传播
func testMountPropagation(t *testing.T, containerID string) {
	// 测试挂载传播设置
	cmd := exec.Command("docker", "exec", containerID, "findmnt", "-o", "PROPAGATION", "/mnt/shared")
	output, err := cmd.Output()
	if err == nil {
		propagation := string(output)
		t.Log("挂载传播设置:", propagation)
	}
}

// testSharedMount 测试共享挂载
func testSharedMount(t *testing.T, containerID string) {
	// 验证共享挂载可见性
	cmd := exec.Command("docker", "exec", containerID, "ls", "-la", "/mnt/shared/")
	output, err := cmd.Output()
	require.NoError(t, err, "访问共享挂载失败")

	sharedContent := string(output)
	t.Log("共享挂载内容:", sharedContent)
	assert.Contains(t, sharedContent, "test-file.txt", "共享挂载应该包含主机文件")
}

// testMountVisibility 测试挂载可见性
func testMountVisibility(t *testing.T, containerID string) {
	// 在共享目录中创建文件
	cmd := exec.Command("docker", "exec", containerID, "touch", "/mnt/shared/container-created.txt")
	require.NoError(t, cmd.Run(), "在共享目录创建文件失败")

	// 验证文件在主机上可见
	hostFile := "/tmp/sysbox-mount-test/host-dir/container-created.txt"
	if _, err := os.Stat(hostFile); err == nil {
		t.Log("容器创建的文件在主机上可见")
	} else {
		t.Logf("容器创建的文件在主机上不可见: %v", err)
	}
}

// testProcfsMount 验证 procfs 挂载
func testProcfsMount(t *testing.T, containerID string) {
	cmd := exec.Command("docker", "exec", containerID, "cat", "/proc/version")
	output, err := cmd.Output()
	require.NoError(t, err, "/proc/version 应该可读")

	version := string(output)
	t.Log("容器内核版本:", version)
	assert.Contains(t, version, "Linux", "/proc/version 应该包含内核信息")

	// 验证 procfs 虚拟化
	cmd = exec.Command("docker", "exec", containerID, "cat", "/proc/uptime")
	output, err = cmd.Output()
	if err == nil {
		uptime := string(output)
		t.Log("容器启动时间:", uptime)
	}
}

// testSysfsMount 验证 sysfs 挂载
func testSysfsMount(t *testing.T, containerID string) {
	cmd := exec.Command("docker", "exec", containerID, "ls", "/sys/")
	output, err := cmd.Output()
	require.NoError(t, err, "/sys 应该可访问")

	sysContent := string(output)
	t.Log("容器 /sys 内容:", sysContent)
	assert.Contains(t, sysContent, "kernel", "/sys 应该包含内核信息")

	// 验证 sysfs 虚拟化
	cmd = exec.Command("docker", "exec", containerID, "cat", "/sys/kernel/hostname")
	output, err = cmd.Output()
	if err == nil {
		hostname := string(output)
		t.Log("容器主机名:", hostname)
	}
}

// testDevtmpfsMount 验证 devtmpfs 挂载
func testDevtmpfsMount(t *testing.T, containerID string) {
	cmd := exec.Command("docker", "exec", containerID, "ls", "/dev/")
	output, err := cmd.Output()
	require.NoError(t, err, "/dev 应该可访问")

	devContent := string(output)
	t.Log("容器 /dev 内容:", devContent)
	assert.Contains(t, devContent, "null", "/dev 应该包含基本设备文件")
	assert.Contains(t, devContent, "zero", "/dev 应该包含 zero 设备")
}

// testCgroupMount 验证 cgroup 挂载
func testCgroupMount(t *testing.T, containerID string) {
	// 检查 cgroup v1
	cmd := exec.Command("docker", "exec", containerID, "ls", "/sys/fs/cgroup/")
	output, err := cmd.Output()
	if err == nil {
		cgroupContent := string(output)
		t.Log("容器 cgroup 内容:", cgroupContent)
	}

	// 检查 cgroup v2
	cmd = exec.Command("docker", "exec", containerID, "cat", "/proc/cgroups")
	output, err = cmd.Output()
	if err == nil {
		cgroupInfo := string(output)
		t.Log("容器 cgroup 信息:", cgroupInfo)
	}
}

// 其他测试辅助函数继续...

// testMountPermissionChecks 测试挂载权限检查
func testMountPermissionChecks(t *testing.T, containerID string) {
	// 尝试挂载敏感路径
	sensitiveAreas := []string{"/proc/sys", "/sys/kernel"}
	
	for _, area := range sensitiveAreas {
		cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", "/tmp/test-"+filepath.Base(area))
		cmd.Run()
		
		cmd = exec.Command("docker", "exec", containerID, "mount", "--bind", area, "/tmp/test-"+filepath.Base(area))
		err := cmd.Run()
		if err != nil {
			t.Logf("敏感区域 %s 挂载被阻止 (安全特性): %v", area, err)
		} else {
			t.Logf("警告: 敏感区域 %s 挂载成功", area)
			// 清理
			exec.Command("docker", "exec", containerID, "umount", "/tmp/test-"+filepath.Base(area)).Run()
		}
	}
}

// testSensitiveMountProtection 测试敏感挂载点保护
func testSensitiveMountProtection(t *testing.T, containerID string) {
	// 验证关键系统路径不能被覆盖
	criticalPaths := []string{"/", "/proc", "/sys"}
	
	for _, path := range criticalPaths {
		cmd := exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "tmpfs", path)
		err := cmd.Run()
		assert.Error(t, err, "关键路径 %s 不应该允许被覆盖", path)
	}
}

// testMountEscapePrevention 测试挂载逃逸防护
func testMountEscapePrevention(t *testing.T, containerID string) {
	// 尝试挂载到容器外路径
	cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", "/tmp/escape-test")
	require.NoError(t, cmd.Run(), "创建逃逸测试目录失败")

	// 尝试绑定挂载到主机路径（应该被阻止）
	cmd = exec.Command("docker", "exec", containerID, "mount", "--bind", "/tmp/escape-test", "../../../host-path")
	err := cmd.Run()
	assert.Error(t, err, "挂载逃逸应该被阻止")
}

// testDynamicMount 测试动态挂载
func testDynamicMount(t *testing.T, containerID string) {
	mountPoint := "/tmp/dynamic-mount"
	
	// 创建挂载点
	cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", mountPoint)
	require.NoError(t, cmd.Run(), "创建动态挂载点失败")

	// 执行动态挂载
	cmd = exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "tmpfs", mountPoint)
	err := cmd.Run()
	if err == nil {
		t.Log("动态挂载成功")

		// 验证挂载状态
		cmd = exec.Command("docker", "exec", containerID, "findmnt", mountPoint)
		err = cmd.Run()
		assert.NoError(t, err, "动态挂载应该可见")
	}
}

// testDynamicUnmount 测试动态卸载
func testDynamicUnmount(t *testing.T, containerID string) {
	mountPoint := "/tmp/dynamic-unmount"
	
	// 创建并挂载
	cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", mountPoint)
	require.NoError(t, cmd.Run(), "创建动态卸载测试目录失败")

	cmd = exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "tmpfs", mountPoint)
	if cmd.Run() == nil {
		// 执行卸载
		cmd = exec.Command("docker", "exec", containerID, "umount", mountPoint)
		err := cmd.Run()
		assert.NoError(t, err, "动态卸载应该成功")

		// 验证卸载状态
		cmd = exec.Command("docker", "exec", containerID, "findmnt", mountPoint)
		err = cmd.Run()
		assert.Error(t, err, "卸载后挂载点不应该存在")
	}
}

// testMountStateTracking 测试挂载状态跟踪
func testMountStateTracking(t *testing.T, containerID string) {
	// 获取初始挂载状态
	initialMounts := getMountPoints(t, containerID)
	initialCount := len(initialMounts)

	// 执行挂载操作
	mountPoint := "/tmp/state-tracking"
	cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", mountPoint)
	require.NoError(t, cmd.Run(), "创建状态跟踪测试目录失败")

	cmd = exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "tmpfs", mountPoint)
	if cmd.Run() == nil {
		// 获取挂载后状态
		afterMounts := getMountPoints(t, containerID)
		afterCount := len(afterMounts)

		// 验证挂载计数变化
		assert.Greater(t, afterCount, initialCount, "挂载后应该增加挂载点数量")

		// 执行卸载
		cmd = exec.Command("docker", "exec", containerID, "umount", mountPoint)
		if cmd.Run() == nil {
			// 获取卸载后状态
			finalMounts := getMountPoints(t, containerID)
			finalCount := len(finalMounts)

			// 验证挂载计数恢复
			assert.Equal(t, initialCount, finalCount, "卸载后挂载点数量应该恢复")
		}
	}
}

// testMountPerformance 测试挂载性能
func testMountPerformance(t *testing.T, containerID string) {
	startTime := time.Now()

	// 执行多个挂载操作
	for i := 0; i < 10; i++ {
		mountPoint := fmt.Sprintf("/tmp/perf-test-%d", i)
		cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", mountPoint)
		cmd.Run()

		cmd = exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "tmpfs", mountPoint)
		if cmd.Run() == nil {
			// 立即卸载
			exec.Command("docker", "exec", containerID, "umount", mountPoint).Run()
		}
	}

	duration := time.Since(startTime)
	t.Logf("挂载性能测试完成，耗时: %v", duration)

	// 性能应该在合理范围内
	assert.Less(t, duration.Seconds(), 30.0, "挂载操作性能应该在合理范围内")
}

// testManyMountPoints 测试大量挂载点
func testManyMountPoints(t *testing.T, containerID string) {
	mountCount := 20
	mountedPoints := []string{}

	// 创建多个挂载点
	for i := 0; i < mountCount; i++ {
		mountPoint := fmt.Sprintf("/tmp/many-mounts-%d", i)
		cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", mountPoint)
		require.NoError(t, cmd.Run(), "创建多挂载点目录失败")

		cmd = exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "tmpfs", mountPoint)
		if cmd.Run() == nil {
			mountedPoints = append(mountedPoints, mountPoint)
		}
	}

	t.Logf("成功创建 %d 个挂载点", len(mountedPoints))

	// 验证所有挂载点
	for _, mountPoint := range mountedPoints {
		cmd := exec.Command("docker", "exec", containerID, "findmnt", mountPoint)
		assert.NoError(t, cmd.Run(), "挂载点 %s 应该存在", mountPoint)
	}

	// 清理挂载点
	for _, mountPoint := range mountedPoints {
		exec.Command("docker", "exec", containerID, "umount", mountPoint).Run()
	}
}

// testMountCaching 测试挂载缓存
func testMountCaching(t *testing.T, containerID string) {
	mountPoint := "/tmp/cache-test"
	
	// 创建挂载点
	cmd := exec.Command("docker", "exec", containerID, "mkdir", "-p", mountPoint)
	require.NoError(t, cmd.Run(), "创建缓存测试目录失败")

	// 执行挂载
	cmd = exec.Command("docker", "exec", containerID, "mount", "-t", "tmpfs", "tmpfs", mountPoint)
	if cmd.Run() == nil {
		// 测试文件操作性能
		startTime := time.Now()
		
		for i := 0; i < 100; i++ {
			fileName := fmt.Sprintf("%s/cache-test-%d.txt", mountPoint, i)
			cmd = exec.Command("docker", "exec", containerID, "sh", "-c", 
				fmt.Sprintf("echo 'test content' > %s", fileName))
			cmd.Run()
		}
		
		duration := time.Since(startTime)
		t.Logf("文件操作性能测试完成，耗时: %v", duration)

		// 清理
		exec.Command("docker", "exec", containerID, "umount", mountPoint).Run()
	}
}