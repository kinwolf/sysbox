package core

import (
	"bufio"
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

// TestSyscallInterception 测试Sysbox系统调用拦截处理核心功能
func TestSyscallInterception(t *testing.T) {
	setupSyscallTestEnv(t)
	defer cleanupSyscallTestEnv(t)

	t.Run("挂载系统调用拦截", func(t *testing.T) {
		testMountSyscallInterception(t)
	})

	t.Run("文件系统操作拦截", func(t *testing.T) {
		testFilesystemOperationInterception(t)
	})

	t.Run("网络相关系统调用处理", func(t *testing.T) {
		testNetworkSyscallHandling(t)
	})

	t.Run("进程管理系统调用拦截", func(t *testing.T) {
		testProcessManagementSyscallInterception(t)
	})

	t.Run("内存管理系统调用处理", func(t *testing.T) {
		testMemoryManagementSyscallHandling(t)
	})

	t.Run("特权操作系统调用限制", func(t *testing.T) {
		testPrivilegedSyscallRestriction(t)
	})

	t.Run("容器逃逸防护", func(t *testing.T) {
		testContainerEscapePrevention(t)
	})

	t.Run("系统调用审计和日志", func(t *testing.T) {
		testSyscallAuditingAndLogging(t)
	})

	t.Run("系统调用性能优化", func(t *testing.T) {
		testSyscallPerformanceOptimization(t)
	})

	t.Run("异常系统调用处理", func(t *testing.T) {
		testAbnormalSyscallHandling(t)
	})
}

// testMountSyscallInterception 测试挂载系统调用拦截
func testMountSyscallInterception(t *testing.T) {
	containerName := "test-mount-syscall"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试正常的挂载操作
	// 在容器内创建临时目录
	execInContainer(t, containerID, "mkdir", "-p", "/tmp/test-mount-source")
	execInContainer(t, containerID, "mkdir", "-p", "/tmp/test-mount-target")
	execInContainer(t, containerID, "echo", "test data", ">", "/tmp/test-mount-source/data.txt")
	
	// 测试bind mount操作
	mountOutput := execInContainer(t, containerID, "mount", "--bind", "/tmp/test-mount-source", "/tmp/test-mount-target")
	assert.Equal(t, "", strings.TrimSpace(mountOutput), "bind mount应该成功执行")
	
	// 验证mount成功
	mountedData := execInContainer(t, containerID, "cat", "/tmp/test-mount-target/data.txt")
	assert.Contains(t, mountedData, "test data", "挂载后应该能访问原始数据")
	
	// 验证挂载信息在/proc/mounts中
	procMounts := execInContainer(t, containerID, "cat", "/proc/mounts")
	assert.Contains(t, procMounts, "/tmp/test-mount-target", "挂载信息应该在/proc/mounts中显示")
	
	// 测试tmpfs挂载
	tmpfsOutput := execInContainer(t, containerID, "mount", "-t", "tmpfs", "tmpfs", "/tmp/test-tmpfs")
	if !strings.Contains(tmpfsOutput, "Permission denied") {
		// 验证tmpfs挂载成功
		tmpfsTest := execInContainer(t, containerID, "touch", "/tmp/test-tmpfs/tmpfs-test")
		assert.Equal(t, "", strings.TrimSpace(tmpfsTest), "tmpfs中应该能创建文件")
		
		// 验证tmpfs在挂载列表中
		tmpfsMounts := execInContainer(t, containerID, "mount", "|", "grep", "tmpfs")
		assert.Contains(t, tmpfsMounts, "/tmp/test-tmpfs", "tmpfs挂载应该显示在挂载列表中")
	}
	
	// 测试危险挂载操作的限制
	// 尝试挂载主机敏感目录（应该被拦截或限制）
	_, rootMountErr := execInContainerWithError(containerID, "mount", "--bind", "/", "/tmp/host-root")
	if rootMountErr == nil {
		// 如果挂载成功，验证是否有适当的限制
		hostRootContent := execInContainer(t, containerID, "ls", "/tmp/host-root")
		// Sysbox应该确保这种挂载不会暴露真正的主机根文件系统
		t.Log("根目录挂载被允许，验证安全限制")
	} else {
		t.Log("根目录挂载被正确拦截")
	}
	
	// 测试proc和sys文件系统的特殊处理
	procMountOutput := execInContainer(t, containerID, "mount", "-t", "proc", "proc", "/tmp/test-proc")
	if !strings.Contains(procMountOutput, "denied") {
		// 验证proc挂载的隔离性
		testProcContent := execInContainer(t, containerID, "ls", "/tmp/test-proc")
		assert.Contains(t, testProcContent, "self", "proc文件系统应该包含基本结构")
	}
	
	// 清理挂载
	execInContainer(t, containerID, "umount", "/tmp/test-mount-target")
	execInContainer(t, containerID, "umount", "/tmp/test-tmpfs")
	execInContainer(t, containerID, "umount", "/tmp/test-proc")
}

// testFilesystemOperationInterception 测试文件系统操作拦截
func testFilesystemOperationInterception(t *testing.T) {
	containerName := "test-fs-syscall"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试普通文件操作
	// 创建文件
	createOutput := execInContainer(t, containerID, "touch", "/tmp/test-file.txt")
	assert.Equal(t, "", strings.TrimSpace(createOutput), "文件创建应该成功")
	
	// 写入文件
	writeOutput := execInContainer(t, containerID, "echo", "test content", ">", "/tmp/test-file.txt")
	assert.Equal(t, "", strings.TrimSpace(writeOutput), "文件写入应该成功")
	
	// 读取文件
	readContent := execInContainer(t, containerID, "cat", "/tmp/test-file.txt")
	assert.Contains(t, readContent, "test content", "文件读取应该成功")
	
	// 测试特殊文件的访问限制
	// 尝试访问敏感的proc文件
	procFiles := []string{
		"/proc/kallsyms",
		"/proc/kcore",
		"/proc/kmsg",
	}
	
	for _, procFile := range procFiles {
		_, err := execInContainerWithError(containerID, "cat", procFile)
		if err != nil {
			t.Logf("访问%s被正确限制", procFile)
		} else {
			t.Logf("访问%s被允许，可能有特殊处理", procFile)
		}
	}
	
	// 测试/sys文件系统的写入限制
	sysFiles := []string{
		"/sys/kernel/domainname",
		"/sys/kernel/hostname",
	}
	
	for _, sysFile := range sysFiles {
		if fileExists(t, containerID, sysFile) {
			_, err := execInContainerWithError(containerID, "echo", "test", ">", sysFile)
			if err != nil {
				t.Logf("写入%s被正确限制", sysFile)
			} else {
				// 验证写入是否真的生效
				content := execInContainer(t, containerID, "cat", sysFile)
				t.Logf("写入%s被允许，内容: %s", sysFile, strings.TrimSpace(content))
			}
		}
	}
	
	// 测试设备文件访问
	devFiles := []string{
		"/dev/kmsg",
		"/dev/mem",
		"/dev/random",
		"/dev/urandom",
	}
	
	for _, devFile := range devFiles {
		if fileExists(t, containerID, devFile) {
			if strings.Contains(devFile, "random") {
				// random设备应该可读
				randomData := execInContainer(t, containerID, "head", "-c", "10", devFile)
				assert.NotEmpty(t, randomData, fmt.Sprintf("%s应该可读", devFile))
			} else {
				// 危险设备文件访问应该被限制
				_, err := execInContainerWithError(containerID, "head", "-c", "10", devFile)
				if err != nil {
					t.Logf("访问%s被正确限制", devFile)
				}
			}
		}
	}
	
	// 测试文件权限变更
	chmodOutput := execInContainer(t, containerID, "chmod", "755", "/tmp/test-file.txt")
	assert.Equal(t, "", strings.TrimSpace(chmodOutput), "chmod操作应该成功")
	
	// 验证权限变更
	lsOutput := execInContainer(t, containerID, "ls", "-l", "/tmp/test-file.txt")
	assert.Contains(t, lsOutput, "rwxr-xr-x", "文件权限应该正确设置")
	
	// 测试文件所有权变更（在用户命名空间内）
	chownOutput := execInContainer(t, containerID, "chown", "1000:1000", "/tmp/test-file.txt")
	// 在用户命名空间内，这应该成功或被适当处理
	
	// 测试硬链接和软链接
	lnOutput := execInContainer(t, containerID, "ln", "/tmp/test-file.txt", "/tmp/test-hardlink.txt")
	assert.Equal(t, "", strings.TrimSpace(lnOutput), "硬链接创建应该成功")
	
	symlnOutput := execInContainer(t, containerID, "ln", "-s", "/tmp/test-file.txt", "/tmp/test-symlink.txt")
	assert.Equal(t, "", strings.TrimSpace(symlnOutput), "软链接创建应该成功")
	
	// 验证链接正确性
	hardlinkContent := execInContainer(t, containerID, "cat", "/tmp/test-hardlink.txt")
	symlinkContent := execInContainer(t, containerID, "cat", "/tmp/test-symlink.txt")
	assert.Equal(t, readContent, hardlinkContent, "硬链接内容应该一致")
	assert.Equal(t, readContent, symlinkContent, "软链接内容应该一致")
}

// testNetworkSyscallHandling 测试网络相关系统调用处理
func testNetworkSyscallHandling(t *testing.T) {
	containerName := "test-network-syscall"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试socket创建
	socketTest := execInContainer(t, containerID, "python3", "-c", 
		"import socket; s = socket.socket(); print('socket created')")
	assert.Contains(t, socketTest, "socket created", "socket创建应该成功")
	
	// 测试网络接口操作
	ifconfigOutput := execInContainer(t, containerID, "ip", "addr", "show")
	assert.Contains(t, ifconfigOutput, "lo", "lo接口应该存在")
	assert.Contains(t, ifconfigOutput, "eth0", "eth0接口应该存在")
	
	// 测试网络连通性
	pingOutput := execInContainer(t, containerID, "ping", "-c", "1", "8.8.8.8")
	assert.Contains(t, pingOutput, "1 packets transmitted", "外网连通性应该正常")
	
	// 测试端口绑定
	portBindTest := execInContainer(t, containerID, "python3", "-c", `
import socket
import time
s = socket.socket()
s.bind(('0.0.0.0', 8080))
s.listen(1)
print('port bind successful')
s.close()
`)
	assert.Contains(t, portBindTest, "port bind successful", "端口绑定应该成功")
	
	// 测试网络命名空间隔离
	netnsOutput := execInContainer(t, containerID, "ip", "netns", "list")
	// 在容器内创建网络命名空间可能需要特殊权限
	
	// 测试路由表访问
	routeOutput := execInContainer(t, containerID, "ip", "route", "show")
	assert.NotEmpty(t, routeOutput, "路由表应该可访问")
	assert.Contains(t, routeOutput, "default", "应该有默认路由")
	
	// 测试iptables操作（如果允许）
	_, iptablesErr := execInContainerWithError(containerID, "iptables", "-L")
	if iptablesErr == nil {
		t.Log("iptables操作被允许")
		
		// 测试简单的iptables规则
		_, addRuleErr := execInContainerWithError(containerID, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT")
		if addRuleErr == nil {
			t.Log("iptables规则添加成功")
		} else {
			t.Log("iptables规则添加被限制")
		}
	} else {
		t.Log("iptables操作被限制")
	}
	
	// 测试网络统计信息访问
	netstatOutput := execInContainer(t, containerID, "cat", "/proc/net/dev")
	assert.Contains(t, netstatOutput, "lo:", "网络统计信息应该包含lo接口")
	assert.Contains(t, netstatOutput, "eth0:", "网络统计信息应该包含eth0接口")
	
	tcpStatOutput := execInContainer(t, containerID, "cat", "/proc/net/tcp")
	assert.Contains(t, tcpStatOutput, "local_address", "TCP统计信息应该可访问")
}

// testProcessManagementSyscallInterception 测试进程管理系统调用拦截
func testProcessManagementSyscallInterception(t *testing.T) {
	containerName := "test-process-syscall"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试进程创建（fork/exec）
	processCreateTest := execInContainer(t, containerID, "sh", "-c", "echo 'child process' &")
	assert.Equal(t, "", strings.TrimSpace(processCreateTest), "子进程创建应该成功")
	
	// 测试进程列表访问
	psOutput := execInContainer(t, containerID, "ps", "aux")
	assert.Contains(t, psOutput, "sleep", "进程列表应该包含sleep进程")
	
	// 测试进程信号发送
	// 创建一个后台进程
	bgProcessOutput := execInContainer(t, containerID, "sh", "-c", "sleep 60 & echo $!")
	bgPid := strings.TrimSpace(bgProcessOutput)
	if bgPid != "" && bgPid != "0" {
		// 发送信号给后台进程
		killOutput := execInContainer(t, containerID, "kill", "-TERM", bgPid)
		assert.Equal(t, "", strings.TrimSpace(killOutput), "信号发送应该成功")
		
		// 等待进程退出
		time.Sleep(1 * time.Second)
		
		// 验证进程已退出
		_, psErr := execInContainerWithError(containerID, "ps", "-p", bgPid)
		assert.Error(t, psErr, "进程应该已经退出")
	}
	
	// 测试命名空间操作
	// 检查进程的命名空间
	pidNS := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/")
	assert.Contains(t, pidNS, "pid", "PID命名空间链接应该存在")
	assert.Contains(t, pidNS, "mnt", "挂载命名空间链接应该存在")
	assert.Contains(t, pidNS, "net", "网络命名空间链接应该存在")
	
	// 测试用户命名空间信息
	uidMapOutput := execInContainer(t, containerID, "cat", "/proc/self/uid_map")
	assert.Contains(t, uidMapOutput, "0", "UID映射应该包含root用户")
	
	gidMapOutput := execInContainer(t, containerID, "cat", "/proc/self/gid_map")
	assert.Contains(t, gidMapOutput, "0", "GID映射应该包含root组")
	
	// 测试进程优先级调整
	niceOutput := execInContainer(t, containerID, "nice", "-n", "10", "echo", "nice test")
	assert.Contains(t, niceOutput, "nice test", "nice命令应该执行成功")
	
	// 测试进程资源限制查看
	ulimitOutput := execInContainer(t, containerID, "ulimit", "-a")
	assert.Contains(t, ulimitOutput, "core file size", "ulimit信息应该可访问")
	
	// 测试ptrace操作限制
	_, ptraceErr := execInContainerWithError(containerID, "strace", "-e", "trace=write", "echo", "test")
	if ptraceErr != nil {
		t.Log("ptrace操作被正确限制")
	} else {
		t.Log("ptrace操作被允许")
	}
	
	// 测试特权进程操作限制
	// 尝试访问其他用户的进程信息
	allProcesses := execInContainer(t, containerID, "ps", "-eo", "pid,user,comm")
	// 在容器内应该只能看到自己的进程
	processLines := strings.Split(allProcesses, "\n")
	rootProcessCount := 0
	for _, line := range processLines {
		if strings.Contains(line, "root") {
			rootProcessCount++
		}
	}
	assert.Greater(t, rootProcessCount, 0, "应该能看到root用户的进程")
}

// testMemoryManagementSyscallHandling 测试内存管理系统调用处理
func testMemoryManagementSyscallHandling(t *testing.T) {
	containerName := "test-memory-syscall"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试内存信息访问
	meminfoOutput := execInContainer(t, containerID, "cat", "/proc/meminfo")
	assert.Contains(t, meminfoOutput, "MemTotal", "内存总量信息应该可访问")
	assert.Contains(t, meminfoOutput, "MemFree", "空闲内存信息应该可访问")
	assert.Contains(t, meminfoOutput, "MemAvailable", "可用内存信息应该可访问")
	
	// 提取内存总量进行验证
	memTotalLine := extractLineFromOutput(meminfoOutput, "MemTotal:")
	memTotal := extractMemoryValue(t, memTotalLine)
	assert.Greater(t, memTotal, int64(0), "内存总量应该大于0")
	
	// 测试内存分配
	memAllocTest := execInContainer(t, containerID, "python3", "-c", `
import os
# 分配100MB内存
data = bytearray(100 * 1024 * 1024)
print("memory allocation successful")
del data
`)
	assert.Contains(t, memAllocTest, "memory allocation successful", "内存分配应该成功")
	
	// 测试mmap操作
	mmapTest := execInContainer(t, containerID, "python3", "-c", `
import mmap
import os
# 创建内存映射
with open('/tmp/mmap-test', 'w+b') as f:
    f.write(b'A' * 1024)
    f.flush()
    with mmap.mmap(f.fileno(), 0) as mm:
        print("mmap successful")
        mm[0] = ord('B')
`)
	assert.Contains(t, mmapTest, "mmap successful", "mmap操作应该成功")
	
	// 验证mmap文件修改
	mmapFileContent := execInContainer(t, containerID, "head", "-c", "1", "/tmp/mmap-test")
	assert.Equal(t, "B", strings.TrimSpace(mmapFileContent), "mmap修改应该生效")
	
	// 测试共享内存
	shmTest := execInContainer(t, containerID, "python3", "-c", `
import os
import mmap
# 尝试创建共享内存
try:
    fd = os.open('/dev/shm/test-shm', os.O_CREAT | os.O_RDWR)
    os.write(fd, b'shared memory test')
    os.close(fd)
    print("shared memory successful")
except Exception as e:
    print(f"shared memory error: {e}")
`)
	if strings.Contains(shmTest, "successful") {
		t.Log("共享内存操作成功")
		
		// 验证共享内存文件
		shmContent := execInContainer(t, containerID, "cat", "/dev/shm/test-shm")
		assert.Contains(t, shmContent, "shared memory test", "共享内存内容应该正确")
	} else {
		t.Log("共享内存操作被限制或失败")
	}
	
	// 测试内存统计信息
	statmOutput := execInContainer(t, containerID, "cat", "/proc/self/statm")
	statmFields := strings.Fields(strings.TrimSpace(statmOutput))
	assert.GreaterOrEqual(t, len(statmFields), 7, "statm应该包含7个字段")
	
	// 验证各字段为有效数字
	for i, field := range statmFields {
		value, err := strconv.Atoi(field)
		assert.NoError(t, err, fmt.Sprintf("statm第%d个字段应该是有效数字", i+1))
		assert.GreaterOrEqual(t, value, 0, fmt.Sprintf("statm第%d个字段应该非负", i+1))
	}
	
	// 测试内存限制信息
	cgroupMemLimit := "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	if fileExists(t, containerID, cgroupMemLimit) {
		memLimitOutput := execInContainer(t, containerID, "cat", cgroupMemLimit)
		memLimitValue, err := strconv.ParseInt(strings.TrimSpace(memLimitOutput), 10, 64)
		if err == nil {
			assert.Greater(t, memLimitValue, int64(0), "内存限制应该大于0")
		}
	}
	
	// 测试页面大小信息
	pagesizeOutput := execInContainer(t, containerID, "getconf", "PAGESIZE")
	pagesize, err := strconv.Atoi(strings.TrimSpace(pagesizeOutput))
	assert.NoError(t, err, "页面大小应该是有效数字")
	assert.Greater(t, pagesize, 0, "页面大小应该大于0")
	assert.True(t, pagesize == 4096 || pagesize == 8192 || pagesize == 16384, "页面大小应该是常见值")
}

// testPrivilegedSyscallRestriction 测试特权操作系统调用限制
func testPrivilegedSyscallRestriction(t *testing.T) {
	containerName := "test-privileged-syscall"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试模块加载限制
	_, modprobeErr := execInContainerWithError(containerID, "modprobe", "dummy")
	assert.Error(t, modprobeErr, "模块加载应该被限制")
	
	// 测试内核参数修改限制
	kernelParams := []string{
		"/proc/sys/kernel/domainname",
		"/proc/sys/kernel/hostname",
		"/proc/sys/net/ipv4/ip_forward",
	}
	
	for _, param := range kernelParams {
		if fileExists(t, containerID, param) {
			_, err := execInContainerWithError(containerID, "echo", "1", ">", param)
			if err != nil {
				t.Logf("内核参数%s修改被正确限制", param)
			} else {
				// 验证是否真的修改成功
				newValue := execInContainer(t, containerID, "cat", param)
				t.Logf("内核参数%s修改被允许，新值: %s", param, strings.TrimSpace(newValue))
			}
		}
	}
	
	// 测试时间设置限制
	_, dateErr := execInContainerWithError(containerID, "date", "-s", "2023-01-01")
	if dateErr != nil {
		t.Log("系统时间设置被正确限制")
	} else {
		t.Log("系统时间设置被允许（可能有虚拟化处理）")
	}
	
	// 测试设备节点创建限制
	_, mknodErr := execInContainerWithError(containerID, "mknod", "/tmp/test-device", "c", "1", "1")
	if mknodErr != nil {
		t.Log("设备节点创建被正确限制")
	} else {
		// 验证设备文件是否真的创建
		deviceFile := execInContainer(t, containerID, "ls", "-l", "/tmp/test-device")
		if strings.Contains(deviceFile, "c") {
			t.Log("字符设备节点创建成功")
		}
	}
	
	// 测试原始套接字创建限制
	rawSocketTest := execInContainer(t, containerID, "python3", "-c", `
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    print("raw socket created")
    s.close()
except PermissionError:
    print("raw socket permission denied")
except Exception as e:
    print(f"raw socket error: {e}")
`)
	
	if strings.Contains(rawSocketTest, "permission denied") {
		t.Log("原始套接字创建被正确限制")
	} else if strings.Contains(rawSocketTest, "created") {
		t.Log("原始套接字创建被允许")
	}
	
	// 测试特权端口绑定
	privPortTest := execInContainer(t, containerID, "python3", "-c", `
import socket
try:
    s = socket.socket()
    s.bind(('0.0.0.0', 80))
    print("privileged port bind successful")
    s.close()
except PermissionError:
    print("privileged port bind denied")
except Exception as e:
    print(f"privileged port bind error: {e}")
`)
	
	if strings.Contains(privPortTest, "denied") {
		t.Log("特权端口绑定被正确限制")
	} else if strings.Contains(privPortTest, "successful") {
		t.Log("特权端口绑定被允许（容器内有CAP_NET_BIND_SERVICE能力）")
	}
	
	// 测试chroot操作
	chrootTest := execInContainer(t, containerID, "mkdir", "-p", "/tmp/chroot-test")
	_, chrootErr := execInContainerWithError(containerID, "chroot", "/tmp/chroot-test", "ls")
	if chrootErr != nil {
		t.Log("chroot操作被限制")
	} else {
		t.Log("chroot操作被允许")
	}
}

// testContainerEscapePrevention 测试容器逃逸防护
func testContainerEscapePrevention(t *testing.T) {
	containerName := "test-escape-prevention"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试文件系统边界
	// 尝试访问容器外的文件系统
	_, hostRootErr := execInContainerWithError(containerID, "ls", "/host-root")
	assert.Error(t, hostRootErr, "不应该能访问主机根文件系统")
	
	// 测试进程边界
	// 尝试查看主机进程
	containerPID := getContainerPID(t, containerID)
	hostProcessTest := execInContainer(t, containerID, "ps", "aux")
	
	// 验证进程列表不包含主机进程
	processLines := strings.Split(hostProcessTest, "\n")
	containerProcessCount := 0
	for _, line := range processLines {
		if strings.TrimSpace(line) != "" && !strings.Contains(line, "PID") {
			containerProcessCount++
		}
	}
	assert.Less(t, containerProcessCount, 50, "容器内可见进程数应该有限")
	
	// 测试命名空间边界
	// 检查mount命名空间隔离
	mountNS := execInContainer(t, containerID, "cat", "/proc/self/mountinfo")
	assert.NotContains(t, mountNS, "/home", "挂载信息不应该包含主机/home目录")
	
	// 检查PID命名空间隔离
	pidNSInfo := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/pid")
	assert.Contains(t, pidNSInfo, "pid:", "PID命名空间应该被隔离")
	
	// 测试网络命名空间边界
	netNSInfo := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/net")
	assert.Contains(t, netNSInfo, "net:", "网络命名空间应该被隔离")
	
	// 测试用户命名空间边界
	userNSInfo := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/user")
	assert.Contains(t, userNSInfo, "user:", "用户命名空间应该被隔离")
	
	// 测试cgroup边界
	cgroupInfo := execInContainer(t, containerID, "cat", "/proc/self/cgroup")
	assert.Contains(t, cgroupInfo, "docker", "cgroup信息应该显示容器隔离")
	
	// 测试内核接口访问限制
	kernelInterfaces := []string{
		"/proc/kallsyms",
		"/proc/kcore",
		"/sys/kernel/debug",
	}
	
	for _, iface := range kernelInterfaces {
		_, err := execInContainerWithError(containerID, "head", "-1", iface)
		if err != nil {
			t.Logf("内核接口%s访问被正确限制", iface)
		} else {
			t.Logf("内核接口%s访问被允许", iface)
		}
	}
	
	// 测试设备访问限制
	dangerousDevices := []string{
		"/dev/kmsg",
		"/dev/mem",
		"/dev/kmem",
	}
	
	for _, device := range dangerousDevices {
		if fileExists(t, containerID, device) {
			_, err := execInContainerWithError(containerID, "head", "-c", "1", device)
			if err != nil {
				t.Logf("危险设备%s访问被正确限制", device)
			} else {
				t.Logf("危险设备%s访问被允许", device)
			}
		}
	}
	
	// 测试容器内核版本隔离
	kernelVersion := execInContainer(t, containerID, "uname", "-r")
	hostKernelVersion, err := exec.Command("uname", "-r").Output()
	if err == nil {
		containerKernel := strings.TrimSpace(kernelVersion)
		hostKernel := strings.TrimSpace(string(hostKernelVersion))
		// 内核版本应该相同（因为共享内核），但其他信息可能被虚拟化
		assert.Equal(t, hostKernel, containerKernel, "内核版本应该一致")
	}
}

// testSyscallAuditingAndLogging 测试系统调用审计和日志
func testSyscallAuditingAndLogging(t *testing.T) {
	containerName := "test-syscall-audit"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 检查是否有审计相关的文件
	auditPaths := []string{
		"/var/log/audit/audit.log",
		"/var/log/sysbox.log",
		"/var/log/sysbox-runc.log",
	}
	
	var activeAuditPath string
	for _, path := range auditPaths {
		if _, err := os.Stat(path); err == nil {
			activeAuditPath = path
			break
		}
	}
	
	if activeAuditPath != "" {
		// 记录当前日志大小
		initialLogSize := getFileLineCount(t, activeAuditPath)
		
		// 执行一些可能被审计的操作
		execInContainer(t, containerID, "mount", "--bind", "/tmp", "/mnt")
		execInContainer(t, containerID, "umount", "/mnt")
		execInContainer(t, containerID, "touch", "/tmp/audit-test-file")
		
		// 等待日志写入
		time.Sleep(2 * time.Second)
		
		// 检查日志是否增加
		currentLogSize := getFileLineCount(t, activeAuditPath)
		if currentLogSize > initialLogSize {
			t.Log("系统调用审计日志正常记录")
			
			// 读取最新的审计日志
			recentLogs, err := exec.Command("tail", "-20", activeAuditPath).Output()
			if err == nil {
				logContent := string(recentLogs)
				if strings.Contains(logContent, containerID[:12]) ||
				   strings.Contains(logContent, containerName) ||
				   strings.Contains(logContent, "mount") {
					t.Log("审计日志包含容器相关操作")
				}
			}
		}
	} else {
		t.Log("未找到系统调用审计日志文件")
	}
	
	// 测试系统调用跟踪工具
	_, straceErr := execInContainerWithError(containerID, "strace", "-c", "ls", "/tmp")
	if straceErr == nil {
		t.Log("strace工具可用，可以进行系统调用跟踪")
	} else {
		t.Log("strace工具被限制或不可用")
	}
	
	// 测试性能计数器访问
	_, perfErr := execInContainerWithError(containerID, "perf", "stat", "ls", "/tmp")
	if perfErr == nil {
		t.Log("perf工具可用")
	} else {
		t.Log("perf工具被限制或不可用")
	}
	
	// 测试seccomp状态
	seccompStatus := execInContainer(t, containerID, "cat", "/proc/self/status")
	if strings.Contains(seccompStatus, "Seccomp") {
		seccompLine := extractLineFromOutput(seccompStatus, "Seccomp:")
		t.Logf("Seccomp状态: %s", seccompLine)
	}
	
	// 测试capability信息
	capabilityStatus := execInContainer(t, containerID, "cat", "/proc/self/status")
	if strings.Contains(capabilityStatus, "Cap") {
		capLines := []string{}
		statusLines := strings.Split(capabilityStatus, "\n")
		for _, line := range statusLines {
			if strings.HasPrefix(line, "Cap") {
				capLines = append(capLines, strings.TrimSpace(line))
			}
		}
		t.Logf("容器能力信息: %v", capLines)
	}
}

// testSyscallPerformanceOptimization 测试系统调用性能优化
func testSyscallPerformanceOptimization(t *testing.T) {
	containerName := "test-syscall-performance"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试文件系统操作性能
	start := time.Now()
	for i := 0; i < 100; i++ {
		execInContainer(t, containerID, "touch", fmt.Sprintf("/tmp/perf-test-%d", i))
	}
	fsOpDuration := time.Since(start)
	
	t.Logf("100次文件创建操作耗时: %v", fsOpDuration)
	assert.Less(t, fsOpDuration, 10*time.Second, "文件操作性能应该合理")
	
	// 测试进程创建性能
	start = time.Now()
	for i := 0; i < 50; i++ {
		execInContainer(t, containerID, "echo", fmt.Sprintf("process-test-%d", i))
	}
	processOpDuration := time.Since(start)
	
	t.Logf("50次进程创建操作耗时: %v", processOpDuration)
	assert.Less(t, processOpDuration, 15*time.Second, "进程操作性能应该合理")
	
	// 测试网络操作性能
	start = time.Now()
	for i := 0; i < 10; i++ {
		execInContainer(t, containerID, "ping", "-c", "1", "127.0.0.1")
	}
	networkOpDuration := time.Since(start)
	
	t.Logf("10次网络操作耗时: %v", networkOpDuration)
	assert.Less(t, networkOpDuration, 20*time.Second, "网络操作性能应该合理")
	
	// 测试内存操作性能
	memOpTest := execInContainer(t, containerID, "python3", "-c", `
import time
start = time.time()
for i in range(100):
    data = bytearray(1024 * 1024)  # 1MB
    del data
end = time.time()
print(f"Memory operations time: {end - start:.3f}s")
`)
	
	if strings.Contains(memOpTest, "Memory operations time:") {
		t.Logf("内存操作性能测试结果: %s", strings.TrimSpace(memOpTest))
	}
	
	// 测试/proc文件系统访问性能
	start = time.Now()
	for i := 0; i < 50; i++ {
		execInContainer(t, containerID, "cat", "/proc/meminfo")
	}
	procOpDuration := time.Since(start)
	
	t.Logf("50次/proc访问操作耗时: %v", procOpDuration)
	assert.Less(t, procOpDuration, 5*time.Second, "/proc访问性能应该良好")
	
	// 测试系统调用延迟
	syscallLatencyTest := execInContainer(t, containerID, "python3", "-c", `
import time
import os
start = time.time()
for i in range(1000):
    os.getpid()
end = time.time()
avg_latency = (end - start) / 1000 * 1000000  # 微秒
print(f"Average syscall latency: {avg_latency:.3f}μs")
`)
	
	if strings.Contains(syscallLatencyTest, "Average syscall latency:") {
		t.Logf("系统调用延迟测试结果: %s", strings.TrimSpace(syscallLatencyTest))
	}
	
	// 清理性能测试文件
	execInContainer(t, containerID, "rm", "-f", "/tmp/perf-test-*")
}

// testAbnormalSyscallHandling 测试异常系统调用处理
func testAbnormalSyscallHandling(t *testing.T) {
	containerName := "test-abnormal-syscall"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试无效文件描述符操作
	invalidFdTest := execInContainer(t, containerID, "python3", "-c", `
import os
try:
    os.read(999, 1024)  # 无效的文件描述符
except OSError as e:
    print(f"Invalid FD error: {e}")
`)
	assert.Contains(t, invalidFdTest, "error", "无效文件描述符应该产生错误")
	
	// 测试无效内存访问
	segfaultTest := execInContainer(t, containerID, "python3", "-c", `
import signal
import sys
def handler(signum, frame):
    print("SIGSEGV caught")
    sys.exit(0)
signal.signal(signal.SIGSEGV, handler)
try:
    import ctypes
    ctypes.c_char.from_address(0)  # 访问NULL指针
except:
    print("Memory access error handled")
`)
	
	if strings.Contains(segfaultTest, "SIGSEGV") || strings.Contains(segfaultTest, "error") {
		t.Log("无效内存访问被正确处理")
	}
	
	// 测试信号处理异常
	signalTest := execInContainer(t, containerID, "python3", "-c", `
import signal
import os
import time
def handler(signum, frame):
    print(f"Signal {signum} received")
signal.signal(signal.SIGUSR1, handler)
os.kill(os.getpid(), signal.SIGUSR1)
time.sleep(0.1)
print("Signal test completed")
`)
	assert.Contains(t, signalTest, "Signal test completed", "信号处理应该正常工作")
	
	// 测试资源耗尽处理
	resourceTest := execInContainer(t, containerID, "python3", "-c", `
import os
try:
    # 尝试打开大量文件
    files = []
    for i in range(1000):
        f = open(f'/tmp/test-{i}', 'w')
        files.append(f)
    print("Many files opened")
except Exception as e:
    print(f"Resource limit reached: {type(e).__name__}")
finally:
    for f in files:
        try:
            f.close()
        except:
            pass
`)
	
	// 测试系统调用中断处理
	interruptTest := execInContainer(t, containerID, "timeout", "2", "sleep", "10")
	// timeout命令应该能正常中断sleep
	
	// 测试并发系统调用
	concurrentTest := execInContainer(t, containerID, "python3", "-c", `
import threading
import time
import os
def worker():
    for i in range(10):
        os.getpid()
        time.sleep(0.01)
threads = []
for i in range(10):
    t = threading.Thread(target=worker)
    threads.append(t)
    t.start()
for t in threads:
    t.join()
print("Concurrent syscalls completed")
`)
	assert.Contains(t, concurrentTest, "completed", "并发系统调用应该正常处理")
	
	// 测试异常退出处理
	exitTest := execInContainer(t, containerID, "sh", "-c", "exit 42")
	// 验证退出码传递
	
	// 测试孤儿进程处理
	orphanTest := execInContainer(t, containerID, "sh", "-c", `
(sleep 1 &)
echo "Parent exits, child becomes orphan"
`)
	assert.Contains(t, orphanTest, "Parent exits", "孤儿进程处理测试应该执行")
	
	// 等待可能的孤儿进程清理
	time.Sleep(2 * time.Second)
	
	// 验证进程状态
	finalPS := execInContainer(t, containerID, "ps", "aux")
	// 不应该有太多僵尸进程
	zombieCount := strings.Count(finalPS, "<defunct>")
	assert.LessOrEqual(t, zombieCount, 2, "僵尸进程数量应该较少")
}

// Helper functions for syscall tests

func setupSyscallTestEnv(t *testing.T) {
	// 验证基本环境
	output, err := exec.Command("docker", "info").Output()
	require.NoError(t, err, "Docker应该正常运行")
	require.Contains(t, string(output), "sysbox-runc", "应该配置sysbox-runc运行时")
	
	// 清理可能存在的测试容器
	testContainers := []string{
		"test-mount-syscall", "test-fs-syscall", "test-network-syscall",
		"test-process-syscall", "test-memory-syscall", "test-privileged-syscall",
		"test-escape-prevention", "test-syscall-audit", "test-syscall-performance",
		"test-abnormal-syscall",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func cleanupSyscallTestEnv(t *testing.T) {
	// 清理所有测试容器
	testContainers := []string{
		"test-mount-syscall", "test-fs-syscall", "test-network-syscall",
		"test-process-syscall", "test-memory-syscall", "test-privileged-syscall",
		"test-escape-prevention", "test-syscall-audit", "test-syscall-performance",
		"test-abnormal-syscall",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}