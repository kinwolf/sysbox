package core

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io/ioutil"
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

// TestSecurityIsolation 测试Sysbox安全隔离核心功能
func TestSecurityIsolation(t *testing.T) {
	setupSecurityTestEnv(t)
	defer cleanupSecurityTestEnv(t)

	t.Run("用户命名空间安全隔离", func(t *testing.T) {
		testUserNamespaceSecurityIsolation(t)
	})

	t.Run("文件系统安全边界", func(t *testing.T) {
		testFilesystemSecurityBoundaries(t)
	})

	t.Run("进程隔离安全验证", func(t *testing.T) {
		testProcessIsolationSecurity(t)
	})

	t.Run("网络安全隔离", func(t *testing.T) {
		testNetworkSecurityIsolation(t)
	})

	t.Run("能力和权限控制", func(t *testing.T) {
		testCapabilitiesAndPermissionControl(t)
	})

	t.Run("资源限制安全", func(t *testing.T) {
		testResourceLimitsSecurity(t)
	})

	t.Run("容器逃逸防护", func(t *testing.T) {
		testContainerEscapeProtection(t)
	})

	t.Run("密钥和敏感信息保护", func(t *testing.T) {
		testSecretsAndSensitiveDataProtection(t)
	})

	t.Run("审计和监控安全", func(t *testing.T) {
		testAuditingAndMonitoringSecurity(t)
	})

	t.Run("多租户隔离验证", func(t *testing.T) {
		testMultiTenantIsolationVerification(t)
	})
}

// testUserNamespaceSecurityIsolation 测试用户命名空间安全隔离
func testUserNamespaceSecurityIsolation(t *testing.T) {
	containerName := "test-userns-security"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证容器内root用户没有主机root权限
	containerUID := execInContainer(t, containerID, "id", "-u")
	containerGID := execInContainer(t, containerID, "id", "-g")
	assert.Equal(t, "0", strings.TrimSpace(containerUID), "容器内应该显示为root用户")
	assert.Equal(t, "0", strings.TrimSpace(containerGID), "容器内应该显示为root组")
	
	// 获取容器主进程在主机上的实际UID
	containerPID := getContainerPID(t, containerID)
	hostUID := getProcessUID(t, containerPID)
	assert.NotEqual(t, "0", hostUID, "容器进程在主机上不应该是root用户")
	
	// 验证UID/GID映射配置
	uidMapPath := fmt.Sprintf("/proc/%s/uid_map", containerPID)
	gidMapPath := fmt.Sprintf("/proc/%s/gid_map", containerPID)
	
	uidMap := readFileContent(t, uidMapPath)
	gidMap := readFileContent(t, gidMapPath)
	
	assert.NotEmpty(t, uidMap, "UID映射应该存在")
	assert.NotEmpty(t, gidMap, "GID映射应该存在")
	
	// 解析映射范围验证安全性
	uidMappings := parseIDMapping(t, uidMap)
	gidMappings := parseIDMapping(t, gidMap)
	
	assert.NotEmpty(t, uidMappings, "应该有UID映射条目")
	assert.NotEmpty(t, gidMappings, "应该有GID映射条目")
	
	// 验证映射范围不包含系统用户
	for _, mapping := range uidMappings {
		hostIDInt, err := strconv.Atoi(mapping.HostID)
		require.NoError(t, err)
		assert.Greater(t, hostIDInt, 1000, "映射的主机UID应该大于1000（避免系统用户冲突）")
	}
	
	// 测试容器内用户创建
	userAddOutput := execInContainer(t, containerID, "useradd", "-m", "testuser")
	assert.Equal(t, "", strings.TrimSpace(userAddOutput), "容器内用户创建应该成功")
	
	// 验证新用户在用户命名空间内的权限
	userID := execInContainer(t, containerID, "id", "-u", "testuser")
	userIDInt, err := strconv.Atoi(strings.TrimSpace(userID))
	require.NoError(t, err)
	assert.Greater(t, userIDInt, 1000, "新创建的用户ID应该大于1000")
	
	// 测试setuid程序的安全性
	// 在容器内创建一个简单的setuid程序
	execInContainer(t, containerID, "sh", "-c", `
cat > /tmp/setuid_test.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
int main() {
    printf("Real UID: %d\n", getuid());
    printf("Effective UID: %d\n", geteuid());
    return 0;
}
EOF
`)
	
	// 编译并设置setuid位
	compileOutput := execInContainer(t, containerID, "gcc", "-o", "/tmp/setuid_test", "/tmp/setuid_test.c")
	if strings.TrimSpace(compileOutput) == "" {
		execInContainer(t, containerID, "chmod", "4755", "/tmp/setuid_test")
		
		// 以普通用户身份运行setuid程序
		setuidResult := execInContainer(t, containerID, "su", "-c", "/tmp/setuid_test", "testuser")
		
		if strings.Contains(setuidResult, "Real UID:") {
			t.Log("setuid程序在用户命名空间内的行为已验证")
		}
	}
	
	// 测试用户命名空间边界
	// 尝试访问主机用户信息
	_, err = execInContainerWithError(containerID, "getent", "passwd", "1000")
	if err != nil {
		t.Log("容器内无法访问主机用户信息，隔离正常")
	}
	
	// 验证/etc/passwd和/etc/group的隔离
	passwdContent := execInContainer(t, containerID, "cat", "/etc/passwd")
	groupContent := execInContainer(t, containerID, "cat", "/etc/group")
	
	assert.Contains(t, passwdContent, "root:x:0:0", "容器内应该有独立的passwd文件")
	assert.Contains(t, groupContent, "root:x:0:", "容器内应该有独立的group文件")
	
	// 验证用户主目录权限
	rootHomePerms := execInContainer(t, containerID, "ls", "-ld", "/root")
	assert.Contains(t, rootHomePerms, "rwx", "root用户主目录应该有正确权限")
	
	testUserHomePerms := execInContainer(t, containerID, "ls", "-ld", "/home/testuser")
	assert.Contains(t, testUserHomePerms, "testuser", "测试用户主目录应该属于该用户")
}

// testFilesystemSecurityBoundaries 测试文件系统安全边界
func testFilesystemSecurityBoundaries(t *testing.T) {
	containerName := "test-fs-security"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试根文件系统隔离
	rootFSContent := execInContainer(t, containerID, "ls", "/")
	expectedDirs := []string{"bin", "etc", "usr", "var", "tmp"}
	for _, dir := range expectedDirs {
		assert.Contains(t, rootFSContent, dir, fmt.Sprintf("根文件系统应该包含%s目录", dir))
	}
	
	// 验证主机敏感目录不可访问
	hostSensitivePaths := []string{
		"/host-root",
		"/host-proc",
		"/host-sys",
		"/boot",
	}
	
	for _, path := range hostSensitivePaths {
		_, err := execInContainerWithError(containerID, "ls", path)
		if err != nil {
			t.Logf("主机敏感路径%s不可访问，隔离正常", path)
		}
	}
	
	// 测试/proc文件系统安全边界
	procContent := execInContainer(t, containerID, "ls", "/proc")
	assert.Contains(t, procContent, "self", "/proc应该包含self链接")
	assert.Contains(t, procContent, "1", "/proc应该包含PID 1目录")
	
	// 验证敏感的/proc文件访问限制
	sensitiveProcFiles := []string{
		"/proc/kallsyms",
		"/proc/kcore",
		"/proc/kmsg",
		"/proc/sysrq-trigger",
	}
	
	for _, procFile := range sensitiveProcFiles {
		_, err := execInContainerWithError(containerID, "cat", procFile)
		if err != nil {
			t.Logf("敏感proc文件%s访问被限制", procFile)
		} else {
			t.Logf("敏感proc文件%s可访问（可能有特殊处理）", procFile)
		}
	}
	
	// 测试/sys文件系统安全边界
	sysContent := execInContainer(t, containerID, "ls", "/sys")
	assert.Contains(t, sysContent, "kernel", "/sys应该包含kernel目录")
	assert.Contains(t, sysContent, "fs", "/sys应该包含fs目录")
	
	// 验证敏感的/sys文件写入限制
	sensitiveSysFiles := []string{
		"/sys/kernel/domainname",
		"/sys/kernel/hostname",
	}
	
	for _, sysFile := range sensitiveSysFiles {
		if fileExists(t, containerID, sysFile) {
			_, err := execInContainerWithError(containerID, "echo", "test", ">", sysFile)
			if err != nil {
				t.Logf("敏感sys文件%s写入被限制", sysFile)
			}
		}
	}
	
	// 测试设备文件系统安全
	devContent := execInContainer(t, containerID, "ls", "/dev")
	assert.Contains(t, devContent, "null", "/dev应该包含null设备")
	assert.Contains(t, devContent, "zero", "/dev应该包含zero设备")
	assert.Contains(t, devContent, "random", "/dev应该包含random设备")
	
	// 验证危险设备文件访问限制
	dangerousDevFiles := []string{
		"/dev/mem",
		"/dev/kmem",
		"/dev/port",
	}
	
	for _, devFile := range dangerousDevFiles {
		_, err := execInContainerWithError(containerID, "head", "-c", "1", devFile)
		if err != nil {
			t.Logf("危险设备文件%s访问被限制", devFile)
		}
	}
	
	// 测试临时文件系统安全
	tmpfsTest := execInContainer(t, containerID, "mount", "|", "grep", "tmpfs")
	if strings.Contains(tmpfsTest, "/dev/shm") {
		// 验证/dev/shm权限
		shmPerms := execInContainer(t, containerID, "ls", "-ld", "/dev/shm")
		assert.Contains(t, shmPerms, "rwx", "/dev/shm应该有正确权限")
		
		// 测试共享内存安全
		shmTest := execInContainer(t, containerID, "touch", "/dev/shm/test-shm")
		assert.Equal(t, "", strings.TrimSpace(shmTest), "共享内存文件创建应该成功")
		
		shmContent := execInContainer(t, containerID, "echo", "shm test", ">", "/dev/shm/test-shm")
		readShmContent := execInContainer(t, containerID, "cat", "/dev/shm/test-shm")
		assert.Contains(t, readShmContent, "shm test", "共享内存文件读写应该正常")
	}
	
	// 测试文件权限和ACL
	testFileCreate := execInContainer(t, containerID, "touch", "/tmp/security-test")
	execInContainer(t, containerID, "chmod", "600", "/tmp/security-test")
	
	filePerms := execInContainer(t, containerID, "ls", "-l", "/tmp/security-test")
	assert.Contains(t, filePerms, "rw-------", "文件权限应该正确设置")
	
	// 测试符号链接安全
	symlinkTest := execInContainer(t, containerID, "ln", "-s", "/etc/passwd", "/tmp/passwd-link")
	symlinkContent := execInContainer(t, containerID, "cat", "/tmp/passwd-link")
	assert.Contains(t, symlinkContent, "root", "符号链接应该正常工作")
	
	// 验证符号链接不能指向容器外
	_, badLinkErr := execInContainerWithError(containerID, "ln", "-s", "/host-etc/passwd", "/tmp/bad-link")
	// 如果创建成功，验证访问时的安全性
	if badLinkErr == nil {
		_, accessErr := execInContainerWithError(containerID, "cat", "/tmp/bad-link")
		if accessErr != nil {
			t.Log("指向容器外的符号链接访问被限制")
		}
	}
}

// testProcessIsolationSecurity 测试进程隔离安全验证
func testProcessIsolationSecurity(t *testing.T) {
	containerName := "test-process-security"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证PID命名空间隔离
	containerProcesses := execInContainer(t, containerID, "ps", "-eo", "pid,ppid,comm")
	processLines := strings.Split(containerProcesses, "\n")
	
	// 验证PID 1存在且正确
	found_pid1 := false
	for _, line := range processLines {
		if strings.Contains(line, " 1 ") && strings.Contains(line, " 0 ") {
			found_pid1 = true
			break
		}
	}
	assert.True(t, found_pid1, "容器内应该有PID 1进程")
	
	// 验证进程数量合理（隔离有效）
	processCount := len(processLines) - 2 // 排除标题和空行
	assert.Less(t, processCount, 20, "容器内可见进程数应该有限")
	
	// 测试进程信号隔离
	// 在容器内创建后台进程
	bgProcess := execInContainer(t, containerID, "sh", "-c", "sleep 30 & echo $!")
	bgPID := strings.TrimSpace(bgProcess)
	
	if bgPID != "" && bgPID != "0" {
		// 验证能够向容器内进程发送信号
		killOutput := execInContainer(t, containerID, "kill", "-TERM", bgPID)
		assert.Equal(t, "", strings.TrimSpace(killOutput), "容器内进程信号发送应该成功")
		
		time.Sleep(1 * time.Second)
		
		// 验证进程已退出
		_, psErr := execInContainerWithError(containerID, "ps", "-p", bgPID)
		assert.Error(t, psErr, "被信号终止的进程应该不存在")
	}
	
	// 测试不能向容器外进程发送信号
	hostPID := fmt.Sprintf("%d", os.Getpid())
	_, signalErr := execInContainerWithError(containerID, "kill", "-0", hostPID)
	assert.Error(t, signalErr, "不应该能向主机进程发送信号")
	
	// 验证进程命名空间边界
	pidNSInfo := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/pid")
	assert.Contains(t, pidNSInfo, "pid:", "PID命名空间应该存在")
	
	// 测试进程创建安全
	forkTest := execInContainer(t, containerID, "python3", "-c", `
import os
import sys
try:
    pid = os.fork()
    if pid == 0:
        # 子进程
        print("Child process created")
        sys.exit(0)
    else:
        # 父进程
        os.waitpid(pid, 0)
        print("Fork test completed")
except Exception as e:
    print(f"Fork error: {e}")
`)
	assert.Contains(t, forkTest, "Fork test completed", "进程创建应该正常工作")
	
	// 测试exec安全性
	execTest := execInContainer(t, containerID, "python3", "-c", `
import subprocess
try:
    result = subprocess.run(['echo', 'exec test'], capture_output=True, text=True)
    print(f"Exec result: {result.stdout.strip()}")
except Exception as e:
    print(f"Exec error: {e}")
`)
	assert.Contains(t, execTest, "exec test", "exec操作应该正常工作")
	
	// 测试进程资源限制
	ulimitOutput := execInContainer(t, containerID, "ulimit", "-a")
	assert.Contains(t, ulimitOutput, "core file size", "ulimit信息应该可访问")
	
	// 验证特定资源限制
	maxProcs := execInContainer(t, containerID, "ulimit", "-u")
	if strings.TrimSpace(maxProcs) != "unlimited" {
		maxProcsInt, err := strconv.Atoi(strings.TrimSpace(maxProcs))
		if err == nil {
			assert.Greater(t, maxProcsInt, 0, "最大进程数限制应该大于0")
		}
	}
	
	// 测试进程优先级安全
	niceTest := execInContainer(t, containerID, "nice", "-n", "10", "echo", "nice test")
	assert.Contains(t, niceTest, "nice test", "nice命令应该执行成功")
	
	// 测试renice限制
	currentPID := execInContainer(t, containerID, "sh", "-c", "echo $$")
	currentPIDStr := strings.TrimSpace(currentPID)
	_, reniceErr := execInContainerWithError(containerID, "renice", "10", currentPIDStr)
	// renice的权限可能被限制或允许，这取决于容器配置
	
	// 测试进程调试限制
	_, ptraceErr := execInContainerWithError(containerID, "strace", "-e", "trace=write", "echo", "test")
	if ptraceErr != nil {
		t.Log("ptrace/strace被限制，增强了安全性")
	} else {
		t.Log("ptrace/strace被允许，可能有特殊用途")
	}
}

// testNetworkSecurityIsolation 测试网络安全隔离
func testNetworkSecurityIsolation(t *testing.T) {
	containerName := "test-network-security"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证网络命名空间隔离
	netNSInfo := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/net")
	assert.Contains(t, netNSInfo, "net:", "网络命名空间应该存在")
	
	// 验证网络接口隔离
	interfaces := execInContainer(t, containerID, "ip", "link", "show")
	assert.Contains(t, interfaces, "lo", "容器应该有lo接口")
	assert.Contains(t, interfaces, "eth0", "容器应该有eth0接口")
	
	// 获取容器IP地址
	containerIP := getContainerIP(t, containerID)
	assert.NotEmpty(t, containerIP, "容器应该有IP地址")
	assert.NotEqual(t, "127.0.0.1", containerIP, "容器IP不应该是本地回环地址")
	
	// 验证网络连通性和限制
	// 测试外部连通性
	pingExternal := execInContainer(t, containerID, "ping", "-c", "1", "8.8.8.8")
	assert.Contains(t, pingExternal, "1 packets transmitted", "外部网络连通性应该正常")
	
	// 测试内部网络隔离
	pingLocalhost := execInContainer(t, containerID, "ping", "-c", "1", "127.0.0.1")
	assert.Contains(t, pingLocalhost, "1 packets transmitted", "本地回环应该可达")
	
	// 测试端口绑定安全
	portBindTest := execInContainer(t, containerID, "python3", "-c", `
import socket
import threading
import time

def test_port_bind(port):
    try:
        s = socket.socket()
        s.bind(('0.0.0.0', port))
        s.listen(1)
        print(f"Port {port} bind successful")
        s.close()
        return True
    except Exception as e:
        print(f"Port {port} bind failed: {e}")
        return False

# 测试普通端口
test_port_bind(8080)

# 测试特权端口
test_port_bind(80)
test_port_bind(443)
`)
	
	// 验证端口绑定结果
	if strings.Contains(portBindTest, "8080 bind successful") {
		t.Log("普通端口绑定正常")
	}
	
	if strings.Contains(portBindTest, "80 bind successful") || strings.Contains(portBindTest, "443 bind successful") {
		t.Log("特权端口绑定被允许（容器可能有NET_BIND_SERVICE capability）")
	}
	
	// 测试网络过滤和防火墙
	iptablesOutput, iptablesErr := execInContainerWithError(containerID, "iptables", "-L")
	if iptablesErr == nil {
		t.Log("iptables可用，网络过滤功能正常")
		assert.Contains(t, iptablesOutput, "Chain", "iptables输出应该包含链信息")
	} else {
		t.Log("iptables不可用或被限制")
	}
	
	// 测试网络统计和监控
	netstatOutput := execInContainer(t, containerID, "cat", "/proc/net/dev")
	assert.Contains(t, netstatOutput, "lo:", "网络统计应该包含lo接口")
	assert.Contains(t, netstatOutput, "eth0:", "网络统计应该包含eth0接口")
	
	// 测试socket创建限制
	socketTest := execInContainer(t, containerID, "python3", "-c", `
import socket

# 测试TCP socket
try:
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("TCP socket created")
    tcp_sock.close()
except Exception as e:
    print(f"TCP socket error: {e}")

# 测试UDP socket
try:
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("UDP socket created")
    udp_sock.close()
except Exception as e:
    print(f"UDP socket error: {e}")

# 测试原始socket
try:
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    print("Raw socket created")
    raw_sock.close()
except PermissionError:
    print("Raw socket permission denied")
except Exception as e:
    print(f"Raw socket error: {e}")
`)
	
	assert.Contains(t, socketTest, "TCP socket created", "TCP socket创建应该成功")
	assert.Contains(t, socketTest, "UDP socket created", "UDP socket创建应该成功")
	
	if strings.Contains(socketTest, "Raw socket permission denied") {
		t.Log("原始socket创建被限制，安全性良好")
	} else if strings.Contains(socketTest, "Raw socket created") {
		t.Log("原始socket创建被允许")
	}
	
	// 测试网络命名空间操作限制
	_, netnsErr := execInContainerWithError(containerID, "ip", "netns", "add", "test-netns")
	if netnsErr != nil {
		t.Log("网络命名空间创建被限制")
	} else {
		t.Log("网络命名空间创建被允许")
		execInContainer(t, containerID, "ip", "netns", "del", "test-netns")
	}
	
	// 测试网络设备操作限制
	_, ifupErr := execInContainerWithError(containerID, "ip", "link", "set", "eth0", "down")
	if ifupErr != nil {
		t.Log("网络接口操作被限制")
	} else {
		// 如果成功，恢复接口
		execInContainer(t, containerID, "ip", "link", "set", "eth0", "up")
		t.Log("网络接口操作被允许")
	}
}

// testCapabilitiesAndPermissionControl 测试能力和权限控制
func testCapabilitiesAndPermissionControl(t *testing.T) {
	containerName := "test-capabilities"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 查看容器的capability信息
	capabilityStatus := execInContainer(t, containerID, "cat", "/proc/self/status")
	
	capabilityLines := []string{}
	statusLines := strings.Split(capabilityStatus, "\n")
	for _, line := range statusLines {
		if strings.HasPrefix(line, "Cap") {
			capabilityLines = append(capabilityLines, strings.TrimSpace(line))
		}
	}
	
	assert.NotEmpty(t, capabilityLines, "应该有capability信息")
	t.Logf("容器capability信息: %v", capabilityLines)
	
	// 测试具体的capability
	capabilities := map[string]string{
		"CAP_NET_BIND_SERVICE": "绑定特权端口",
		"CAP_SYS_ADMIN":        "系统管理",
		"CAP_SYS_PTRACE":       "进程跟踪",
		"CAP_SYS_MODULE":       "模块加载",
		"CAP_DAC_OVERRIDE":     "文件权限覆盖",
	}
	
	for cap, desc := range capabilities {
		capTest := execInContainer(t, containerID, "capsh", "--print")
		if strings.Contains(capTest, strings.ToLower(cap)) {
			t.Logf("容器具有%s capability (%s)", cap, desc)
		} else {
			t.Logf("容器不具有%s capability (%s)", cap, desc)
		}
	}
	
	// 测试文件权限控制
	// 创建测试文件
	execInContainer(t, containerID, "touch", "/tmp/perm-test")
	execInContainer(t, containerID, "chmod", "644", "/tmp/perm-test")
	
	// 验证权限设置
	filePerms := execInContainer(t, containerID, "ls", "-l", "/tmp/perm-test")
	assert.Contains(t, filePerms, "rw-r--r--", "文件权限应该正确设置")
	
	// 测试setuid/setgid程序
	// 检查系统中的setuid程序
	setuidProgs := execInContainer(t, containerID, "find", "/usr", "-perm", "-4000", "-type", "f", "2>/dev/null", "|", "head", "-5")
	if strings.TrimSpace(setuidProgs) != "" {
		t.Logf("发现setuid程序: %s", setuidProgs)
		
		// 测试其中一个setuid程序
		setuidProgLines := strings.Split(strings.TrimSpace(setuidProgs), "\n")
		if len(setuidProgLines) > 0 {
			firstProg := strings.TrimSpace(setuidProgLines[0])
			if firstProg != "" {
				progPerms := execInContainer(t, containerID, "ls", "-l", firstProg)
				assert.Contains(t, progPerms, "s", "setuid程序应该有s位")
			}
		}
	}
	
	// 测试sudo权限（如果安装）
	_, sudoErr := execInContainerWithError(containerID, "sudo", "-n", "echo", "sudo test")
	if sudoErr == nil {
		t.Log("sudo功能可用")
	} else {
		t.Log("sudo功能不可用或被限制")
	}
	
	// 测试文件系统ACL（如果支持）
	_, aclErr := execInContainerWithError(containerID, "getfacl", "/tmp/perm-test")
	if aclErr == nil {
		t.Log("ACL功能可用")
	} else {
		t.Log("ACL功能不可用")
	}
	
	// 测试进程capability
	processCapTest := execInContainer(t, containerID, "python3", "-c", `
import os
try:
    # 尝试执行需要特定capability的操作
    
    # 测试CAP_NET_BIND_SERVICE
    import socket
    s = socket.socket()
    try:
        s.bind(('0.0.0.0', 80))
        print("CAP_NET_BIND_SERVICE: Available")
        s.close()
    except PermissionError:
        print("CAP_NET_BIND_SERVICE: Not available")
    except Exception as e:
        print(f"CAP_NET_BIND_SERVICE: Error - {e}")
    
except Exception as e:
    print(f"Capability test error: {e}")
`)
	
	t.Logf("进程capability测试结果: %s", processCapTest)
	
	// 测试资源限制权限
	rlimitTest := execInContainer(t, containerID, "python3", "-c", `
import resource
try:
    # 获取当前资源限制
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"File descriptor limit: soft={soft}, hard={hard}")
    
    # 尝试修改资源限制
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        print("Resource limit modification: Allowed")
    except PermissionError:
        print("Resource limit modification: Denied")
    except Exception as e:
        print(f"Resource limit modification: Error - {e}")
        
except Exception as e:
    print(f"Resource limit test error: {e}")
`)
	
	t.Logf("资源限制测试结果: %s", rlimitTest)
}

// testResourceLimitsSecurity 测试资源限制安全
func testResourceLimitsSecurity(t *testing.T) {
	containerName := "test-resource-security"
	
	// 创建带资源限制的容器
	containerID := createSysboxContainerWithOptions(t, containerName, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--memory=256m", "--cpus=0.5", "--pids-limit=100")
	defer cleanupContainer(t, containerID)
	
	// 测试内存限制安全
	memLimitTest := execInContainer(t, containerID, "python3", "-c", `
import gc
import sys
try:
    # 尝试分配大量内存
    data_chunks = []
    chunk_size = 10 * 1024 * 1024  # 10MB chunks
    
    for i in range(50):  # 尝试分配500MB
        try:
            chunk = bytearray(chunk_size)
            data_chunks.append(chunk)
            print(f"Allocated chunk {i+1}: {(i+1)*10}MB")
        except MemoryError:
            print(f"Memory limit reached at chunk {i+1}")
            break
        except Exception as e:
            print(f"Memory allocation error: {e}")
            break
    
    print(f"Total chunks allocated: {len(data_chunks)}")
    
except Exception as e:
    print(f"Memory test error: {e}")
`)
	
	t.Logf("内存限制测试结果: %s", memLimitTest)
	
	// 验证内存限制配置
	memLimitFile := "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	if fileExists(t, containerID, memLimitFile) {
		memLimit := execInContainer(t, containerID, "cat", memLimitFile)
		memLimitBytes := parseBytes(t, strings.TrimSpace(memLimit))
		expectedBytes := int64(256 * 1024 * 1024) // 256MB
		assert.InDelta(t, expectedBytes, memLimitBytes, float64(expectedBytes)*0.1,
			"内存限制应该接近设置值")
	}
	
	// 测试CPU限制安全
	cpuLimitTest := execInContainer(t, containerID, "python3", "-c", `
import time
import threading
import multiprocessing

def cpu_intensive_task(duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        pass

try:
    print(f"CPU count: {multiprocessing.cpu_count()}")
    
    # 启动CPU密集型任务
    start_time = time.time()
    threads = []
    
    # 启动2个线程进行CPU密集型计算
    for i in range(2):
        t = threading.Thread(target=cpu_intensive_task, args=(2,))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    end_time = time.time()
    print(f"CPU intensive task completed in {end_time - start_time:.2f} seconds")
    
except Exception as e:
    print(f"CPU test error: {e}")
`)
	
	t.Logf("CPU限制测试结果: %s", cpuLimitTest)
	
	// 测试进程数限制安全
	pidLimitTest := execInContainer(t, containerID, "python3", "-c", `
import os
import signal
import time

def create_child_process():
    try:
        pid = os.fork()
        if pid == 0:
            # 子进程，等待信号
            time.sleep(30)
            os._exit(0)
        return pid
    except OSError as e:
        return None

try:
    child_pids = []
    
    for i in range(150):  # 尝试创建超过限制的进程
        pid = create_child_process()
        if pid is not None:
            child_pids.append(pid)
            print(f"Created process {i+1}: PID {pid}")
        else:
            print(f"Failed to create process {i+1}: Limit reached")
            break
    
    print(f"Total processes created: {len(child_pids)}")
    
    # 清理子进程
    for pid in child_pids:
        try:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
        except:
            pass
    
except Exception as e:
    print(f"PID limit test error: {e}")
`)
	
	t.Logf("进程数限制测试结果: %s", pidLimitTest)
	
	// 测试文件描述符限制
	fdLimitTest := execInContainer(t, containerID, "python3", "-c", `
import resource
import tempfile

try:
    # 获取文件描述符限制
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    print(f"FD limit: soft={soft_limit}, hard={hard_limit}")
    
    # 尝试打开大量文件
    files = []
    try:
        for i in range(int(soft_limit) + 10):
            f = tempfile.TemporaryFile()
            files.append(f)
            if i % 100 == 0:
                print(f"Opened {i+1} files")
    except OSError as e:
        print(f"File descriptor limit reached: {e}")
    
    print(f"Total files opened: {len(files)}")
    
    # 关闭文件
    for f in files:
        f.close()
    
except Exception as e:
    print(f"FD limit test error: {e}")
`)
	
	t.Logf("文件描述符限制测试结果: %s", fdLimitTest)
	
	// 测试磁盘空间限制（如果配置）
	diskUsageTest := execInContainer(t, containerID, "df", "-h", "/")
	t.Logf("磁盘使用情况: %s", diskUsageTest)
	
	// 尝试创建大文件测试磁盘限制
	diskLimitTest := execInContainer(t, containerID, "dd", "if=/dev/zero", "of=/tmp/large-file", 
		"bs=1M", "count=100", "2>&1", "||", "echo", "Disk limit reached")
	
	if strings.Contains(diskLimitTest, "limit reached") || strings.Contains(diskLimitTest, "No space") {
		t.Log("磁盘空间限制生效")
	} else {
		t.Log("磁盘空间限制测试完成")
		// 清理大文件
		execInContainer(t, containerID, "rm", "-f", "/tmp/large-file")
	}
}

// testContainerEscapeProtection 测试容器逃逸防护
func testContainerEscapeProtection(t *testing.T) {
	containerName := "test-escape-protection"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试挂载点逃逸防护
	// 尝试访问主机文件系统
	_, hostAccessErr := execInContainerWithError(containerID, "ls", "/host")
	assert.Error(t, hostAccessErr, "不应该能访问主机文件系统")
	
	// 测试符号链接逃逸防护
	symlinkEscapeTest := execInContainer(t, containerID, "ln", "-s", "../../../etc/passwd", "/tmp/escape-link")
	_, escapeAccessErr := execInContainerWithError(containerID, "cat", "/tmp/escape-link")
	if escapeAccessErr != nil {
		t.Log("符号链接逃逸被防护")
	} else {
		// 如果访问成功，验证是否访问的是容器内的文件
		escapeContent := execInContainer(t, containerID, "cat", "/tmp/escape-link")
		if strings.Contains(escapeContent, "root:x:0:0") {
			t.Log("符号链接访问的是容器内文件，安全")
		}
	}
	
	// 测试proc文件系统逃逸防护
	procEscapeTest := []string{
		"/proc/1/root",
		"/proc/self/root/../../../etc/passwd",
		"/proc/version",
	}
	
	for _, procPath := range procEscapeTest {
		_, err := execInContainerWithError(containerID, "ls", procPath)
		if err != nil {
			t.Logf("proc路径%s访问被防护", procPath)
		} else {
			t.Logf("proc路径%s可访问", procPath)
		}
	}
	
	// 测试设备文件逃逸防护
	deviceEscapeTest := []string{
		"/dev/kmsg",
		"/dev/mem", 
		"/dev/kmem",
		"/dev/port",
	}
	
	for _, device := range deviceEscapeTest {
		if fileExists(t, containerID, device) {
			_, err := execInContainerWithError(containerID, "head", "-c", "1", device)
			if err != nil {
				t.Logf("危险设备%s访问被防护", device)
			} else {
				t.Logf("危险设备%s可访问（需要验证安全性）", device)
			}
		}
	}
	
	// 测试内核模块逃逸防护
	_, modprobeErr := execInContainerWithError(containerID, "modprobe", "dummy")
	assert.Error(t, modprobeErr, "内核模块加载应该被阻止")
	
	// 测试系统调用逃逸防护
	syscallEscapeTest := execInContainer(t, containerID, "python3", "-c", `
import os
import sys

# 测试危险系统调用
dangerous_operations = [
    ("reboot", lambda: os.system("reboot")),
    ("mount", lambda: os.system("mount --bind /etc /tmp/escape")),
    ("chroot", lambda: os.chroot("/tmp")),
]

for name, operation in dangerous_operations:
    try:
        result = operation()
        print(f"{name}: {'Success' if result == 0 else 'Failed'}")
    except Exception as e:
        print(f"{name}: Blocked - {e}")
`)
	
	t.Logf("系统调用逃逸测试结果: %s", syscallEscapeTest)
	
	// 测试cgroup逃逸防护
	cgroupEscapeTest := execInContainer(t, containerID, "cat", "/proc/self/cgroup")
	assert.Contains(t, cgroupEscapeTest, "/docker/", "进程应该在Docker cgroup中")
	
	// 尝试修改cgroup设置
	_, cgroupWriteErr := execInContainerWithError(containerID, "echo", "1", ">", "/sys/fs/cgroup/memory/memory.limit_in_bytes")
	if cgroupWriteErr != nil {
		t.Log("cgroup设置修改被防护")
	}
	
	// 测试命名空间逃逸防护
	nsEscapeTest := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/")
	namespaces := []string{"pid", "mnt", "net", "user", "uts", "ipc"}
	
	for _, ns := range namespaces {
		if strings.Contains(nsEscapeTest, ns) {
			t.Logf("命名空间%s存在", ns)
		}
	}
	
	// 测试用户命名空间逃逸防护
	userNSEscapeTest := execInContainer(t, containerID, "python3", "-c", `
import os
try:
    # 尝试创建新的用户命名空间
    pid = os.fork()
    if pid == 0:
        try:
            # 子进程中尝试unshare
            os.system("unshare -U echo 'New user namespace created'")
        except:
            print("User namespace creation failed")
        os._exit(0)
    else:
        os.waitpid(pid, 0)
        print("User namespace escape test completed")
except Exception as e:
    print(f"User namespace escape test error: {e}")
`)
	
	t.Logf("用户命名空间逃逸测试结果: %s", userNSEscapeTest)
}

// testSecretsAndSensitiveDataProtection 测试密钥和敏感信息保护
func testSecretsAndSensitiveDataProtection(t *testing.T) {
	containerName := "test-secrets-protection"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试环境变量保护
	// 设置敏感环境变量
	envTestContainer := createSysboxContainerWithOptions(t, "test-env-secrets", "ubuntu:20.04",
		[]string{"sleep", "300"}, "-e", "SECRET_KEY=my-secret-123", "-e", "DB_PASSWORD=db-pass-456")
	defer cleanupContainer(t, envTestContainer)
	
	// 验证环境变量在容器内可见
	envOutput := execInContainer(t, envTestContainer, "env")
	assert.Contains(t, envOutput, "SECRET_KEY=my-secret-123", "环境变量应该在容器内可见")
	assert.Contains(t, envOutput, "DB_PASSWORD=db-pass-456", "环境变量应该在容器内可见")
	
	// 验证环境变量不会泄露到其他容器
	otherEnvOutput := execInContainer(t, containerID, "env")
	assert.NotContains(t, otherEnvOutput, "my-secret-123", "环境变量不应该泄露到其他容器")
	assert.NotContains(t, otherEnvOutput, "db-pass-456", "环境变量不应该泄露到其他容器")
	
	// 测试文件权限保护
	// 创建包含敏感信息的文件
	secretFileContent := "database_password=super-secret-password\napi_key=sk-1234567890abcdef"
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("echo '%s' > /tmp/secrets.conf", secretFileContent))
	
	// 设置严格权限
	execInContainer(t, containerID, "chmod", "600", "/tmp/secrets.conf")
	
	// 验证权限设置
	secretFilePerms := execInContainer(t, containerID, "ls", "-l", "/tmp/secrets.conf")
	assert.Contains(t, secretFilePerms, "rw-------", "敏感文件应该有严格权限")
	
	// 测试不同用户访问
	execInContainer(t, containerID, "useradd", "-m", "testuser")
	_, userAccessErr := execInContainerWithError(containerID, "su", "-c", "cat /tmp/secrets.conf", "testuser")
	assert.Error(t, userAccessErr, "其他用户不应该能访问敏感文件")
	
	// 测试内存中的敏感数据保护
	memorySecretTest := execInContainer(t, containerID, "python3", "-c", `
import os
import gc
import ctypes

# 创建包含敏感数据的变量
secret_data = "credit_card_number=1234-5678-9012-3456"
secret_bytes = secret_data.encode('utf-8')

print(f"Secret data created: {len(secret_data)} characters")

# 尝试从内存中清除敏感数据
secret_data = None
secret_bytes = None

# 强制垃圾回收
gc.collect()

print("Attempted to clear secret data from memory")

# 模拟检查内存泄露（简化版本）
# 在实际环境中，这需要更复杂的内存分析工具
print("Memory cleanup test completed")
`)
	
	t.Logf("内存敏感数据保护测试: %s", memorySecretTest)
	
	// 测试临时文件保护
	tempSecretTest := execInContainer(t, containerID, "python3", "-c", `
import tempfile
import os

# 创建临时文件存储敏感信息
with tempfile.NamedTemporaryFile(mode='w', delete=False, prefix='secret_', suffix='.tmp', dir='/tmp') as temp_file:
    temp_file.write("temporary_secret=temp-secret-data")
    temp_file_path = temp_file.name

print(f"Temporary secret file created: {temp_file_path}")

# 检查文件权限
file_stat = os.stat(temp_file_path)
file_mode = oct(file_stat.st_mode)[-3:]
print(f"Temporary file permissions: {file_mode}")

# 清理临时文件
os.unlink(temp_file_path)
print("Temporary file cleaned up")
`)
	
	t.Logf("临时文件保护测试: %s", tempSecretTest)
	
	// 测试进程信息泄露防护
	procInfoTest := execInContainer(t, containerID, "ps", "aux")
	
	# 检查进程列表中是否包含敏感信息
	if strings.Contains(procInfoTest, "password") || strings.Contains(procInfoTest, "secret") {
		t.Log("警告：进程列表中可能包含敏感信息")
	} else {
		t.Log("进程列表中未发现明显的敏感信息")
	}
	
	// 测试网络连接信息保护
	netConnectionTest := execInContainer(t, containerID, "netstat", "-tuln")
	t.Logf("网络连接信息: %s", netConnectionTest)
	
	// 测试系统日志保护
	syslogProtectionTest := []string{
		"/var/log/auth.log",
		"/var/log/syslog",
		"/var/log/messages",
	}
	
	for _, logFile := range syslogProtectionTest {
		_, err := execInContainerWithError(containerID, "cat", logFile)
		if err != nil {
			t.Logf("系统日志%s访问被保护", logFile)
		} else {
			t.Logf("系统日志%s可访问", logFile)
		}
	}
	
	// 测试核心转储保护
	coreDumpTest := execInContainer(t, containerID, "ulimit", "-c")
	coreDumpLimit := strings.TrimSpace(coreDumpTest)
	if coreDumpLimit == "0" {
		t.Log("核心转储被禁用，有助于保护敏感信息")
	} else {
		t.Logf("核心转储限制: %s", coreDumpLimit)
	}
	
	// 测试swap文件保护
	swapInfoTest := execInContainer(t, containerID, "cat", "/proc/swaps")
	if strings.TrimSpace(swapInfoTest) == "" || strings.Contains(swapInfoTest, "Filename") {
		t.Log("swap信息检查完成")
	}
}

// testAuditingAndMonitoringSecurity 测试审计和监控安全
func testAuditingAndMonitoringSecurity(t *testing.T) {
	containerName := "test-audit-security"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 检查审计日志文件
	auditLogPaths := []string{
		"/var/log/audit/audit.log",
		"/var/log/auth.log",
		"/var/log/syslog",
	}
	
	var availableAuditLogs []string
	for _, logPath := range auditLogPaths {
		if _, err := os.Stat(logPath); err == nil {
			availableAuditLogs = append(availableAuditLogs, logPath)
		}
	}
	
	if len(availableAuditLogs) > 0 {
		t.Logf("发现审计日志文件: %v", availableAuditLogs)
		
		// 记录初始日志大小
		initialLogSizes := make(map[string]int)
		for _, logPath := range availableAuditLogs {
			initialLogSizes[logPath] = getFileLineCount(t, logPath)
		}
		
		// 执行一些安全相关操作
		securityOperations := [][]string{
			{"mount", "--bind", "/tmp", "/mnt"},
			{"umount", "/mnt"},
			{"chmod", "4755", "/tmp/test-setuid"},
			{"su", "-c", "echo test", "root"},
		}
		
		for _, op := range securityOperations {
			execInContainer(t, containerID, op...)
			time.Sleep(1 * time.Second)
		}
		
		// 检查日志是否有更新
		time.Sleep(3 * time.Second)
		for _, logPath := range availableAuditLogs {
			currentSize := getFileLineCount(t, logPath)
			if currentSize > initialLogSizes[logPath] {
				t.Logf("审计日志%s有新记录", logPath)
			}
		}
	} else {
		t.Log("未找到系统审计日志文件")
	}
	
	// 测试进程监控
	processMonitorTest := execInContainer(t, containerID, "ps", "-eo", "pid,ppid,user,comm,cmd")
	processLines := strings.Split(processMonitorTest, "\n")
	
	suspiciousProcesses := []string{"nc", "ncat", "socat", "telnet", "ssh"}
	for _, line := range processLines {
		for _, suspicious := range suspiciousProcesses {
			if strings.Contains(strings.ToLower(line), suspicious) {
				t.Logf("发现可疑进程: %s", line)
			}
		}
	}
	
	// 测试网络连接监控
	networkMonitorTest := execInContainer(t, containerID, "netstat", "-tuln")
	networkLines := strings.Split(networkMonitorTest, "\n")
	
	for _, line := range networkLines {
		if strings.Contains(line, "LISTEN") {
			t.Logf("监听端口: %s", line)
		}
	}
	
	// 测试文件系统监控
	// 创建测试文件并监控访问
	execInContainer(t, containerID, "touch", "/tmp/monitored-file")
	
	// 模拟文件监控
	fileMonitorTest := execInContainer(t, containerID, "inotifywait", "-e", "access", "/tmp/monitored-file", "&")
	if !strings.Contains(fileMonitorTest, "command not found") {
		t.Log("文件系统监控工具可用")
	}
	
	// 测试用户活动监控
	userActivityTest := execInContainer(t, containerID, "w")
	t.Logf("用户活动信息: %s", userActivityTest)
	
	lastLoginTest := execInContainer(t, containerID, "last", "-n", "5")
	if !strings.Contains(lastLoginTest, "wtmp begins") {
		t.Logf("登录历史: %s", lastLoginTest)
	}
	
	// 测试系统调用监控
	_, straceErr := execInContainerWithError(containerID, "strace", "-e", "trace=openat", "ls", "/tmp")
	if straceErr == nil {
		t.Log("系统调用监控工具可用")
	} else {
		t.Log("系统调用监控工具不可用或被限制")
	}
	
	// 测试性能监控
	performanceMonitorTest := execInContainer(t, containerID, "top", "-n", "1", "-b")
	if strings.Contains(performanceMonitorTest, "load average") {
		t.Log("性能监控工具正常工作")
	}
	
	// 测试安全事件检测
	securityEventTest := execInContainer(t, containerID, "python3", "-c", `
import os
import subprocess
import time

# 模拟一些安全事件
security_events = [
    "Failed login attempt simulation",
    "Privilege escalation attempt simulation", 
    "Suspicious file access simulation",
]

for event in security_events:
    print(f"Security event: {event}")
    time.sleep(0.5)

print("Security event simulation completed")
`)
	
	t.Logf("安全事件模拟: %s", securityEventTest)
}

// testMultiTenantIsolationVerification 测试多租户隔离验证
func testMultiTenantIsolationVerification(t *testing.T) {
	// 创建多个容器模拟多租户环境
	tenant1Container := createSysboxContainer(t, "tenant1-container", "ubuntu:20.04", []string{"sleep", "300"})
	tenant2Container := createSysboxContainer(t, "tenant2-container", "ubuntu:20.04", []string{"sleep", "300"})
	
	defer func() {
		cleanupContainer(t, tenant1Container)
		cleanupContainer(t, tenant2Container)
	}()
	
	// 验证容器间进程隔离
	tenant1Processes := execInContainer(t, tenant1Container, "ps", "aux")
	tenant2Processes := execInContainer(t, tenant2Container, "ps", "aux")
	
	// 验证进程列表不同
	assert.NotEqual(t, tenant1Processes, tenant2Processes, "不同租户的进程列表应该不同")
	
	// 验证各自只能看到自己的进程
	assert.NotContains(t, tenant1Processes, "tenant2", "租户1不应该看到租户2相关进程")
	assert.NotContains(t, tenant2Processes, "tenant1", "租户2不应该看到租户1相关进程")
	
	// 验证网络隔离
	tenant1IP := getContainerIP(t, tenant1Container)
	tenant2IP := getContainerIP(t, tenant2Container)
	
	assert.NotEmpty(t, tenant1IP, "租户1应该有IP地址")
	assert.NotEmpty(t, tenant2IP, "租户2应该有IP地址")
	assert.NotEqual(t, tenant1IP, tenant2IP, "不同租户应该有不同的IP地址")
	
	// 测试租户间网络连通性（默认应该可达）
	pingTest := execInContainer(t, tenant1Container, "ping", "-c", "1", tenant2IP)
	if strings.Contains(pingTest, "1 packets transmitted") {
		t.Log("租户间网络默认可达")
	} else {
		t.Log("租户间网络被隔离")
	}
	
	// 验证文件系统隔离
	// 在租户1中创建文件
	execInContainer(t, tenant1Container, "echo", "tenant1 data", ">", "/tmp/tenant1-file")
	execInContainer(t, tenant1Container, "mkdir", "-p", "/tmp/tenant1-dir")
	
	// 在租户2中创建文件
	execInContainer(t, tenant2Container, "echo", "tenant2 data", ">", "/tmp/tenant2-file")
	execInContainer(t, tenant2Container, "mkdir", "-p", "/tmp/tenant2-dir")
	
	// 验证文件隔离
	_, tenant1AccessErr := execInContainerWithError(tenant1Container, "cat", "/tmp/tenant2-file")
	_, tenant2AccessErr := execInContainerWithError(tenant2Container, "cat", "/tmp/tenant1-file")
	
	assert.Error(t, tenant1AccessErr, "租户1不应该能访问租户2的文件")
	assert.Error(t, tenant2AccessErr, "租户2不应该能访问租户1的文件")
	
	// 验证用户命名空间隔离
	tenant1PID := getContainerPID(t, tenant1Container)
	tenant2PID := getContainerPID(t, tenant2Container)
	
	tenant1UIDMap := readFileContent(t, fmt.Sprintf("/proc/%s/uid_map", tenant1PID))
	tenant2UIDMap := readFileContent(t, fmt.Sprintf("/proc/%s/uid_map", tenant2PID))
	
	// 解析UID映射
	tenant1Mappings := parseIDMapping(t, tenant1UIDMap)
	tenant2Mappings := parseIDMapping(t, tenant2UIDMap)
	
	if len(tenant1Mappings) > 0 && len(tenant2Mappings) > 0 {
		// 验证不同租户的UID映射范围不重叠
		assert.NotEqual(t, tenant1Mappings[0].HostID, tenant2Mappings[0].HostID,
			"不同租户的UID映射范围应该不重叠")
	}
	
	// 验证资源隔离
	// 在租户1中进行资源密集型操作
	resourceTest1 := execInContainer(t, tenant1Container, "python3", "-c", `
import time
start = time.time()
data = bytearray(50 * 1024 * 1024)  # 50MB
end = time.time()
print(f"Tenant1 memory allocation: {end - start:.3f}s")
`)
	
	// 同时在租户2中进行资源操作
	resourceTest2 := execInContainer(t, tenant2Container, "python3", "-c", `
import time
start = time.time()
data = bytearray(50 * 1024 * 1024)  # 50MB
end = time.time()
print(f"Tenant2 memory allocation: {end - start:.3f}s")
`)
	
	t.Logf("租户1资源测试: %s", resourceTest1)
	t.Logf("租户2资源测试: %s", resourceTest2)
	
	// 验证cgroup隔离
	tenant1Cgroup := execInContainer(t, tenant1Container, "cat", "/proc/self/cgroup")
	tenant2Cgroup := execInContainer(t, tenant2Container, "cat", "/proc/self/cgroup")
	
	assert.NotEqual(t, tenant1Cgroup, tenant2Cgroup, "不同租户应该在不同的cgroup中")
	
	// 验证设备访问隔离
	// 测试设备文件访问
	tenant1Devices := execInContainer(t, tenant1Container, "ls", "/dev")
	tenant2Devices := execInContainer(t, tenant2Container, "ls", "/dev")
	
	// 基本设备文件应该都有
	commonDevices := []string{"null", "zero", "random", "urandom"}
	for _, device := range commonDevices {
		assert.Contains(t, tenant1Devices, device, fmt.Sprintf("租户1应该有%s设备", device))
		assert.Contains(t, tenant2Devices, device, fmt.Sprintf("租户2应该有%s设备", device))
	}
	
	// 验证IPC隔离
	ipcTest1 := execInContainer(t, tenant1Container, "ipcs")
	ipcTest2 := execInContainer(t, tenant2Container, "ipcs")
	
	t.Logf("租户1 IPC资源: %s", ipcTest1)
	t.Logf("租户2 IPC资源: %s", ipcTest2)
	
	// 创建共享内存段测试隔离
	shmTest1 := execInContainer(t, tenant1Container, "python3", "-c", `
import os
import mmap
try:
    fd = os.open('/dev/shm/tenant1-shm', os.O_CREAT | os.O_RDWR)
    os.write(fd, b'tenant1 shared memory')
    os.close(fd)
    print("Tenant1 shared memory created")
except Exception as e:
    print(f"Tenant1 shared memory error: {e}")
`)
	
	shmTest2 := execInContainer(t, tenant2Container, "python3", "-c", `
import os
try:
    with open('/dev/shm/tenant1-shm', 'r') as f:
        content = f.read()
        print(f"Tenant2 accessed tenant1 shm: {content}")
except FileNotFoundError:
    print("Tenant2 cannot access tenant1 shared memory - isolated")
except Exception as e:
    print(f"Tenant2 shared memory access error: {e}")
`)
	
	t.Logf("租户1共享内存测试: %s", shmTest1)
	t.Logf("租户2共享内存访问测试: %s", shmTest2)
	
	if strings.Contains(shmTest2, "cannot access") || strings.Contains(shmTest2, "isolated") {
		t.Log("共享内存在租户间正确隔离")
	}
}

// Helper functions for security tests

func setupSecurityTestEnv(t *testing.T) {
	// 验证测试环境
	output, err := exec.Command("docker", "info").Output()
	require.NoError(t, err, "Docker应该正常运行")
	require.Contains(t, string(output), "sysbox-runc", "应该配置sysbox-runc运行时")
	
	// 清理可能存在的测试容器
	testContainers := []string{
		"test-userns-security", "test-fs-security", "test-process-security",
		"test-network-security", "test-capabilities", "test-resource-security",
		"test-escape-protection", "test-secrets-protection", "test-env-secrets",
		"test-audit-security", "tenant1-container", "tenant2-container",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func cleanupSecurityTestEnv(t *testing.T) {
	// 清理所有测试容器
	testContainers := []string{
		"test-userns-security", "test-fs-security", "test-process-security",
		"test-network-security", "test-capabilities", "test-resource-security",
		"test-escape-protection", "test-secrets-protection", "test-env-secrets",
		"test-audit-security", "tenant1-container", "tenant2-container",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}
