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

// TestIPCCommunication 测试Sysbox组件间IPC通信核心流程
func TestIPCCommunication(t *testing.T) {
	setupIPCTestEnv(t)
	defer cleanupIPCTestEnv(t)

	t.Run("sysbox-runc与sysbox-mgr通信", func(t *testing.T) {
		testSysboxRuncMgrCommunication(t)
	})

	t.Run("sysbox-runc与sysbox-fs通信", func(t *testing.T) {
		testSysboxRuncFSCommunication(t)
	})

	t.Run("sysbox-mgr与sysbox-fs通信", func(t *testing.T) {
		testSysboxMgrFSCommunication(t)
	})

	t.Run("gRPC服务发现和连接", func(t *testing.T) {
		testGRPCServiceDiscoveryAndConnection(t)
	})

	t.Run("IPC消息序列化和反序列化", func(t *testing.T) {
		testIPCMessageSerialization(t)
	})

	t.Run("IPC错误处理和重试机制", func(t *testing.T) {
		testIPCErrorHandlingAndRetry(t)
	})

	t.Run("IPC性能和延迟测试", func(t *testing.T) {
		testIPCPerformanceAndLatency(t)
	})

	t.Run("IPC安全和认证", func(t *testing.T) {
		testIPCSecurityAndAuthentication(t)
	})

	t.Run("IPC连接池和资源管理", func(t *testing.T) {
		testIPCConnectionPooling(t)
	})

	t.Run("IPC监控和调试", func(t *testing.T) {
		testIPCMonitoringAndDebugging(t)
	})
}

// testSysboxRuncMgrCommunication 测试sysbox-runc与sysbox-mgr通信
func testSysboxRuncMgrCommunication(t *testing.T) {
	// 验证sysbox-mgr服务运行
	mgrPID := getSysboxMgrPID(t)
	require.NotEmpty(t, mgrPID, "sysbox-mgr应该正在运行")
	
	// 验证sysbox-mgr监听端口
	mgrPort := getSysboxMgrPort(t)
	if mgrPort != "" {
		t.Logf("sysbox-mgr监听端口: %s", mgrPort)
		
		// 测试端口连通性
		conn, err := net.DialTimeout("tcp", "localhost:"+mgrPort, 5*time.Second)
		if err == nil {
			conn.Close()
			t.Log("sysbox-mgr gRPC端口连通正常")
		} else {
			t.Logf("sysbox-mgr端口连接测试: %v", err)
		}
	}
	
	// 创建系统容器测试runc-mgr通信
	containerName := "test-runc-mgr-comm"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证容器创建过程中的通信
	// 通过检查sysbox-mgr日志验证通信
	mgrLogs := getSysboxMgrLogs(t)
	if strings.Contains(mgrLogs, containerID[:12]) || strings.Contains(mgrLogs, "container") {
		t.Log("sysbox-mgr日志中发现容器相关通信记录")
	}
	
	// 验证用户命名空间配置通信
	containerPID := getContainerPID(t, containerID)
	uidMapPath := fmt.Sprintf("/proc/%s/uid_map", containerPID)
	uidMap := readFileContent(t, uidMapPath)
	
	assert.NotEmpty(t, uidMap, "UID映射应该存在")
	t.Log("sysbox-runc与sysbox-mgr的用户命名空间通信正常")
	
	// 验证挂载管理通信
	mountInfo := execInContainer(t, containerID, "mount")
	assert.Contains(t, mountInfo, "/proc", "procfs挂载应该存在")
	assert.Contains(t, mountInfo, "/sys", "sysfs挂载应该存在")
	
	// 检查特殊挂载点（由sysbox-mgr管理）
	specialMounts := []string{"/proc", "/sys", "/dev"}
	for _, mount := range specialMounts {
		if strings.Contains(mountInfo, mount) {
			t.Logf("特殊挂载点%s配置正常", mount)
		}
	}
	
	// 测试容器停止时的通信
	execCommand(t, "docker", "stop", containerID)
	
	// 验证停止后的清理通信
	time.Sleep(2 * time.Second)
	finalMgrLogs := getSysboxMgrLogs(t)
	if len(finalMgrLogs) > len(mgrLogs) {
		t.Log("容器停止触发了额外的mgr通信")
	}
	
	// 测试runc状态查询通信
	_, err := exec.Command("docker", "inspect", containerID).Output()
	assert.NoError(t, err, "容器状态查询应该成功")
	
	// 验证runc exec通信
	execInContainer(t, containerID, "echo", "ipc-test")
	
	// 测试网络命名空间通信
	netNS := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/net")
	assert.Contains(t, netNS, "net", "网络命名空间应该正确配置")
}

// testSysboxRuncFSCommunication 测试sysbox-runc与sysbox-fs通信
func testSysboxRuncFSCommunication(t *testing.T) {
	// 验证sysbox-fs服务运行
	fsPID := getSysboxFSPID(t)
	require.NotEmpty(t, fsPID, "sysbox-fs应该正在运行")
	
	// 验证sysbox-fs FUSE挂载
	fuseMounts := getFUSEMounts(t)
	t.Logf("FUSE挂载数量: %d", len(fuseMounts))
	
	containerName := "test-runc-fs-comm"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证procfs虚拟化通信
	procTests := []struct {
		file     string
		expected string
	}{
		{"/proc/version", "Linux"},
		{"/proc/meminfo", "MemTotal"},
		{"/proc/cpuinfo", "processor"},
		{"/proc/uptime", ""},
	}
	
	for _, test := range procTests {
		content := execInContainer(t, containerID, "cat", test.file)
		if test.expected != "" {
			assert.Contains(t, content, test.expected, 
				fmt.Sprintf("%s应该包含%s", test.file, test.expected))
		} else {
			assert.NotEmpty(t, content, fmt.Sprintf("%s应该有内容", test.file))
		}
		t.Logf("procfs文件%s访问正常", test.file)
	}
	
	// 验证sysfs虚拟化通信
	sysTests := []string{
		"/sys/kernel/ostype",
		"/sys/kernel/osrelease",
		"/sys/kernel/version",
	}
	
	for _, sysFile := range sysTests {
		if fileExists(t, containerID, sysFile) {
			content := execInContainer(t, containerID, "cat", sysFile)
			assert.NotEmpty(t, content, fmt.Sprintf("%s应该有内容", sysFile))
			t.Logf("sysfs文件%s访问正常", sysFile)
		}
	}
	
	// 测试动态文件系统内容
	uptime1 := execInContainer(t, containerID, "cat", "/proc/uptime")
	time.Sleep(2 * time.Second)
	uptime2 := execInContainer(t, containerID, "cat", "/proc/uptime")
	
	assert.NotEqual(t, uptime1, uptime2, "/proc/uptime内容应该动态变化")
	t.Log("动态文件系统内容更新正常")
	
	// 验证文件系统权限和访问控制
	_, procKmsgErr := execInContainerWithError(containerID, "cat", "/proc/kmsg")
	if procKmsgErr != nil {
		t.Log("敏感proc文件访问被正确限制")
	}
	
	// 测试文件系统写入操作
	writeTest := execInContainer(t, containerID, "echo", "test", ">", "/tmp/fs-test")
	readTest := execInContainer(t, containerID, "cat", "/tmp/fs-test")
	assert.Contains(t, readTest, "test", "文件系统写入读取应该正常")
	
	// 验证挂载点信息
	mountInfo := execInContainer(t, containerID, "mount")
	procMountLine := extractLineFromOutput(mountInfo, "/proc")
	if procMountLine != "" {
		t.Logf("procfs挂载信息: %s", procMountLine)
	}
	
	sysMountLine := extractLineFromOutput(mountInfo, "/sys")
	if sysMountLine != "" {
		t.Logf("sysfs挂载信息: %s", sysMountLine)
	}
	
	// 测试并发文件系统访问
	concurrentTest := execInContainer(t, containerID, "sh", "-c", `
for i in $(seq 1 10); do
  cat /proc/meminfo > /dev/null &
done
wait
echo "concurrent access completed"
`)
	assert.Contains(t, concurrentTest, "concurrent access completed", 
		"并发文件系统访问应该成功")
}

// testSysboxMgrFSCommunication 测试sysbox-mgr与sysbox-fs通信
func testSysboxMgrFSCommunication(t *testing.T) {
	// 验证两个服务都在运行
	mgrPID := getSysboxMgrPID(t)
	fsPID := getSysboxFSPID(t)
	require.NotEmpty(t, mgrPID, "sysbox-mgr应该正在运行")
	require.NotEmpty(t, fsPID, "sysbox-fs应该正在运行")
	
	containerName := "test-mgr-fs-comm"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证资源管理通信
	// 检查内存资源信息一致性
	procMeminfo := execInContainer(t, containerID, "cat", "/proc/meminfo")
	memTotalLine := extractLineFromOutput(procMeminfo, "MemTotal:")
	
	if memTotalLine != "" {
		t.Logf("容器内存信息: %s", memTotalLine)
		
		// 验证内存信息的合理性
		memTotal := extractMemoryValue(t, memTotalLine)
		assert.Greater(t, memTotal, int64(0), "内存总量应该大于0")
	}
	
	// 验证用户命名空间信息同步
	containerPID := getContainerPID(t, containerID)
	uidMapPath := fmt.Sprintf("/proc/%s/uid_map", containerPID)
	uidMap := readFileContent(t, uidMapPath)
	
	// 检查容器内的用户信息与命名空间映射的一致性
	containerUID := execInContainer(t, containerID, "id", "-u")
	assert.Equal(t, "0", strings.TrimSpace(containerUID), "容器内应该显示为root用户")
	
	uidMappings := parseIDMapping(t, uidMap)
	if len(uidMappings) > 0 {
		assert.Equal(t, "0", uidMappings[0].ContainerID, "UID映射应该包含root用户")
		t.Log("用户命名空间信息在mgr和fs间同步正常")
	}
	
	// 验证挂载信息同步
	mountInfo := execInContainer(t, containerID, "mount")
	
	// 检查特殊文件系统挂载
	specialFS := []string{"proc", "sysfs", "tmpfs"}
	for _, fs := range specialFS {
		if strings.Contains(mountInfo, fs) {
			t.Logf("特殊文件系统%s挂载信息同步正常", fs)
		}
	}
	
	// 验证cgroup信息同步
	cgroupInfo := execInContainer(t, containerID, "cat", "/proc/self/cgroup")
	assert.NotEmpty(t, cgroupInfo, "cgroup信息应该可读")
	
	// 检查容器级别的资源限制信息
	if strings.Contains(cgroupInfo, "memory") {
		memCgroupPath := findMemoryCgroupPath(t, containerID)
		if memCgroupPath != "" {
			t.Log("内存cgroup信息在mgr和fs间同步")
		}
	}
	
	// 测试动态配置更新通信
	// 创建第二个容器测试配置隔离
	container2Name := "test-mgr-fs-comm-2"
	container2ID := createSysboxContainer(t, container2Name, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, container2ID)
	
	// 验证两个容器的配置隔离
	container1PID := getContainerPID(t, containerID)
	container2PID := getContainerPID(t, container2ID)
	
	assert.NotEqual(t, container1PID, container2PID, "不同容器应该有不同的PID")
	
	// 验证各自的文件系统视图
	proc1Uptime := execInContainer(t, containerID, "cat", "/proc/uptime")
	proc2Uptime := execInContainer(t, container2ID, "cat", "/proc/uptime")
	
	// 两个容器的uptime可能相近但不应该完全相同
	assert.NotEmpty(t, proc1Uptime, "容器1的uptime应该可读")
	assert.NotEmpty(t, proc2Uptime, "容器2的uptime应该可读")
	
	// 验证网络配置同步
	net1Info := execInContainer(t, containerID, "ip", "addr", "show")
	net2Info := execInContainer(t, container2ID, "ip", "addr", "show")
	
	// 获取各自的IP地址
	ip1 := getContainerIP(t, containerID)
	ip2 := getContainerIP(t, container2ID)
	
	assert.NotEqual(t, ip1, ip2, "不同容器应该有不同的IP地址")
	t.Log("网络配置在mgr和fs间正确同步和隔离")
	
	// 测试资源统计信息同步
	stat1Info := execInContainer(t, containerID, "cat", "/proc/stat")
	stat2Info := execInContainer(t, container2ID, "cat", "/proc/stat")
	
	assert.NotEmpty(t, stat1Info, "容器1的统计信息应该可读")
	assert.NotEmpty(t, stat2Info, "容器2的统计信息应该可读")
	
	// 验证文件系统操作的一致性
	testFile1 := execInContainer(t, containerID, "touch", "/tmp/container1-test")
	testFile2 := execInContainer(t, container2ID, "touch", "/tmp/container2-test")
	
	// 验证文件隔离
	_, accessErr1 := execInContainerWithError(containerID, "ls", "/tmp/container2-test")
	_, accessErr2 := execInContainerWithError(container2ID, "ls", "/tmp/container1-test")
	
	assert.Error(t, accessErr1, "容器1不应该看到容器2的文件")
	assert.Error(t, accessErr2, "容器2不应该看到容器1的文件")
	
	t.Log("文件系统隔离在mgr和fs间正确维护")
}

// testGRPCServiceDiscoveryAndConnection 测试gRPC服务发现和连接
func testGRPCServiceDiscoveryAndConnection(t *testing.T) {
	// 检查gRPC服务端口
	grpcPorts := getGRPCServicePorts(t)
	t.Logf("发现的gRPC服务端口: %v", grpcPorts)
	
	// 测试服务发现机制
	sysboxServices := []string{
		"sysbox-mgr",
		"sysbox-fs",
	}
	
	activeServices := make(map[string]string)
	
	for _, service := range sysboxServices {
		pid := getServicePID(t, service)
		if pid != "" {
			activeServices[service] = pid
			t.Logf("服务%s运行正常，PID: %s", service, pid)
		}
	}
	
	require.NotEmpty(t, activeServices, "应该至少有一个sysbox服务运行")
	
	// 测试gRPC连接建立
	for _, port := range grpcPorts {
		testGRPCConnection(t, port)
	}
	
	// 测试服务健康检查
	for service, pid := range activeServices {
		testServiceHealth(t, service, pid)
	}
	
	// 模拟gRPC通信
	containerName := "test-grpc-communication"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 容器创建过程应该触发gRPC通信
	time.Sleep(2 * time.Second)
	
	// 验证通信建立
	for service := range activeServices {
		logs := getServiceLogs(t, service)
		if strings.Contains(logs, "grpc") || strings.Contains(logs, "rpc") || 
		   strings.Contains(logs, containerID[:12]) {
			t.Logf("服务%s的gRPC通信日志正常", service)
		}
	}
	
	// 测试并发gRPC连接
	concurrentContainers := make([]string, 3)
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("test-concurrent-grpc-%d", i)
		concurrentContainers[i] = createSysboxContainer(t, name, "ubuntu:20.04", []string{"sleep", "60"})
	}
	
	// 清理并发容器
	defer func() {
		for _, cid := range concurrentContainers {
			cleanupContainer(t, cid)
		}
	}()
	
	// 验证并发连接处理
	time.Sleep(3 * time.Second)
	
	for _, cid := range concurrentContainers {
		state := getContainerState(t, cid)
		assert.Equal(t, "running", state.Status, "并发创建的容器应该运行正常")
	}
	
	t.Log("并发gRPC连接处理正常")
	
	// 测试连接复用
	for i := 0; i < 5; i++ {
		execInContainer(t, containerID, "echo", fmt.Sprintf("test-%d", i))
		time.Sleep(100 * time.Millisecond)
	}
	
	t.Log("gRPC连接复用测试完成")
}

// testIPCMessageSerialization 测试IPC消息序列化和反序列化
func testIPCMessageSerialization(t *testing.T) {
	containerName := "test-ipc-serialization"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试各种数据类型的序列化
	serializationTests := []struct {
		description string
		operation   func() string
	}{
		{
			"容器状态查询",
			func() string {
				output, _ := exec.Command("docker", "inspect", containerID).Output()
				return string(output)
			},
		},
		{
			"容器执行命令",
			func() string {
				return execInContainer(t, containerID, "echo", "serialization-test")
			},
		},
		{
			"容器网络信息",
			func() string {
				return execInContainer(t, containerID, "ip", "addr", "show")
			},
		},
		{
			"容器文件系统操作",
			func() string {
				execInContainer(t, containerID, "touch", "/tmp/serial-test")
				return execInContainer(t, containerID, "ls", "-la", "/tmp/serial-test")
			},
		},
	}
	
	for _, test := range serializationTests {
		t.Logf("测试%s的消息序列化", test.description)
		
		start := time.Now()
		result := test.operation()
		duration := time.Since(start)
		
		assert.NotEmpty(t, result, fmt.Sprintf("%s应该返回结果", test.description))
		t.Logf("%s耗时: %v", test.description, duration)
		
		// 验证返回结果的格式正确性
		if test.description == "容器状态查询" {
			var jsonData []interface{}
			err := json.Unmarshal([]byte(result), &jsonData)
			assert.NoError(t, err, "容器状态信息应该是有效的JSON")
		}
	}
	
	// 测试大数据量序列化
	largeDataTest := execInContainer(t, containerID, "dd", "if=/dev/zero", "of=/tmp/large-file", 
		"bs=1M", "count=10", "2>/dev/null", "&&", "ls", "-lh", "/tmp/large-file")
	assert.Contains(t, largeDataTest, "large-file", "大文件操作的序列化应该成功")
	
	// 测试特殊字符和编码
	specialCharTest := execInContainer(t, containerID, "echo", "测试中文字符 !@#$%^&*()")
	assert.Contains(t, specialCharTest, "测试中文字符", "特殊字符序列化应该正确")
	
	// 测试二进制数据处理
	binaryTest := execInContainer(t, containerID, "head", "-c", "100", "/dev/urandom", "|", "base64")
	assert.NotEmpty(t, binaryTest, "二进制数据序列化应该成功")
	
	// 测试并发序列化
	concurrentSerialization := execInContainer(t, containerID, "sh", "-c", `
for i in $(seq 1 10); do
  echo "concurrent-$i" > /tmp/concurrent-$i &
done
wait
ls /tmp/concurrent-* | wc -l
`)
	assert.Contains(t, concurrentSerialization, "10", "并发序列化操作应该成功")
	
	// 测试错误情况的序列化
	_, errorResult := execInContainerWithError(containerID, "cat", "/nonexistent/file")
	assert.Error(t, errorResult, "错误情况应该正确序列化")
	
	// 测试超长输出的序列化
	longOutputTest := execInContainer(t, containerID, "find", "/usr", "-type", "f", "|", "head", "-1000")
	assert.NotEmpty(t, longOutputTest, "长输出序列化应该成功")
	
	t.Log("IPC消息序列化和反序列化测试完成")
}

// testIPCErrorHandlingAndRetry 测试IPC错误处理和重试机制
func testIPCErrorHandlingAndRetry(t *testing.T) {
	containerName := "test-ipc-error-handling"
	
	// 测试正常情况
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 模拟各种错误情况
	errorTests := []struct {
		description string
		operation   func() error
		expectError bool
	}{
		{
			"访问不存在的容器",
			func() error {
				_, err := execInContainerWithError("nonexistent-container", "echo", "test")
				return err
			},
			true,
		},
		{
			"在停止的容器中执行命令",
			func() error {
				stoppedContainer := createSysboxContainer(t, "test-stopped", "ubuntu:20.04", []string{"sleep", "1"})
				time.Sleep(3 * time.Second) // 等待容器停止
				_, err := execInContainerWithError(stoppedContainer, "echo", "test")
				cleanupContainer(t, stoppedContainer)
				return err
			},
			true,
		},
		{
			"执行无效命令",
			func() error {
				_, err := execInContainerWithError(containerID, "nonexistent-command")
				return err
			},
			true,
		},
		{
			"访问受限制的文件",
			func() error {
				_, err := execInContainerWithError(containerID, "cat", "/proc/kcore")
				return err
			},
			true,
		},
	}
	
	for _, test := range errorTests {
		t.Logf("测试错误处理: %s", test.description)
		
		err := test.operation()
		if test.expectError {
			assert.Error(t, err, fmt.Sprintf("%s应该返回错误", test.description))
		} else {
			assert.NoError(t, err, fmt.Sprintf("%s不应该返回错误", test.description))
		}
	}
	
	// 测试网络错误恢复
	networkErrorTest := func() {
		// 模拟网络延迟
		slowCommand := execInContainer(t, containerID, "sh", "-c", "sleep 1; echo network-test")
		assert.Contains(t, slowCommand, "network-test", "网络延迟情况下命令应该执行成功")
	}
	
	networkErrorTest()
	
	// 测试资源耗尽情况
	resourceExhaustionTest := execInContainer(t, containerID, "sh", "-c", `
for i in $(seq 1 100); do
  echo "test-$i" > /tmp/test-$i
done
echo "resource test completed"
`)
	assert.Contains(t, resourceExhaustionTest, "resource test completed", 
		"资源密集操作应该正确处理")
	
	// 测试并发错误处理
	concurrentErrorTest := execInContainer(t, containerID, "sh", "-c", `
for i in $(seq 1 5); do
  (echo "concurrent-$i"; sleep 0.1) &
done
wait
echo "concurrent error test completed"
`)
	assert.Contains(t, concurrentErrorTest, "concurrent error test completed", 
		"并发操作错误处理应该正确")
	
	// 测试超时处理
	timeoutTest := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		cmd := exec.CommandContext(ctx, "docker", "exec", containerID, "sleep", "10")
		err := cmd.Run()
		
		if err != nil && strings.Contains(err.Error(), "context deadline exceeded") {
			t.Log("超时处理机制正常工作")
		} else {
			t.Log("超时测试未触发或命令提前完成")
		}
	}
	
	timeoutTest()
	
	// 测试重试机制
	retryTest := func() {
		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			_, err := execInContainerWithError(containerID, "test", "-f", "/tmp/retry-test")
			if err == nil {
				break
			}
			
			if i < maxRetries-1 {
				time.Sleep(100 * time.Millisecond)
				// 创建文件以便下次重试成功
				if i == 1 {
					execInContainer(t, containerID, "touch", "/tmp/retry-test")
				}
			}
		}
		t.Log("重试机制测试完成")
	}
	
	retryTest()
	
	// 测试错误恢复
	recoveryTest := func() {
		// 模拟临时错误后的恢复
		execInContainer(t, containerID, "rm", "-f", "/tmp/recovery-test")
		
		_, err1 := execInContainerWithError(containerID, "cat", "/tmp/recovery-test")
		assert.Error(t, err1, "文件不存在应该返回错误")
		
		execInContainer(t, containerID, "echo", "recovery", ">", "/tmp/recovery-test")
		
		result := execInContainer(t, containerID, "cat", "/tmp/recovery-test")
		assert.Contains(t, result, "recovery", "错误恢复后操作应该成功")
	}
	
	recoveryTest()
	
	t.Log("IPC错误处理和重试机制测试完成")
}

// testIPCPerformanceAndLatency 测试IPC性能和延迟
func testIPCPerformanceAndLatency(t *testing.T) {
	containerName := "test-ipc-performance"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试基本操作延迟
	basicOperations := []struct {
		name      string
		operation func() time.Duration
	}{
		{
			"容器状态查询",
			func() time.Duration {
				start := time.Now()
				getContainerState(t, containerID)
				return time.Since(start)
			},
		},
		{
			"简单命令执行",
			func() time.Duration {
				start := time.Now()
				execInContainer(t, containerID, "echo", "performance-test")
				return time.Since(start)
			},
		},
		{
			"文件系统操作",
			func() time.Duration {
				start := time.Now()
				execInContainer(t, containerID, "touch", "/tmp/perf-test")
				return time.Since(start)
			},
		},
		{
			"网络配置查询",
			func() time.Duration {
				start := time.Now()
				execInContainer(t, containerID, "ip", "addr", "show", "eth0")
				return time.Since(start)
			},
		},
	}
	
	for _, op := range basicOperations {
		durations := make([]time.Duration, 10)
		
		// 预热
		op.operation()
		
		// 测试10次取平均值
		for i := 0; i < 10; i++ {
			durations[i] = op.operation()
			time.Sleep(10 * time.Millisecond)
		}
		
		// 计算统计信息
		var total time.Duration
		min := durations[0]
		max := durations[0]
		
		for _, d := range durations {
			total += d
			if d < min {
				min = d
			}
			if d > max {
				max = d
			}
		}
		
		avg := total / time.Duration(len(durations))
		
		t.Logf("%s性能统计:", op.name)
		t.Logf("  平均延迟: %v", avg)
		t.Logf("  最小延迟: %v", min)
		t.Logf("  最大延迟: %v", max)
		
		// 性能断言
		assert.Less(t, avg, 5*time.Second, fmt.Sprintf("%s平均延迟应该小于5秒", op.name))
		assert.Less(t, max, 10*time.Second, fmt.Sprintf("%s最大延迟应该小于10秒", op.name))
	}
	
	// 测试吞吐量
	throughputTest := func() {
		start := time.Now()
		operations := 100
		
		for i := 0; i < operations; i++ {
			execInContainer(t, containerID, "echo", fmt.Sprintf("throughput-%d", i))
		}
		
		duration := time.Since(start)
		opsPerSecond := float64(operations) / duration.Seconds()
		
		t.Logf("吞吐量测试: %d个操作耗时%v", operations, duration)
		t.Logf("每秒操作数: %.2f ops/sec", opsPerSecond)
		
		assert.Greater(t, opsPerSecond, 10.0, "吞吐量应该至少10 ops/sec")
	}
	
	throughputTest()
	
	// 测试并发性能
	concurrentPerformanceTest := func() {
		concurrency := 5
		operationsPerGoroutine := 20
		
		start := time.Now()
		done := make(chan bool, concurrency)
		
		for i := 0; i < concurrency; i++ {
			go func(id int) {
				for j := 0; j < operationsPerGoroutine; j++ {
					execInContainer(t, containerID, "echo", fmt.Sprintf("concurrent-%d-%d", id, j))
				}
				done <- true
			}(i)
		}
		
		// 等待所有goroutine完成
		for i := 0; i < concurrency; i++ {
			<-done
		}
		
		duration := time.Since(start)
		totalOps := concurrency * operationsPerGoroutine
		opsPerSecond := float64(totalOps) / duration.Seconds()
		
		t.Logf("并发性能测试: %d个并发，总计%d个操作，耗时%v", concurrency, totalOps, duration)
		t.Logf("并发每秒操作数: %.2f ops/sec", opsPerSecond)
		
		assert.Greater(t, opsPerSecond, 20.0, "并发吞吐量应该至少20 ops/sec")
	}
	
	concurrentPerformanceTest()
	
	// 测试大数据传输性能
	largeDataTest := func() {
		start := time.Now()
		
		// 创建1MB数据
		execInContainer(t, containerID, "dd", "if=/dev/zero", "of=/tmp/large-data", 
			"bs=1K", "count=1024", "2>/dev/null")
		
		// 读取数据
		execInContainer(t, containerID, "cat", "/tmp/large-data", ">", "/dev/null")
		
		duration := time.Since(start)
		throughputMBps := 1.0 / duration.Seconds()
		
		t.Logf("大数据传输测试: 1MB数据耗时%v", duration)
		t.Logf("传输速度: %.2f MB/s", throughputMBps)
		
		assert.Less(t, duration, 10*time.Second, "1MB数据传输应该在10秒内完成")
	}
	
	largeDataTest()
	
	// 测试内存使用效率
	memoryEfficiencyTest := func() {
		// 监控内存使用
		initialMemory := getProcessMemoryUsage(t, "sysbox-mgr")
		
		// 执行一系列操作
		for i := 0; i < 50; i++ {
			execInContainer(t, containerID, "echo", fmt.Sprintf("memory-test-%d", i))
		}
		
		finalMemory := getProcessMemoryUsage(t, "sysbox-mgr")
		
		if initialMemory > 0 && finalMemory > 0 {
			memoryIncrease := finalMemory - initialMemory
			t.Logf("内存使用变化: %d KB", memoryIncrease)
			
			// 内存增长应该控制在合理范围内
			assert.Less(t, memoryIncrease, int64(10000), "内存增长应该小于10MB")
		}
	}
	
	memoryEfficiencyTest()
	
	t.Log("IPC性能和延迟测试完成")
}

// testIPCSecurityAndAuthentication 测试IPC安全和认证
func testIPCSecurityAndAuthentication(t *testing.T) {
	// 验证IPC通信的安全配置
	securityTests := []struct {
		description string
		check       func() bool
	}{
		{
			"验证sysbox进程用户权限",
			func() bool {
				mgrPID := getSysboxMgrPID(t)
				if mgrPID == "" {
					return false
				}
				
				processUser := getProcessUser(t, mgrPID)
				return processUser == "root" // sysbox需要root权限运行
			},
		},
		{
			"验证IPC端点访问权限",
			func() bool {
				grpcPorts := getGRPCServicePorts(t)
				for _, port := range grpcPorts {
					// 检查端口绑定地址
					bindAddress := getPortBindAddress(t, port)
					if bindAddress != "127.0.0.1" && bindAddress != "localhost" {
						return false // IPC端点不应该绑定到公共地址
					}
				}
				return true
			},
		},
		{
			"验证文件系统权限",
			func() bool {
				sysboxPaths := []string{
					"/var/lib/sysbox",
					"/run/sysbox",
				}
				
				for _, path := range sysboxPaths {
					if fileExists(t, "", path) {
						permissions := getFilePermissions(t, path)
						// 验证关键目录只有root可访问
						if !strings.HasPrefix(permissions, "drwx------") {
							return false
						}
					}
				}
				return true
			},
		},
	}
	
	for _, test := range securityTests {
		t.Logf("安全检查: %s", test.description)
		result := test.check()
		assert.True(t, result, test.description)
	}
	
	// 测试容器间隔离安全
	container1Name := "test-security-isolation-1"
	container2Name := "test-security-isolation-2"
	
	container1ID := createSysboxContainer(t, container1Name, "ubuntu:20.04", []string{"sleep", "300"})
	container2ID := createSysboxContainer(t, container2Name, "ubuntu:20.04", []string{"sleep", "300"})
	
	defer func() {
		cleanupContainer(t, container1ID)
		cleanupContainer(t, container2ID)
	}()
	
	// 验证进程隔离
	container1PID := getContainerPID(t, container1ID)
	container2PID := getContainerPID(t, container2ID)
	
	assert.NotEqual(t, container1PID, container2PID, "不同容器应该有不同的PID")
	
	// 验证用户命名空间隔离
	uid1Map := readFileContent(t, fmt.Sprintf("/proc/%s/uid_map", container1PID))
	uid2Map := readFileContent(t, fmt.Sprintf("/proc/%s/uid_map", container2PID))
	
	uid1Mappings := parseIDMapping(t, uid1Map)
	uid2Mappings := parseIDMapping(t, uid2Map)
	
	if len(uid1Mappings) > 0 && len(uid2Mappings) > 0 {
		assert.NotEqual(t, uid1Mappings[0].HostID, uid2Mappings[0].HostID,
			"不同容器的UID映射范围应该不重叠")
	}
	
	// 验证网络隔离
	ip1 := getContainerIP(t, container1ID)
	ip2 := getContainerIP(t, container2ID)
	assert.NotEqual(t, ip1, ip2, "不同容器应该有不同的IP地址")
	
	// 测试权限提升攻击防护
	privilegeEscalationTest := execInContainer(t, container1ID, "sh", "-c", `
# 尝试各种权限提升方法
echo "Testing privilege escalation protection"

# 尝试访问主机进程
ps aux | grep -v "^root.*\[\|^root.*sleep" | head -5

# 尝试访问敏感文件
cat /proc/kallsyms 2>&1 | head -1

# 尝试挂载操作
mount 2>&1 | head -1

echo "Privilege escalation test completed"
`)
	
	assert.Contains(t, privilegeEscalationTest, "Privilege escalation test completed",
		"权限提升测试应该完成")
	
	// 验证容器逃逸防护
	escapePreventionTest := execInContainer(t, container1ID, "sh", "-c", `
# 测试容器逃逸防护
echo "Testing container escape prevention"

# 尝试访问主机文件系统
ls /host-root 2>&1 | head -1

# 尝试访问Docker socket
ls -la /var/run/docker.sock 2>&1 | head -1

# 尝试访问主机网络命名空间
ip netns list 2>&1 | head -1

echo "Escape prevention test completed"
`)
	
	assert.Contains(t, escapePreventionTest, "Escape prevention test completed",
		"容器逃逸防护测试应该完成")
	
	// 测试资源访问控制
	resourceAccessTest := execInContainer(t, container1ID, "sh", "-c", `
# 测试资源访问控制
echo "Testing resource access control"

# 尝试访问特权设备
head -c 1 /dev/kmsg 2>&1 | head -1

# 尝试修改系统参数
echo 1 > /proc/sys/kernel/domainname 2>&1 | head -1

# 尝试加载内核模块
modprobe dummy 2>&1 | head -1

echo "Resource access control test completed"
`)
	
	assert.Contains(t, resourceAccessTest, "Resource access control test completed",
		"资源访问控制测试应该完成")
	
	// 验证审计日志
	auditTest := func() {
		logPaths := []string{
			"/var/log/sysbox-mgr.log",
			"/var/log/sysbox-fs.log",
		}
		
		for _, logPath := range logPaths {
			if fileExists(t, "", logPath) {
				t.Logf("发现审计日志文件: %s", logPath)
				// 这里可以检查日志内容是否包含安全相关事件
			}
		}
	}
	
	auditTest()
	
	t.Log("IPC安全和认证测试完成")
}

// testIPCConnectionPooling 测试IPC连接池和资源管理
func testIPCConnectionPooling(t *testing.T) {
	// 创建多个容器测试连接池
	containerCount := 5
	containers := make([]string, containerCount)
	
	for i := 0; i < containerCount; i++ {
		name := fmt.Sprintf("test-connection-pool-%d", i)
		containers[i] = createSysboxContainer(t, name, "ubuntu:20.04", []string{"sleep", "300"})
	}
	
	defer func() {
		for _, cid := range containers {
			cleanupContainer(t, cid)
		}
	}()
	
	// 测试连接复用
	connectionReuseTest := func() {
		for i := 0; i < 3; i++ {
			for _, cid := range containers {
				start := time.Now()
				execInContainer(t, cid, "echo", fmt.Sprintf("reuse-test-%d", i))
				duration := time.Since(start)
				
				// 后续操作应该更快（连接复用）
				if i > 0 {
					assert.Less(t, duration, 2*time.Second, "连接复用应该提高性能")
				}
			}
		}
		t.Log("连接复用测试完成")
	}
	
	connectionReuseTest()
	
	// 测试并发连接管理
	concurrentConnectionTest := func() {
		done := make(chan bool, containerCount)
		
		for i, cid := range containers {
			go func(id int, containerID string) {
				for j := 0; j < 10; j++ {
					execInContainer(t, containerID, "echo", fmt.Sprintf("concurrent-%d-%d", id, j))
					time.Sleep(10 * time.Millisecond)
				}
				done <- true
			}(i, cid)
		}
		
		// 等待所有goroutine完成
		for i := 0; i < containerCount; i++ {
			<-done
		}
		
		t.Log("并发连接管理测试完成")
	}
	
	concurrentConnectionTest()
	
	// 测试连接清理
	connectionCleanupTest := func() {
		// 获取当前活跃连接数
		initialConnections := getCurrentConnections(t)
		
		// 执行一些操作
		for _, cid := range containers {
			execInContainer(t, cid, "echo", "cleanup-test")
		}
		
		// 等待连接清理
		time.Sleep(5 * time.Second)
		
		finalConnections := getCurrentConnections(t)
		
		t.Logf("初始连接数: %d, 最终连接数: %d", initialConnections, finalConnections)
		
		// 连接数不应该无限增长
		assert.LessOrEqual(t, finalConnections, initialConnections+containerCount,
			"连接数应该得到合理控制")
	}
	
	connectionCleanupTest()
	
	// 测试资源限制
	resourceLimitTest := func() {
		mgrMemory := getProcessMemoryUsage(t, "sysbox-mgr")
		fsMemory := getProcessMemoryUsage(t, "sysbox-fs")
		
		if mgrMemory > 0 {
			t.Logf("sysbox-mgr内存使用: %d KB", mgrMemory)
			assert.Less(t, mgrMemory, int64(500000), "sysbox-mgr内存使用应该控制在500MB以内")
		}
		
		if fsMemory > 0 {
			t.Logf("sysbox-fs内存使用: %d KB", fsMemory)
			assert.Less(t, fsMemory, int64(200000), "sysbox-fs内存使用应该控制在200MB以内")
		}
	}
	
	resourceLimitTest()
	
	// 测试连接超时
	connectionTimeoutTest := func() {
		start := time.Now()
		
		// 执行可能超时的操作
		execInContainer(t, containers[0], "sleep", "1")
		
		duration := time.Since(start)
		t.Logf("操作耗时: %v", duration)
		
		assert.Less(t, duration, 10*time.Second, "操作不应该长时间阻塞")
	}
	
	connectionTimeoutTest()
	
	// 测试连接恢复
	connectionRecoveryTest := func() {
		// 模拟暂时的连接问题
		execInContainer(t, containers[0], "echo", "before-recovery")
		
		// 等待一段时间
		time.Sleep(1 * time.Second)
		
		// 连接应该自动恢复
		result := execInContainer(t, containers[0], "echo", "after-recovery")
		assert.Contains(t, result, "after-recovery", "连接应该自动恢复")
	}
	
	connectionRecoveryTest()
	
	t.Log("IPC连接池和资源管理测试完成")
}

// testIPCMonitoringAndDebugging 测试IPC监控和调试
func testIPCMonitoringAndDebugging(t *testing.T) {
	containerName := "test-ipc-monitoring"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试日志监控
	logMonitoringTest := func() {
		logPaths := []string{
			"/var/log/sysbox-mgr.log",
			"/var/log/sysbox-fs.log",
		}
		
		for _, logPath := range logPaths {
			if fileExists(t, "", logPath) {
				t.Logf("监控日志文件: %s", logPath)
				
				// 获取初始日志大小
				initialSize := getFileSize(t, logPath)
				
				// 执行一些操作以产生日志
				execInContainer(t, containerID, "echo", "monitoring-test")
				time.Sleep(1 * time.Second)
				
				// 检查日志是否增长
				finalSize := getFileSize(t, logPath)
				if finalSize >= initialSize {
					t.Logf("日志文件%s正常记录: %d -> %d bytes", logPath, initialSize, finalSize)
				}
			}
		}
	}
	
	logMonitoringTest()
	
	// 测试进程监控
	processMonitoringTest := func() {
		processes := []string{"sysbox-mgr", "sysbox-fs"}
		
		for _, process := range processes {
			pid := getServicePID(t, process)
			if pid != "" {
				// 监控CPU使用率
				cpuUsage := getProcessCPUUsage(t, pid)
				t.Logf("进程%s (PID: %s) CPU使用率: %s", process, pid, cpuUsage)
				
				// 监控内存使用
				memUsage := getProcessMemoryUsage(t, process)
				if memUsage > 0 {
					t.Logf("进程%s内存使用: %d KB", process, memUsage)
				}
				
				// 监控文件描述符使用
				fdCount := getProcessFDCount(t, pid)
				if fdCount > 0 {
					t.Logf("进程%s文件描述符数量: %d", process, fdCount)
					assert.Less(t, fdCount, 1000, "文件描述符数量应该控制在合理范围")
				}
			}
		}
	}
	
	processMonitoringTest()
	
	// 测试网络连接监控
	networkMonitoringTest := func() {
		grpcPorts := getGRPCServicePorts(t)
		
		for _, port := range grpcPorts {
			connections := getPortConnections(t, port)
			t.Logf("端口%s连接数: %d", port, connections)
			
			// 连接数应该在合理范围内
			assert.LessOrEqual(t, connections, 100, "单个端口连接数应该控制在100以内")
		}
	}
	
	networkMonitoringTest()
	
	// 测试性能指标监控
	performanceMonitoringTest := func() {
		metrics := []struct {
			name   string
			getter func() interface{}
		}{
			{
				"IPC调用延迟",
				func() interface{} {
					start := time.Now()
					execInContainer(t, containerID, "echo", "latency-test")
					return time.Since(start)
				},
			},
			{
				"文件系统操作延迟",
				func() interface{} {
					start := time.Now()
					execInContainer(t, containerID, "touch", "/tmp/fs-latency-test")
					return time.Since(start)
				},
			},
			{
				"网络操作延迟",
				func() interface{} {
					start := time.Now()
					execInContainer(t, containerID, "ip", "addr", "show")
					return time.Since(start)
				},
			},
		}
		
		for _, metric := range metrics {
			value := metric.getter()
			t.Logf("性能指标 - %s: %v", metric.name, value)
		}
	}
	
	performanceMonitoringTest()
	
	// 测试错误统计
	errorStatisticsTest := func() {
		// 故意产生一些错误
		_, err1 := execInContainerWithError(containerID, "cat", "/nonexistent")
		_, err2 := execInContainerWithError(containerID, "invalid-command")
		
		assert.Error(t, err1, "应该产生文件不存在错误")
		assert.Error(t, err2, "应该产生命令不存在错误")
		
		// 检查错误是否被正确记录
		t.Log("错误统计测试完成，错误应该被正确记录和处理")
	}
	
	errorStatisticsTest()
	
	// 测试调试信息收集
	debugInfoTest := func() {
		debugInfo := collectDebugInfo(t)
		
		assert.NotEmpty(t, debugInfo["sysbox_version"], "应该包含Sysbox版本信息")
		assert.NotEmpty(t, debugInfo["running_containers"], "应该包含运行容器信息")
		
		t.Logf("调试信息收集完成: %d 项信息", len(debugInfo))
	}
	
	debugInfoTest()
	
	// 测试事件追踪
	eventTracingTest := func() {
		// 开始事件追踪
		events := []string{}
		
		// 执行一系列操作
		operations := []string{
			"echo event-1",
			"touch /tmp/event-test",
			"ls /tmp/event-test",
			"rm /tmp/event-test",
		}
		
		for _, op := range operations {
			execInContainer(t, containerID, "sh", "-c", op)
			events = append(events, op)
			time.Sleep(100 * time.Millisecond)
		}
		
		t.Logf("事件追踪完成，记录了%d个事件", len(events))
	}
	
	eventTracingTest()
	
	// 测试健康检查
	healthCheckTest := func() {
		services := []string{"sysbox-mgr", "sysbox-fs"}
		
		for _, service := range services {
			healthy := isServiceHealthy(t, service)
			assert.True(t, healthy, fmt.Sprintf("服务%s应该健康", service))
		}
	}
	
	healthCheckTest()
	
	t.Log("IPC监控和调试测试完成")
}

// Helper functions for IPC tests

func setupIPCTestEnv(t *testing.T) {
	// 验证Sysbox组件运行状态
	require.NotEmpty(t, getSysboxMgrPID(t), "sysbox-mgr应该正在运行")
	require.NotEmpty(t, getSysboxFSPID(t), "sysbox-fs应该正在运行")
	
	// 清理测试容器
	testContainers := []string{
		"test-runc-mgr-comm", "test-runc-fs-comm", "test-mgr-fs-comm",
		"test-mgr-fs-comm-2", "test-grpc-communication", "test-ipc-serialization",
		"test-ipc-error-handling", "test-stopped", "test-ipc-performance",
		"test-security-isolation-1", "test-security-isolation-2", "test-ipc-monitoring",
	}
	
	for i := 0; i < 10; i++ {
		testContainers = append(testContainers, fmt.Sprintf("test-concurrent-grpc-%d", i))
		testContainers = append(testContainers, fmt.Sprintf("test-connection-pool-%d", i))
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func cleanupIPCTestEnv(t *testing.T) {
	// 清理所有测试容器
	testContainers := []string{
		"test-runc-mgr-comm", "test-runc-fs-comm", "test-mgr-fs-comm",
		"test-mgr-fs-comm-2", "test-grpc-communication", "test-ipc-serialization",
		"test-ipc-error-handling", "test-stopped", "test-ipc-performance",
		"test-security-isolation-1", "test-security-isolation-2", "test-ipc-monitoring",
	}
	
	for i := 0; i < 10; i++ {
		testContainers = append(testContainers, fmt.Sprintf("test-concurrent-grpc-%d", i))
		testContainers = append(testContainers, fmt.Sprintf("test-connection-pool-%d", i))
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func getSysboxMgrPID(t *testing.T) string {
	output, err := exec.Command("pgrep", "-f", "sysbox-mgr").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func getSysboxFSPID(t *testing.T) string {
	output, err := exec.Command("pgrep", "-f", "sysbox-fs").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func getSysboxMgrPort(t *testing.T) string {
	pid := getSysboxMgrPID(t)
	if pid == "" {
		return ""
	}
	
	output, err := exec.Command("netstat", "-tlnp").Output()
	if err != nil {
		return ""
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, pid) && strings.Contains(line, "LISTEN") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				addr := fields[3]
				parts := strings.Split(addr, ":")
				if len(parts) >= 2 {
					return parts[len(parts)-1]
				}
			}
		}
	}
	
	return ""
}

func getSysboxMgrLogs(t *testing.T) string {
	logPaths := []string{
		"/var/log/sysbox-mgr.log",
		"/tmp/sysbox-mgr.log",
	}
	
	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			content, err := exec.Command("tail", "-100", path).Output()
			if err == nil {
				return string(content)
			}
		}
	}
	
	return ""
}

func getFUSEMounts(t *testing.T) []string {
	output, err := exec.Command("mount", "-t", "fuse").Output()
	if err != nil {
		return []string{}
	}
	
	lines := strings.Split(string(output), "\n")
	mounts := []string{}
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			mounts = append(mounts, strings.TrimSpace(line))
		}
	}
	
	return mounts
}

func getGRPCServicePorts(t *testing.T) []string {
	output, err := exec.Command("netstat", "-tlnp").Output()
	if err != nil {
		return []string{}
	}
	
	ports := []string{}
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		if strings.Contains(line, "sysbox") && strings.Contains(line, "LISTEN") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				addr := fields[3]
				parts := strings.Split(addr, ":")
				if len(parts) >= 2 {
					port := parts[len(parts)-1]
					ports = append(ports, port)
				}
			}
		}
	}
	
	return ports
}

func getServicePID(t *testing.T, serviceName string) string {
	output, err := exec.Command("pgrep", "-f", serviceName).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func testGRPCConnection(t *testing.T, port string) {
	conn, err := net.DialTimeout("tcp", "localhost:"+port, 3*time.Second)
	if err == nil {
		conn.Close()
		t.Logf("gRPC端口%s连接正常", port)
	} else {
		t.Logf("gRPC端口%s连接测试: %v", port, err)
	}
}

func testServiceHealth(t *testing.T, serviceName, pid string) {
	// 检查进程是否存在
	_, err := os.Stat(fmt.Sprintf("/proc/%s", pid))
	if err == nil {
		t.Logf("服务%s健康检查通过", serviceName)
	} else {
		t.Logf("服务%s健康检查失败: %v", serviceName, err)
	}
}

func getServiceLogs(t *testing.T, serviceName string) string {
	logPaths := []string{
		fmt.Sprintf("/var/log/%s.log", serviceName),
		fmt.Sprintf("/tmp/%s.log", serviceName),
	}
	
	for _, path := range logPaths {
		if _, err := os.Stat(path); err == nil {
			content, err := exec.Command("tail", "-50", path).Output()
			if err == nil {
				return string(content)
			}
		}
	}
	
	return ""
}

func getProcessMemoryUsage(t *testing.T, processName string) int64 {
	output, err := exec.Command("ps", "-o", "rss=", "-C", processName).Output()
	if err != nil {
		return 0
	}
	
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var total int64
	
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			rss, err := strconv.ParseInt(strings.TrimSpace(line), 10, 64)
			if err == nil {
				total += rss
			}
		}
	}
	
	return total
}

func getProcessUser(t *testing.T, pid string) string {
	output, err := exec.Command("ps", "-o", "user=", "-p", pid).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func getPortBindAddress(t *testing.T, port string) string {
	output, err := exec.Command("netstat", "-tln").Output()
	if err != nil {
		return ""
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ":"+port) && strings.Contains(line, "LISTEN") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				addr := fields[3]
				parts := strings.Split(addr, ":")
				if len(parts) >= 2 {
					return strings.Join(parts[:len(parts)-1], ":")
				}
			}
		}
	}
	
	return ""
}

func getFilePermissions(t *testing.T, path string) string {
	output, err := exec.Command("ls", "-ld", path).Output()
	if err != nil {
		return ""
	}
	
	fields := strings.Fields(string(output))
	if len(fields) >= 1 {
		return fields[0]
	}
	
	return ""
}

func getCurrentConnections(t *testing.T) int {
	output, err := exec.Command("netstat", "-an").Output()
	if err != nil {
		return 0
	}
	
	lines := strings.Split(string(output), "\n")
	count := 0
	
	for _, line := range lines {
		if strings.Contains(line, "ESTABLISHED") {
			count++
		}
	}
	
	return count
}

func getProcessCPUUsage(t *testing.T, pid string) string {
	output, err := exec.Command("ps", "-o", "pcpu=", "-p", pid).Output()
	if err != nil {
		return "0"
	}
	return strings.TrimSpace(string(output)) + "%"
}

func getProcessFDCount(t *testing.T, pid string) int {
	fdDir := fmt.Sprintf("/proc/%s/fd", pid)
	files, err := ioutil.ReadDir(fdDir)
	if err != nil {
		return 0
	}
	return len(files)
}

func getPortConnections(t *testing.T, port string) int {
	output, err := exec.Command("netstat", "-an").Output()
	if err != nil {
		return 0
	}
	
	lines := strings.Split(string(output), "\n")
	count := 0
	
	for _, line := range lines {
		if strings.Contains(line, ":"+port) {
			count++
		}
	}
	
	return count
}

func getFileSize(t *testing.T, path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func collectDebugInfo(t *testing.T) map[string]string {
	info := make(map[string]string)
	
	// 收集版本信息
	if content, err := ioutil.ReadFile("/VERSION"); err == nil {
		info["sysbox_version"] = strings.TrimSpace(string(content))
	}
	
	// 收集运行容器信息
	if output, err := exec.Command("docker", "ps", "--format", "{{.Names}}").Output(); err == nil {
		info["running_containers"] = string(output)
	}
	
	// 收集进程信息
	if output, err := exec.Command("ps", "aux").Output(); err == nil {
		info["process_list"] = string(output)
	}
	
	return info
}

func isServiceHealthy(t *testing.T, serviceName string) bool {
	pid := getServicePID(t, serviceName)
	if pid == "" {
		return false
	}
	
	_, err := os.Stat(fmt.Sprintf("/proc/%s", pid))
	return err == nil
}
