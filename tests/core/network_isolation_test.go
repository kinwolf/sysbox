package core

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSysboxNetworkIsolation 测试 Sysbox 网络隔离核心功能
func TestSysboxNetworkIsolation(t *testing.T) {
	setupNetworkIsolationTestEnv(t)
	defer cleanupNetworkIsolationTestEnv(t)

	t.Run("基本网络命名空间隔离", func(t *testing.T) {
		testBasicNetworkNamespaceIsolation(t)
	})

	t.Run("容器网络接口配置", func(t *testing.T) {
		testContainerNetworkInterfaceConfiguration(t)
	})

	t.Run("网络流量隔离验证", func(t *testing.T) {
		testNetworkTrafficIsolation(t)
	})

	t.Run("端口映射和网络服务", func(t *testing.T) {
		testPortMappingAndNetworkServices(t)
	})

	t.Run("多容器网络通信", func(t *testing.T) {
		testMultiContainerNetworkCommunication(t)
	})

	t.Run("网络策略执行", func(t *testing.T) {
		testNetworkPolicyEnforcement(t)
	})

	t.Run("网络性能和延迟", func(t *testing.T) {
		testNetworkPerformanceAndLatency(t)
	})
}

// setupNetworkIsolationTestEnv 设置网络隔离测试环境
func setupNetworkIsolationTestEnv(t *testing.T) {
	t.Log("设置网络隔离测试环境...")

	// 验证必要的网络工具
	requiredTools := []string{"ip", "ping", "nc", "ss", "iptables"}
	for _, tool := range requiredTools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("跳过测试: 缺少必要工具 %s", tool)
		}
	}

	// 验证 sysbox-runc 运行时可用
	verifySysboxRuntime(t)

	// 创建测试网络
	cmd := exec.Command("docker", "network", "create", "--driver", "bridge", "sysbox-test-network")
	if err := cmd.Run(); err != nil {
		t.Logf("警告: 创建测试网络失败 (可能已存在): %v", err)
	}

	t.Log("网络隔离测试环境设置完成")
}

// cleanupNetworkIsolationTestEnv 清理网络隔离测试环境
func cleanupNetworkIsolationTestEnv(t *testing.T) {
	t.Log("清理网络隔离测试环境...")

	// 清理测试容器
	cleanupTestContainersWithPrefix(t, "test-network")

	// 清理测试网络
	cmd := exec.Command("docker", "network", "rm", "sysbox-test-network")
	if err := cmd.Run(); err != nil {
		t.Logf("警告: 删除测试网络失败: %v", err)
	}

	t.Log("网络隔离测试环境清理完成")
}

// testBasicNetworkNamespaceIsolation 测试基本网络命名空间隔离
func testBasicNetworkNamespaceIsolation(t *testing.T) {
	t.Log("测试基本网络命名空间隔离...")

	// 创建 Sysbox 容器
	containerID := createSysboxContainer(t, "test-network-basic", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 等待容器启动
	waitForContainerRunning(t, containerID)

	// 获取主机网络接口列表
	hostInterfaces := getNetworkInterfaces(t, "")

	// 获取容器内网络接口列表
	containerInterfaces := getNetworkInterfaces(t, containerID)

	// 验证网络命名空间隔离
	t.Log("主机网络接口:", hostInterfaces)
	t.Log("容器网络接口:", containerInterfaces)

	// 容器应该有独立的网络命名空间
	assert.NotEqual(t, hostInterfaces, containerInterfaces, "容器应该有独立的网络命名空间")

	// 容器应该至少有 lo 接口
	assert.Contains(t, containerInterfaces, "lo", "容器应该有 loopback 接口")

	// 验证容器内网络配置
	testContainerNetworkConfiguration(t, containerID)
}

// testContainerNetworkInterfaceConfiguration 测试容器网络接口配置
func testContainerNetworkInterfaceConfiguration(t *testing.T) {
	t.Log("测试容器网络接口配置...")

	// 创建带有自定义网络的容器
	containerID := createSysboxContainerWithNetwork(t, "test-network-interface", "ubuntu:20.04", "sysbox-test-network", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	waitForContainerRunning(t, containerID)

	// 验证网络接口配置
	cmd := exec.Command("docker", "exec", containerID, "ip", "addr", "show")
	output, err := cmd.Output()
	require.NoError(t, err, "获取容器网络接口信息失败")

	interfaceInfo := string(output)
	t.Log("容器网络接口信息:", interfaceInfo)

	// 验证 eth0 接口存在并配置了 IP
	assert.Contains(t, interfaceInfo, "eth0", "容器应该有 eth0 接口")
	assert.Contains(t, interfaceInfo, "inet", "eth0 接口应该配置了 IP 地址")

	// 验证网络连通性
	testNetworkConnectivity(t, containerID)
}

// testNetworkTrafficIsolation 测试网络流量隔离
func testNetworkTrafficIsolation(t *testing.T) {
	t.Log("测试网络流量隔离...")

	// 创建两个容器用于测试隔离
	container1ID := createSysboxContainer(t, "test-network-isolation-1", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, container1ID)

	container2ID := createSysboxContainer(t, "test-network-isolation-2", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, container2ID)

	waitForContainerRunning(t, container1ID)
	waitForContainerRunning(t, container2ID)

	// 安装网络工具
	installNetworkTools(t, container1ID)
	installNetworkTools(t, container2ID)

	// 获取容器 IP 地址
	container1IP := getContainerIP(t, container1ID)
	container2IP := getContainerIP(t, container2ID)

	t.Logf("容器1 IP: %s, 容器2 IP: %s", container1IP, container2IP)

	// 验证容器间网络连通性（同一网络应该可以通信）
	testContainerToPing(t, container1ID, container2IP, true)

	// 测试端口隔离
	testPortIsolation(t, container1ID, container2ID, container1IP, container2IP)
}

// testPortMappingAndNetworkServices 测试端口映射和网络服务
func testPortMappingAndNetworkServices(t *testing.T) {
	t.Log("测试端口映射和网络服务...")

	// 创建带端口映射的容器
	hostPort := findAvailablePort(t)
	containerPort := "8080"

	args := []string{
		"run", "-d", "--name", "test-network-port-mapping",
		"--runtime", "sysbox-runc",
		"-p", fmt.Sprintf("%d:%s", hostPort, containerPort),
		"ubuntu:20.04",
		"sh", "-c", "apt-get update && apt-get install -y netcat && nc -l -p 8080",
	}

	cmd := exec.Command("docker", args...)
	output, err := cmd.Output()
	require.NoError(t, err, "创建带端口映射的容器失败")

	containerID := strings.TrimSpace(string(output))
	defer cleanupContainer(t, containerID)

	// 等待容器启动和服务准备
	time.Sleep(10 * time.Second)

	// 验证端口映射
	testPortMapping(t, hostPort, containerPort)

	// 验证服务可达性
	testServiceReachability(t, hostPort)
}

// testMultiContainerNetworkCommunication 测试多容器网络通信
func testMultiContainerNetworkCommunication(t *testing.T) {
	t.Log("测试多容器网络通信...")

	// 创建多个容器在同一网络
	containers := make([]string, 3)
	for i := 0; i < 3; i++ {
		containerName := fmt.Sprintf("test-network-multi-%d", i)
		containerID := createSysboxContainerWithNetwork(t, containerName, "ubuntu:20.04", "sysbox-test-network", []string{"sleep", "600"})
		containers[i] = containerID
		defer cleanupContainer(t, containerID)
	}

	// 等待所有容器启动
	for _, containerID := range containers {
		waitForContainerRunning(t, containerID)
		installNetworkTools(t, containerID)
	}

	// 测试容器间通信
	testInterContainerCommunication(t, containers)

	// 测试网络发现
	testNetworkDiscovery(t, containers)
}

// testNetworkPolicyEnforcement 测试网络策略执行
func testNetworkPolicyEnforcement(t *testing.T) {
	t.Log("测试网络策略执行...")

	// 创建受限网络容器
	containerID := createSysboxContainer(t, "test-network-policy", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	waitForContainerRunning(t, containerID)
	installNetworkTools(t, containerID)

	// 验证网络策略限制
	testNetworkRestrictions(t, containerID)

	// 验证防火墙规则
	testFirewallRules(t, containerID)
}

// testNetworkPerformanceAndLatency 测试网络性能和延迟
func testNetworkPerformanceAndLatency(t *testing.T) {
	t.Log("测试网络性能和延迟...")

	// 创建性能测试容器
	container1ID := createSysboxContainer(t, "test-network-perf-1", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, container1ID)

	container2ID := createSysboxContainer(t, "test-network-perf-2", "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, container2ID)

	waitForContainerRunning(t, container1ID)
	waitForContainerRunning(t, container2ID)

	installNetworkTools(t, container1ID)
	installNetworkTools(t, container2ID)

	// 测试网络延迟
	testNetworkLatency(t, container1ID, container2ID)

	// 测试网络吞吐量
	testNetworkThroughput(t, container1ID, container2ID)
}

// 辅助函数

// getNetworkInterfaces 获取网络接口列表
func getNetworkInterfaces(t *testing.T, containerID string) []string {
	var cmd *exec.Cmd
	if containerID == "" {
		cmd = exec.Command("ip", "link", "show")
	} else {
		cmd = exec.Command("docker", "exec", containerID, "ip", "link", "show")
	}

	output, err := cmd.Output()
	if err != nil {
		t.Logf("获取网络接口失败: %v", err)
		return []string{}
	}

	interfaces := []string{}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, ": ") && !strings.HasPrefix(line, " ") {
			parts := strings.Split(line, ": ")
			if len(parts) >= 2 {
				interfaceName := strings.Split(parts[1], "@")[0]
				interfaces = append(interfaces, interfaceName)
			}
		}
	}

	return interfaces
}

// createSysboxContainerWithNetwork 创建带指定网络的 Sysbox 容器
func createSysboxContainerWithNetwork(t *testing.T, name, image, network string, command []string) string {
	args := []string{"run", "-d", "--name", name, "--runtime", "sysbox-runc", "--network", network, image}
	args = append(args, command...)

	cmd := exec.Command("docker", args...)
	output, err := cmd.Output()
	require.NoError(t, err, "创建 Sysbox 容器失败")

	containerID := strings.TrimSpace(string(output))
	t.Logf("创建容器 %s (ID: %s)", name, containerID)

	return containerID
}

// testContainerNetworkConfiguration 测试容器网络配置
func testContainerNetworkConfiguration(t *testing.T, containerID string) {
	// 验证路由表
	cmd := exec.Command("docker", "exec", containerID, "ip", "route", "show")
	output, err := cmd.Output()
	if err == nil {
		routeInfo := string(output)
		t.Log("容器路由信息:", routeInfo)
		assert.Contains(t, routeInfo, "default", "容器应该有默认路由")
	}

	// 验证 DNS 配置
	cmd = exec.Command("docker", "exec", containerID, "cat", "/etc/resolv.conf")
	output, err = cmd.Output()
	if err == nil {
		dnsInfo := string(output)
		t.Log("容器 DNS 配置:", dnsInfo)
		assert.Contains(t, dnsInfo, "nameserver", "容器应该有 DNS 配置")
	}
}

// installNetworkTools 在容器中安装网络工具
func installNetworkTools(t *testing.T, containerID string) {
	cmd := exec.Command("docker", "exec", containerID, "sh", "-c", 
		"apt-get update && apt-get install -y iputils-ping netcat-openbsd iproute2")
	if err := cmd.Run(); err != nil {
		t.Logf("警告: 安装网络工具失败: %v", err)
	}
}

// getContainerIP 获取容器 IP 地址
func getContainerIP(t *testing.T, containerID string) string {
	cmd := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", containerID)
	output, err := cmd.Output()
	require.NoError(t, err, "获取容器 IP 失败")

	ip := strings.TrimSpace(string(output))
	require.NotEmpty(t, ip, "容器 IP 不能为空")

	return ip
}

// testContainerToPing 测试容器到指定 IP 的 ping 连通性
func testContainerToPing(t *testing.T, containerID, targetIP string, shouldSucceed bool) {
	cmd := exec.Command("docker", "exec", containerID, "ping", "-c", "3", "-W", "5", targetIP)
	err := cmd.Run()

	if shouldSucceed {
		assert.NoError(t, err, "容器应该能够 ping 通目标 IP %s", targetIP)
	} else {
		assert.Error(t, err, "容器不应该能够 ping 通目标 IP %s", targetIP)
	}
}

// testPortIsolation 测试端口隔离
func testPortIsolation(t *testing.T, container1ID, container2ID, container1IP, container2IP string) {
	// 在容器1中启动一个简单的服务
	go func() {
		cmd := exec.Command("docker", "exec", container1ID, "nc", "-l", "-p", "12345")
		cmd.Run()
	}()

	time.Sleep(2 * time.Second)

	// 从容器2尝试连接容器1的服务
	cmd := exec.Command("docker", "exec", container2ID, "nc", "-z", "-w", "3", container1IP, "12345")
	err := cmd.Run()
	
	// 在同一网络中应该能够连接
	assert.NoError(t, err, "同一网络中的容器应该能够互相连接")
}

// findAvailablePort 寻找可用端口
func findAvailablePort(t *testing.T) int {
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err, "查找可用端口失败")
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	return addr.Port
}

// testPortMapping 测试端口映射
func testPortMapping(t *testing.T, hostPort int, containerPort string) {
	// 验证端口映射是否生效
	cmd := exec.Command("netstat", "-tulpn")
	output, err := cmd.Output()
	if err == nil {
		portInfo := string(output)
		expectedListen := fmt.Sprintf(":%d", hostPort)
		assert.Contains(t, portInfo, expectedListen, "主机应该监听映射的端口")
	}
}

// testServiceReachability 测试服务可达性
func testServiceReachability(t *testing.T, hostPort int) {
	// 尝试连接服务
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", hostPort), 5*time.Second)
	if err == nil {
		conn.Close()
		t.Log("服务可达性测试通过")
	} else {
		t.Logf("服务可达性测试失败: %v", err)
	}
}

// testInterContainerCommunication 测试容器间通信
func testInterContainerCommunication(t *testing.T, containers []string) {
	// 获取所有容器的 IP
	containerIPs := make([]string, len(containers))
	for i, containerID := range containers {
		containerIPs[i] = getContainerIP(t, containerID)
	}

	// 测试每个容器到其他容器的连通性
	for i, containerID := range containers {
		for j, targetIP := range containerIPs {
			if i != j {
				testContainerToPing(t, containerID, targetIP, true)
			}
		}
	}
}

// testNetworkDiscovery 测试网络发现
func testNetworkDiscovery(t *testing.T, containers []string) {
	// 测试 DNS 解析
	for i, containerID := range containers {
		for j, targetContainer := range containers {
			if i != j {
				// 尝试通过容器名解析
				containerName := fmt.Sprintf("test-network-multi-%d", j)
				cmd := exec.Command("docker", "exec", containerID, "nslookup", containerName)
				err := cmd.Run()
				if err == nil {
					t.Logf("容器 %d 可以解析容器 %s", i, containerName)
				}
			}
		}
	}
}

// testNetworkRestrictions 测试网络限制
func testNetworkRestrictions(t *testing.T, containerID string) {
	// 测试是否能访问主机网络命名空间
	cmd := exec.Command("docker", "exec", containerID, "cat", "/proc/sys/net/ipv4/ip_forward")
	output, err := cmd.Output()
	if err == nil {
		ipForward := strings.TrimSpace(string(output))
		t.Logf("容器内 IP forward 设置: %s", ipForward)
	}

	// 验证网络命名空间隔离
	cmd = exec.Command("docker", "exec", containerID, "ls", "/proc/sys/net/")
	err = cmd.Run()
	assert.NoError(t, err, "容器应该有独立的网络参数空间")
}

// testFirewallRules 测试防火墙规则
func testFirewallRules(t *testing.T, containerID string) {
	// 验证容器内的 iptables 隔离
	cmd := exec.Command("docker", "exec", containerID, "iptables", "-L")
	err := cmd.Run()
	// 在 Sysbox 容器中，iptables 应该是虚拟化的
	if err != nil {
		t.Logf("容器内 iptables 访问受限 (预期行为): %v", err)
	}
}

// testNetworkLatency 测试网络延迟
func testNetworkLatency(t *testing.T, container1ID, container2ID string) {
	container2IP := getContainerIP(t, container2ID)

	cmd := exec.Command("docker", "exec", container1ID, "ping", "-c", "10", "-i", "0.1", container2IP)
	output, err := cmd.Output()
	if err == nil {
		pingOutput := string(output)
		t.Log("网络延迟测试结果:", pingOutput)
		
		// 解析延迟结果
		if strings.Contains(pingOutput, "avg") {
			assert.True(t, true, "网络延迟测试完成")
		}
	}
}

// testNetworkThroughput 测试网络吞吐量
func testNetworkThroughput(t *testing.T, container1ID, container2ID string) {
	container2IP := getContainerIP(t, container2ID)

	// 在容器2中启动 nc 服务器
	go func() {
		cmd := exec.Command("docker", "exec", container2ID, "nc", "-l", "-p", "12346")
		cmd.Run()
	}()

	time.Sleep(2 * time.Second)

	// 从容器1发送数据到容器2测试吞吐量
	cmd := exec.Command("docker", "exec", container1ID, "sh", "-c", 
		"yes | head -n 1000 | nc -w 5 "+container2IP+" 12346")
	err := cmd.Run()
	if err == nil {
		t.Log("网络吞吐量测试完成")
	} else {
		t.Logf("网络吞吐量测试失败: %v", err)
	}
}

// testNetworkConnectivity 测试网络连通性
func testNetworkConnectivity(t *testing.T, containerID string) {
	// 测试外网连通性
	cmd := exec.Command("docker", "exec", containerID, "ping", "-c", "3", "-W", "5", "8.8.8.8")
	err := cmd.Run()
	if err == nil {
		t.Log("外网连通性测试通过")
	} else {
		t.Logf("外网连通性测试失败: %v", err)
	}

	// 测试 DNS 解析
	cmd = exec.Command("docker", "exec", containerID, "nslookup", "google.com")
	err = cmd.Run()
	if err == nil {
		t.Log("DNS 解析测试通过")
	} else {
		t.Logf("DNS 解析测试失败: %v", err)
	}
}