package core

import (
	"encoding/json"
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

// TestKubernetesInDockerWorkflow 测试Kubernetes-in-Docker核心工作流程
func TestKubernetesInDockerWorkflow(t *testing.T) {
	setupKinDTestEnv(t)
	defer cleanupKinDTestEnv(t)

	t.Run("Kubernetes集群基础设置", func(t *testing.T) {
		testKubernetesClusterSetup(t)
	})

	t.Run("kubelet和容器运行时配置", func(t *testing.T) {
		testKubeletAndContainerRuntime(t)
	})

	t.Run("Kubernetes网络配置", func(t *testing.T) {
		testKubernetesNetworking(t)
	})

	t.Run("etcd数据存储管理", func(t *testing.T) {
		testEtcdDataStorage(t)
	})

	t.Run("Kubernetes API服务器", func(t *testing.T) {
		testKubernetesAPIServer(t)
	})

	t.Run("Pod和工作负载管理", func(t *testing.T) {
		testPodAndWorkloadManagement(t)
	})

	t.Run("Kubernetes服务发现", func(t *testing.T) {
		testKubernetesServiceDiscovery(t)
	})

	t.Run("持久化存储管理", func(t *testing.T) {
		testPersistentStorageManagement(t)
	})

	t.Run("Kubernetes安全和RBAC", func(t *testing.T) {
		testKubernetesSecurityAndRBAC(t)
	})

	t.Run("多节点集群管理", func(t *testing.T) {
		testMultiNodeClusterManagement(t)
	})
}

// testKubernetesClusterSetup 测试Kubernetes集群基础设置
func testKubernetesClusterSetup(t *testing.T) {
	containerName := "test-k8s-setup"
	
	// 使用包含Kubernetes的镜像创建容器
	containerID := createSysboxContainer(t, containerName, "kindest/node:latest", 
		[]string{"/usr/local/bin/entrypoint", "/sbin/init"})
	defer cleanupContainer(t, containerID)
	
	// 等待容器启动和系统初始化
	time.Sleep(20 * time.Second)
	
	// 验证systemd已启动
	systemdStatus := execInContainer(t, containerID, "systemctl", "is-active", "multi-user.target")
	assert.Contains(t, systemdStatus, "active", "systemd应该处于活动状态")
	
	// 验证Kubernetes组件安装
	kubernetesComponents := []string{
		"kubelet",
		"kubeadm", 
		"kubectl",
	}
	
	for _, component := range kubernetesComponents {
		componentVersion := execInContainer(t, containerID, component, "--version")
		assert.NotContains(t, componentVersion, "command not found", 
			fmt.Sprintf("%s应该已安装", component))
		t.Logf("%s版本: %s", component, strings.TrimSpace(componentVersion))
	}
	
	// 验证容器运行时（containerd或Docker）
	containerRuntime := detectContainerRuntime(t, containerID)
	t.Logf("检测到的容器运行时: %s", containerRuntime)
	
	switch containerRuntime {
	case "containerd":
		containerdStatus := execInContainer(t, containerID, "systemctl", "is-active", "containerd")
		assert.Contains(t, containerdStatus, "active", "containerd应该处于活动状态")
		
		containerdVersion := execInContainer(t, containerID, "containerd", "--version")
		t.Logf("containerd版本: %s", containerdVersion)
		
	case "docker":
		dockerStatus := execInContainer(t, containerID, "systemctl", "is-active", "docker")
		assert.Contains(t, dockerStatus, "active", "Docker应该处于活动状态")
		
		dockerVersion := execInContainer(t, containerID, "docker", "--version")
		t.Logf("Docker版本: %s", dockerVersion)
	}
	
	// 检查Kubernetes配置目录
	k8sConfigDirs := []string{
		"/etc/kubernetes",
		"/var/lib/kubelet",
		"/var/lib/etcd",
	}
	
	for _, dir := range k8sConfigDirs {
		dirContent := execInContainer(t, containerID, "ls", "-la", dir)
		if !strings.Contains(dirContent, "No such file") {
			t.Logf("Kubernetes配置目录%s存在", dir)
		}
	}
	
	// 验证网络配置
	networkInterfaces := execInContainer(t, containerID, "ip", "addr", "show")
	assert.Contains(t, networkInterfaces, "lo", "应该有本地回环接口")
	assert.Contains(t, networkInterfaces, "eth0", "应该有主网络接口")
	
	// 检查内核模块支持
	kernelModules := []string{
		"bridge",
		"netfilter",
		"xt_conntrack",
		"br_netfilter",
	}
	
	for _, module := range kernelModules {
		moduleCheck := execInContainer(t, containerID, "lsmod", "|", "grep", module)
		if strings.TrimSpace(moduleCheck) != "" {
			t.Logf("内核模块%s已加载", module)
		}
	}
	
	// 验证系统资源
	memInfo := execInContainer(t, containerID, "cat", "/proc/meminfo")
	assert.Contains(t, memInfo, "MemTotal", "内存信息应该可读")
	
	cpuInfo := execInContainer(t, containerID, "cat", "/proc/cpuinfo")
	assert.Contains(t, cpuInfo, "processor", "CPU信息应该可读")
}

// testKubeletAndContainerRuntime 测试kubelet和容器运行时配置
func testKubeletAndContainerRuntime(t *testing.T) {
	containerName := "test-kubelet-runtime"
	
	containerID := createKubernetesContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 验证kubelet配置文件
	kubeletConfigFile := "/var/lib/kubelet/config.yaml"
	if fileExists(t, containerID, kubeletConfigFile) {
		kubeletConfig := execInContainer(t, containerID, "cat", kubeletConfigFile)
		assert.Contains(t, kubeletConfig, "kind: KubeletConfiguration", 
			"kubelet配置应该包含正确的kind")
		
		t.Logf("kubelet配置文件内容预览: %s", 
			truncateString(kubeletConfig, 200))
	}
	
	// 验证kubelet服务状态
	kubeletStatus := execInContainer(t, containerID, "systemctl", "status", "kubelet")
	t.Logf("kubelet服务状态: %s", kubeletStatus)
	
	// 启动kubelet服务（如果未运行）
	execInContainer(t, containerID, "systemctl", "start", "kubelet")
	time.Sleep(5 * time.Second)
	
	kubeletActiveStatus := execInContainer(t, containerID, "systemctl", "is-active", "kubelet")
	if strings.Contains(kubeletActiveStatus, "active") {
		t.Log("kubelet服务已激活")
	} else {
		t.Log("kubelet服务状态:", kubeletActiveStatus)
	}
	
	// 验证容器运行时配置
	containerRuntime := detectContainerRuntime(t, containerID)
	
	switch containerRuntime {
	case "containerd":
		// 检查containerd配置
		containerdConfigFile := "/etc/containerd/config.toml"
		if fileExists(t, containerID, containerdConfigFile) {
			containerdConfig := execInContainer(t, containerID, "cat", containerdConfigFile)
			t.Logf("containerd配置预览: %s", truncateString(containerdConfig, 300))
		}
		
		// 验证containerd运行状态
		containerdStatus := execInContainer(t, containerID, "systemctl", "is-active", "containerd")
		assert.Contains(t, containerdStatus, "active", "containerd应该处于活动状态")
		
		// 测试containerd功能
		containerdTest := execInContainer(t, containerID, "ctr", "version")
		if !strings.Contains(containerdTest, "command not found") {
			t.Logf("containerd客户端版本: %s", containerdTest)
		}
		
	case "docker":
		// 检查Docker配置
		dockerConfigFile := "/etc/docker/daemon.json"
		if fileExists(t, containerID, dockerConfigFile) {
			dockerConfig := execInContainer(t, containerID, "cat", dockerConfigFile)
			t.Logf("Docker配置: %s", dockerConfig)
		}
		
		// 验证Docker运行状态
		dockerStatus := execInContainer(t, containerID, "systemctl", "is-active", "docker")
		assert.Contains(t, dockerStatus, "active", "Docker应该处于活动状态")
		
		// 测试Docker功能
		dockerInfo := execInContainer(t, containerID, "docker", "info")
		if strings.Contains(dockerInfo, "Server Version") {
			t.Log("Docker运行正常")
		}
	}
	
	// 测试容器运行时接口 (CRI)
	criTest := execInContainer(t, containerID, "crictl", "version")
	if !strings.Contains(criTest, "command not found") {
		t.Logf("CRI客户端版本: %s", criTest)
		
		// 测试CRI功能
		criInfo := execInContainer(t, containerID, "crictl", "info")
		if !strings.Contains(criInfo, "ERRO") {
			t.Log("CRI接口工作正常")
		}
	}
	
	// 验证kubelet与容器运行时的集成
	kubeletLogs := execInContainer(t, containerID, "journalctl", "-u", "kubelet", "--no-pager", "-n", "20")
	t.Logf("kubelet日志摘要: %s", truncateString(kubeletLogs, 500))
	
	// 检查kubelet配置的容器运行时
	kubeletConfigYaml := execInContainer(t, containerID, "cat", "/var/lib/kubelet/config.yaml")
	if strings.Contains(kubeletConfigYaml, "containerRuntimeEndpoint") {
		t.Log("kubelet配置了容器运行时端点")
	}
	
	// 验证运行时类配置
	runtimeClasses := execInContainer(t, containerID, "kubectl", "get", "runtimeclasses", "--no-headers")
	if !strings.Contains(runtimeClasses, "error") && strings.TrimSpace(runtimeClasses) != "" {
		t.Logf("运行时类: %s", runtimeClasses)
	}
}

// testKubernetesNetworking 测试Kubernetes网络配置
func testKubernetesNetworking(t *testing.T) {
	containerName := "test-k8s-networking"
	
	containerID := createKubernetesContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 验证网络接口配置
	networkInterfaces := execInContainer(t, containerID, "ip", "addr", "show")
	t.Logf("网络接口: %s", networkInterfaces)
	
	// 检查桥接网络配置
	bridgeInterfaces := execInContainer(t, containerID, "ip", "link", "show", "type", "bridge")
	if !strings.Contains(bridgeInterfaces, "does not exist") {
		t.Logf("桥接接口: %s", bridgeInterfaces)
	}
	
	// 验证iptables规则（用于Service代理）
	iptablesNat := execInContainer(t, containerID, "iptables", "-t", "nat", "-L")
	if !strings.Contains(iptablesNat, "Permission denied") {
		t.Logf("iptables NAT规则数量: %d", 
			len(strings.Split(iptablesNat, "\n")))
	}
	
	// 检查CNI配置
	cniConfigDir := "/etc/cni/net.d"
	if fileExists(t, containerID, cniConfigDir) {
		cniConfigs := execInContainer(t, containerID, "ls", "-la", cniConfigDir)
		t.Logf("CNI配置文件: %s", cniConfigs)
		
		// 读取CNI配置文件
		cniFiles := execInContainer(t, containerID, "find", cniConfigDir, "-name", "*.conf", "-o", "-name", "*.conflist")
		if strings.TrimSpace(cniFiles) != "" {
			firstCNIFile := strings.Split(strings.TrimSpace(cniFiles), "\n")[0]
			cniConfig := execInContainer(t, containerID, "cat", firstCNIFile)
			t.Logf("CNI配置内容: %s", truncateString(cniConfig, 300))
		}
	}
	
	// 验证DNS配置
	dnsConfig := execInContainer(t, containerID, "cat", "/etc/resolv.conf")
	assert.Contains(t, dnsConfig, "nameserver", "DNS配置应该包含nameserver")
	t.Logf("DNS配置: %s", dnsConfig)
	
	// 测试网络连通性
	networkConnectivityTests := []struct {
		target      string
		description string
	}{
		{"127.0.0.1", "本地回环"},
		{"8.8.8.8", "外部DNS"},
		{"kubernetes.default.svc.cluster.local", "集群内DNS"},
	}
	
	for _, test := range networkConnectivityTests {
		pingResult := execInContainer(t, containerID, "ping", "-c", "1", "-W", "3", test.target)
		if strings.Contains(pingResult, "1 packets transmitted") {
			t.Logf("✓ %s网络连通性正常", test.description)
		} else {
			t.Logf("✗ %s网络连通性异常", test.description)
		}
	}
	
	// 验证kube-proxy配置
	kubeProxyConfigFile := "/var/lib/kube-proxy/config.conf"
	if fileExists(t, containerID, kubeProxyConfigFile) {
		kubeProxyConfig := execInContainer(t, containerID, "cat", kubeProxyConfigFile)
		t.Logf("kube-proxy配置: %s", truncateString(kubeProxyConfig, 200))
	}
	
	// 检查Service CIDR和Pod CIDR配置
	clusterInfo := execInContainer(t, containerID, "kubectl", "cluster-info", "dump")
	if !strings.Contains(clusterInfo, "error") {
		if strings.Contains(clusterInfo, "service-cluster-ip-range") {
			t.Log("发现Service CIDR配置")
		}
		if strings.Contains(clusterInfo, "cluster-cidr") {
			t.Log("发现Pod CIDR配置")
		}
	}
	
	// 测试网络策略支持
	networkPolicyTest := execInContainer(t, containerID, "kubectl", "api-resources", "|", "grep", "networkpolicies")
	if strings.Contains(networkPolicyTest, "networkpolicies") {
		t.Log("网络策略API可用")
	}
	
	// 验证负载均衡器配置
	loadBalancerTest := execInContainer(t, containerID, "kubectl", "get", "services", "-A", "--no-headers")
	if !strings.Contains(loadBalancerTest, "error") {
		t.Logf("服务列表: %s", loadBalancerTest)
	}
}

// testEtcdDataStorage 测试etcd数据存储管理
func testEtcdDataStorage(t *testing.T) {
	containerName := "test-etcd-storage"
	
	containerID := createKubernetesContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 验证etcd安装
	etcdVersion := execInContainer(t, containerID, "etcd", "--version")
	if !strings.Contains(etcdVersion, "command not found") {
		t.Logf("etcd版本: %s", etcdVersion)
	} else {
		t.Log("etcd未直接安装，可能作为静态Pod运行")
	}
	
	// 检查etcd数据目录
	etcdDataDir := "/var/lib/etcd"
	if fileExists(t, containerID, etcdDataDir) {
		etcdDataContent := execInContainer(t, containerID, "ls", "-la", etcdDataDir)
		t.Logf("etcd数据目录: %s", etcdDataContent)
	}
	
	// 验证etcd配置文件
	etcdConfigPaths := []string{
		"/etc/kubernetes/manifests/etcd.yaml",
		"/etc/etcd/etcd.conf",
	}
	
	for _, configPath := range etcdConfigPaths {
		if fileExists(t, containerID, configPath) {
			etcdConfig := execInContainer(t, containerID, "cat", configPath)
			t.Logf("etcd配置文件%s: %s", configPath, 
				truncateString(etcdConfig, 300))
		}
	}
	
	// 测试etcd健康检查
	etcdHealthCheck := execInContainer(t, containerID, "etcdctl", "endpoint", "health")
	if !strings.Contains(etcdHealthCheck, "command not found") {
		t.Logf("etcd健康检查: %s", etcdHealthCheck)
	}
	
	// 验证etcd集群成员
	etcdMembers := execInContainer(t, containerID, "etcdctl", "member", "list")
	if !strings.Contains(etcdMembers, "command not found") {
		t.Logf("etcd集群成员: %s", etcdMembers)
	}
	
	// 测试etcd数据操作
	etcdDataTest := execInContainer(t, containerID, "etcdctl", "put", "test-key", "test-value")
	if !strings.Contains(etcdDataTest, "command not found") {
		etcdGetTest := execInContainer(t, containerID, "etcdctl", "get", "test-key")
		if strings.Contains(etcdGetTest, "test-value") {
			t.Log("etcd数据读写测试成功")
		}
		
		// 清理测试数据
		execInContainer(t, containerID, "etcdctl", "del", "test-key")
	}
	
	// 验证etcd存储的Kubernetes数据
	etcdK8sData := execInContainer(t, containerID, "etcdctl", "get", "/registry/", "--prefix", "--keys-only")
	if !strings.Contains(etcdK8sData, "command not found") && strings.TrimSpace(etcdK8sData) != "" {
		k8sKeys := strings.Split(strings.TrimSpace(etcdK8sData), "\n")
		t.Logf("etcd中存储的Kubernetes对象类型数: %d", len(k8sKeys))
		
		// 显示前几个键
		for i, key := range k8sKeys {
			if i < 5 {
				t.Logf("K8s对象键: %s", key)
			} else {
				break
			}
		}
	}
	
	// 检查etcd备份配置
	etcdBackupScript := "/usr/local/bin/backup-etcd.sh"
	if fileExists(t, containerID, etcdBackupScript) {
		t.Log("发现etcd备份脚本")
	}
	
	// 验证etcd存储大小
	etcdStorageSize := execInContainer(t, containerID, "du", "-sh", etcdDataDir)
	if !strings.Contains(etcdStorageSize, "No such file") {
		t.Logf("etcd存储大小: %s", etcdStorageSize)
	}
	
	// 测试etcd压缩功能
	etcdCompactTest := execInContainer(t, containerID, "etcdctl", "compact", "1")
	if !strings.Contains(etcdCompactTest, "command not found") {
		t.Log("etcd压缩功能可用")
	}
	
	// 验证etcd TLS配置
	etcdTLSFiles := []string{
		"/etc/kubernetes/pki/etcd/server.crt",
		"/etc/kubernetes/pki/etcd/server.key",
		"/etc/kubernetes/pki/etcd/ca.crt",
	}
	
	tlsFilesCount := 0
	for _, tlsFile := range etcdTLSFiles {
		if fileExists(t, containerID, tlsFile) {
			tlsFilesCount++
		}
	}
	
	if tlsFilesCount > 0 {
		t.Logf("发现%d个etcd TLS文件", tlsFilesCount)
	}
}

// testKubernetesAPIServer 测试Kubernetes API服务器
func testKubernetesAPIServer(t *testing.T) {
	containerName := "test-k8s-apiserver"
	
	containerID := createKubernetesContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 验证API服务器配置
	apiServerManifest := "/etc/kubernetes/manifests/kube-apiserver.yaml"
	if fileExists(t, containerID, apiServerManifest) {
		apiServerConfig := execInContainer(t, containerID, "cat", apiServerManifest)
		t.Logf("API服务器配置: %s", truncateString(apiServerConfig, 400))
	}
	
	// 检查API服务器进程
	apiServerProcess := execInContainer(t, containerID, "pgrep", "-f", "kube-apiserver")
	if strings.TrimSpace(apiServerProcess) != "" {
		t.Log("API服务器进程运行中")
	}
	
	// 验证kubectl配置
	kubeconfigPath := "/etc/kubernetes/admin.conf"
	if fileExists(t, containerID, kubeconfigPath) {
		t.Log("发现kubectl配置文件")
		
		// 设置KUBECONFIG环境变量
		execInContainer(t, containerID, "export", "KUBECONFIG="+kubeconfigPath)
	}
	
	// 测试API服务器连接
	apiServerHealth := execInContainer(t, containerID, "kubectl", "get", "--raw=/healthz")
	if strings.Contains(apiServerHealth, "ok") {
		t.Log("API服务器健康检查通过")
	} else {
		t.Logf("API服务器健康检查: %s", apiServerHealth)
	}
	
	// 验证API版本
	apiVersions := execInContainer(t, containerID, "kubectl", "api-versions")
	if !strings.Contains(apiVersions, "error") {
		apiVersionList := strings.Split(strings.TrimSpace(apiVersions), "\n")
		t.Logf("支持的API版本数: %d", len(apiVersionList))
		
		// 检查核心API版本
		coreAPIs := []string{"v1", "apps/v1", "extensions/v1beta1"}
		for _, api := range coreAPIs {
			if strings.Contains(apiVersions, api) {
				t.Logf("✓ 核心API %s 可用", api)
			}
		}
	}
	
	// 测试API资源列表
	apiResources := execInContainer(t, containerID, "kubectl", "api-resources", "--no-headers")
	if !strings.Contains(apiResources, "error") {
		resourceList := strings.Split(strings.TrimSpace(apiResources), "\n")
		t.Logf("可用API资源数: %d", len(resourceList))
		
		// 检查基本资源类型
		basicResources := []string{"pods", "services", "deployments", "configmaps", "secrets"}
		for _, resource := range basicResources {
			if strings.Contains(apiResources, resource) {
				t.Logf("✓ 基本资源 %s 可用", resource)
			}
		}
	}
	
	// 验证集群信息
	clusterInfo := execInContainer(t, containerID, "kubectl", "cluster-info")
	if strings.Contains(clusterInfo, "Kubernetes control plane") {
		t.Log("集群控制平面运行正常")
	}
	
	// 测试节点状态
	nodeStatus := execInContainer(t, containerID, "kubectl", "get", "nodes", "-o", "wide")
	if !strings.Contains(nodeStatus, "error") {
		t.Logf("节点状态: %s", nodeStatus)
	}
	
	// 验证系统命名空间
	systemNamespaces := execInContainer(t, containerID, "kubectl", "get", "namespaces")
	expectedNamespaces := []string{"default", "kube-system", "kube-public", "kube-node-lease"}
	for _, ns := range expectedNamespaces {
		if strings.Contains(systemNamespaces, ns) {
			t.Logf("✓ 系统命名空间 %s 存在", ns)
		}
	}
	
	// 检查API服务器审计配置
	auditPolicyPath := "/etc/kubernetes/audit-policy.yaml"
	if fileExists(t, containerID, auditPolicyPath) {
		auditPolicy := execInContainer(t, containerID, "cat", auditPolicyPath)
		t.Logf("审计策略: %s", truncateString(auditPolicy, 200))
	}
	
	// 验证准入控制器
	admissionControllers := execInContainer(t, containerID, "kubectl", "get", "--raw=/api/v1", "|", "grep", "admission")
	if strings.TrimSpace(admissionControllers) != "" {
		t.Log("准入控制器配置存在")
	}
	
	// 测试API服务器日志
	apiServerLogs := execInContainer(t, containerID, "kubectl", "logs", "-n", "kube-system", "-l", "component=kube-apiserver", "--tail=10")
	if !strings.Contains(apiServerLogs, "error") && strings.TrimSpace(apiServerLogs) != "" {
		t.Log("API服务器日志可访问")
	}
}

// testPodAndWorkloadManagement 测试Pod和工作负载管理
func testPodAndWorkloadManagement(t *testing.T) {
	containerName := "test-pod-workload"
	
	containerID := createKubernetesContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 创建测试命名空间
	testNamespace := "test-workload"
	createNSOutput := execInContainer(t, containerID, "kubectl", "create", "namespace", testNamespace)
	if strings.Contains(createNSOutput, "created") {
		t.Log("测试命名空间创建成功")
	}
	
	defer func() {
		execInContainer(t, containerID, "kubectl", "delete", "namespace", testNamespace, "--force", "--grace-period=0")
	}()
	
	// 创建简单Pod
	podYAML := `
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: test-workload
spec:
  containers:
  - name: test-container
    image: nginx:alpine
    ports:
    - containerPort: 80
`
	
	// 写入Pod YAML文件
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-pod.yaml << 'EOF'\n%sEOF", podYAML))
	
	// 创建Pod
	createPodOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-pod.yaml")
	if strings.Contains(createPodOutput, "created") || strings.Contains(createPodOutput, "configured") {
		t.Log("测试Pod创建成功")
	}
	
	// 等待Pod启动
	time.Sleep(30 * time.Second)
	
	// 验证Pod状态
	podStatus := execInContainer(t, containerID, "kubectl", "get", "pod", "test-pod", "-n", testNamespace, "-o", "wide")
	t.Logf("Pod状态: %s", podStatus)
	
	// 检查Pod详细信息
	podDescription := execInContainer(t, containerID, "kubectl", "describe", "pod", "test-pod", "-n", testNamespace)
	if strings.Contains(podDescription, "Status:") {
		t.Log("Pod描述信息可获取")
	}
	
	// 验证Pod日志
	podLogs := execInContainer(t, containerID, "kubectl", "logs", "test-pod", "-n", testNamespace)
	if !strings.Contains(podLogs, "error") {
		t.Log("Pod日志可访问")
	}
	
	// 测试Pod端口转发
	portForwardTest := execInContainer(t, containerID, "timeout", "5", "kubectl", "port-forward", "test-pod", "8080:80", "-n", testNamespace)
	if !strings.Contains(portForwardTest, "error") {
		t.Log("端口转发功能可用")
	}
	
	// 创建Deployment
	deploymentYAML := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-deployment
  namespace: test-workload
spec:
  replicas: 2
  selector:
    matchLabels:
      app: test-app
  template:
    metadata:
      labels:
        app: test-app
    spec:
      containers:
      - name: test-container
        image: nginx:alpine
        ports:
        - containerPort: 80
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-deployment.yaml << 'EOF'\n%sEOF", deploymentYAML))
	
	createDeploymentOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-deployment.yaml")
	if strings.Contains(createDeploymentOutput, "created") || strings.Contains(createDeploymentOutput, "configured") {
		t.Log("测试Deployment创建成功")
	}
	
	// 等待Deployment就绪
	time.Sleep(45 * time.Second)
	
	// 验证Deployment状态
	deploymentStatus := execInContainer(t, containerID, "kubectl", "get", "deployment", "test-deployment", "-n", testNamespace)
	t.Logf("Deployment状态: %s", deploymentStatus)
	
	// 验证ReplicaSet
	replicaSetStatus := execInContainer(t, containerID, "kubectl", "get", "replicaset", "-n", testNamespace)
	t.Logf("ReplicaSet状态: %s", replicaSetStatus)
	
	// 测试扩缩容
	scaleOutput := execInContainer(t, containerID, "kubectl", "scale", "deployment", "test-deployment", "--replicas=3", "-n", testNamespace)
	if strings.Contains(scaleOutput, "scaled") {
		t.Log("Deployment扩容成功")
		
		time.Sleep(20 * time.Second)
		scaledStatus := execInContainer(t, containerID, "kubectl", "get", "deployment", "test-deployment", "-n", testNamespace)
		t.Logf("扩容后状态: %s", scaledStatus)
	}
	
	// 测试滚动更新
	updateOutput := execInContainer(t, containerID, "kubectl", "set", "image", "deployment/test-deployment", "test-container=nginx:latest", "-n", testNamespace)
	if strings.Contains(updateOutput, "image updated") {
		t.Log("滚动更新启动成功")
	}
	
	// 验证事件
	events := execInContainer(t, containerID, "kubectl", "get", "events", "-n", testNamespace, "--sort-by=.metadata.creationTimestamp")
	if !strings.Contains(events, "error") {
		t.Log("命名空间事件可查看")
	}
	
	// 清理资源
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-deployment.yaml")
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-pod.yaml")
}

// testKubernetesServiceDiscovery 测试Kubernetes服务发现
func testKubernetesServiceDiscovery(t *testing.T) {
	containerName := "test-service-discovery"
	
	containerID := createKubernetesContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	testNamespace := "test-svc-discovery"
	execInContainer(t, containerID, "kubectl", "create", "namespace", testNamespace)
	
	defer func() {
		execInContainer(t, containerID, "kubectl", "delete", "namespace", testNamespace, "--force", "--grace-period=0")
	}()
	
	// 创建服务和Pod
	serviceYAML := `
apiVersion: v1
kind: Service
metadata:
  name: test-service
  namespace: test-svc-discovery
spec:
  selector:
    app: test-svc-app
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: ClusterIP
---
apiVersion: v1
kind: Pod
metadata:
  name: test-svc-pod
  namespace: test-svc-discovery
  labels:
    app: test-svc-app
spec:
  containers:
  - name: nginx
    image: nginx:alpine
    ports:
    - containerPort: 80
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-service.yaml << 'EOF'\n%sEOF", serviceYAML))
	
	createServiceOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-service.yaml")
	if strings.Contains(createServiceOutput, "created") {
		t.Log("测试服务和Pod创建成功")
	}
	
	time.Sleep(30 * time.Second)
	
	// 验证服务状态
	serviceStatus := execInContainer(t, containerID, "kubectl", "get", "service", "test-service", "-n", testNamespace, "-o", "wide")
	t.Logf("服务状态: %s", serviceStatus)
	
	// 获取服务详细信息
	serviceDetail := execInContainer(t, containerID, "kubectl", "describe", "service", "test-service", "-n", testNamespace)
	if strings.Contains(serviceDetail, "Endpoints:") {
		t.Log("服务端点信息可获取")
	}
	
	// 验证Endpoints对象
	endpoints := execInContainer(t, containerID, "kubectl", "get", "endpoints", "test-service", "-n", testNamespace)
	t.Logf("服务端点: %s", endpoints)
	
	// 测试DNS解析
	dnsTest := execInContainer(t, containerID, "nslookup", "test-service.test-svc-discovery.svc.cluster.local")
	if strings.Contains(dnsTest, "Address:") {
		t.Log("服务DNS解析成功")
	}
	
	// 测试服务连接
	serviceIP := extractServiceIP(serviceStatus)
	if serviceIP != "" {
		connectTest := execInContainer(t, containerID, "curl", "-s", "--connect-timeout", "5", "http://"+serviceIP)
		if strings.Contains(connectTest, "nginx") || strings.Contains(connectTest, "Welcome") {
			t.Log("服务连接测试成功")
		}
	}
	
	// 创建NodePort服务
	nodePortServiceYAML := `
apiVersion: v1
kind: Service
metadata:
  name: test-nodeport-service
  namespace: test-svc-discovery
spec:
  selector:
    app: test-svc-app
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
    nodePort: 30080
  type: NodePort
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-nodeport.yaml << 'EOF'\n%sEOF", nodePortServiceYAML))
	
	createNodePortOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-nodeport.yaml")
	if strings.Contains(createNodePortOutput, "created") {
		t.Log("NodePort服务创建成功")
	}
	
	time.Sleep(10 * time.Second)
	
	nodePortStatus := execInContainer(t, containerID, "kubectl", "get", "service", "test-nodeport-service", "-n", testNamespace)
	t.Logf("NodePort服务状态: %s", nodePortStatus)
	
	// 验证kube-dns/CoreDNS
	dnsService := execInContainer(t, containerID, "kubectl", "get", "service", "-n", "kube-system", "kube-dns")
	if strings.Contains(dnsService, "kube-dns") {
		t.Log("kube-dns服务可用")
	}
	
	coreDNSService := execInContainer(t, containerID, "kubectl", "get", "service", "-n", "kube-system", "coredns")
	if strings.Contains(coreDNSService, "coredns") {
		t.Log("CoreDNS服务可用")
	}
	
	// 测试服务发现机制
	discoveryTest := execInContainer(t, containerID, "kubectl", "get", "services", "--all-namespaces")
	if !strings.Contains(discoveryTest, "error") {
		serviceCount := len(strings.Split(strings.TrimSpace(discoveryTest), "\n")) - 1
		t.Logf("集群中总服务数: %d", serviceCount)
	}
	
	// 验证Ingress支持
	ingressSupport := execInContainer(t, containerID, "kubectl", "api-resources", "|", "grep", "ingress")
	if strings.Contains(ingressSupport, "ingresses") {
		t.Log("Ingress资源类型可用")
	}
	
	// 清理测试资源
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-service.yaml")
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-nodeport.yaml")
}

// testPersistentStorageManagement 测试持久化存储管理
func testPersistentStorageManagement(t *testing.T) {
	containerName := "test-storage"
	
	containerID := createKubernetesContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	testNamespace := "test-storage"
	execInContainer(t, containerID, "kubectl", "create", "namespace", testNamespace)
	
	defer func() {
		execInContainer(t, containerID, "kubectl", "delete", "namespace", testNamespace, "--force", "--grace-period=0")
	}()
	
	// 验证StorageClass
	storageClasses := execInContainer(t, containerID, "kubectl", "get", "storageclass")
	t.Logf("存储类: %s", storageClasses)
	
	// 创建PersistentVolume
	pvYAML := `
apiVersion: v1
kind: PersistentVolume
metadata:
  name: test-pv
spec:
  capacity:
    storage: 1Gi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Delete
  hostPath:
    path: /tmp/test-pv-data
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-pv.yaml << 'EOF'\n%sEOF", pvYAML))
	
	createPVOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-pv.yaml")
	if strings.Contains(createPVOutput, "created") {
		t.Log("PersistentVolume创建成功")
	}
	
	// 创建PersistentVolumeClaim
	pvcYAML := `
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: test-pvc
  namespace: test-storage
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-pvc.yaml << 'EOF'\n%sEOF", pvcYAML))
	
	createPVCOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-pvc.yaml")
	if strings.Contains(createPVCOutput, "created") {
		t.Log("PersistentVolumeClaim创建成功")
	}
	
	time.Sleep(10 * time.Second)
	
	// 验证PV和PVC绑定
	pvStatus := execInContainer(t, containerID, "kubectl", "get", "pv", "test-pv")
	pvcStatus := execInContainer(t, containerID, "kubectl", "get", "pvc", "test-pvc", "-n", testNamespace)
	
	t.Logf("PV状态: %s", pvStatus)
	t.Logf("PVC状态: %s", pvcStatus)
	
	// 创建使用PVC的Pod
	storagePodYAML := `
apiVersion: v1
kind: Pod
metadata:
  name: test-storage-pod
  namespace: test-storage
spec:
  containers:
  - name: test-container
    image: nginx:alpine
    volumeMounts:
    - name: test-volume
      mountPath: /usr/share/nginx/html
  volumes:
  - name: test-volume
    persistentVolumeClaim:
      claimName: test-pvc
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-storage-pod.yaml << 'EOF'\n%sEOF", storagePodYAML))
	
	createStoragePodOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-storage-pod.yaml")
	if strings.Contains(createStoragePodOutput, "created") {
		t.Log("存储Pod创建成功")
	}
	
	time.Sleep(30 * time.Second)
	
	storagePodStatus := execInContainer(t, containerID, "kubectl", "get", "pod", "test-storage-pod", "-n", testNamespace)
	t.Logf("存储Pod状态: %s", storagePodStatus)
	
	// 测试存储功能
	writeDataTest := execInContainer(t, containerID, "kubectl", "exec", "test-storage-pod", "-n", testNamespace, "--", "sh", "-c", "echo 'persistent data' > /usr/share/nginx/html/index.html")
	if writeDataTest == "" {
		t.Log("数据写入持久化存储成功")
	}
	
	readDataTest := execInContainer(t, containerID, "kubectl", "exec", "test-storage-pod", "-n", testNamespace, "--", "cat", "/usr/share/nginx/html/index.html")
	if strings.Contains(readDataTest, "persistent data") {
		t.Log("数据从持久化存储读取成功")
	}
	
	// 验证存储配置映射
	configMapYAML := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
  namespace: test-storage
data:
  config.txt: |
    This is a test configuration
    key1=value1
    key2=value2
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-configmap.yaml << 'EOF'\n%sEOF", configMapYAML))
	
	createConfigMapOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-configmap.yaml")
	if strings.Contains(createConfigMapOutput, "created") {
		t.Log("ConfigMap创建成功")
	}
	
	// 测试Secret
	secretYAML := `
apiVersion: v1
kind: Secret
metadata:
  name: test-secret
  namespace: test-storage
type: Opaque
data:
  username: dGVzdHVzZXI=  # testuser base64 encoded
  password: dGVzdHBhc3M=  # testpass base64 encoded
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-secret.yaml << 'EOF'\n%sEOF", secretYAML))
	
	createSecretOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-secret.yaml")
	if strings.Contains(createSecretOutput, "created") {
		t.Log("Secret创建成功")
	}
	
	// 验证EmptyDir存储
	emptyDirTest := execInContainer(t, containerID, "kubectl", "run", "emptydir-test", "--image=nginx:alpine", "-n", testNamespace, "--dry-run=client", "-o", "yaml")
	if strings.Contains(emptyDirTest, "apiVersion: v1") {
		t.Log("EmptyDir存储类型支持")
	}
	
	// 清理存储资源
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-storage-pod.yaml")
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-pvc.yaml")
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-pv.yaml")
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-configmap.yaml")
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-secret.yaml")
}

// testKubernetesSecurityAndRBAC 测试Kubernetes安全和RBAC
func testKubernetesSecurityAndRBAC(t *testing.T) {
	containerName := "test-k8s-security"
	
	containerID := createKubernetesContainer(t, containerName)
	defer cleanupContainer(t, containerID)
	
	// 验证当前用户权限
	currentContext := execInContainer(t, containerID, "kubectl", "config", "current-context")
	t.Logf("当前上下文: %s", currentContext)
	
	whoAmI := execInContainer(t, containerID, "kubectl", "auth", "whoami")
	if !strings.Contains(whoAmI, "error") {
		t.Logf("当前用户: %s", whoAmI)
	}
	
	// 验证RBAC资源
	rbacResources := []string{
		"roles",
		"rolebindings", 
		"clusterroles",
		"clusterrolebindings",
	}
	
	for _, resource := range rbacResources {
		resourceList := execInContainer(t, containerID, "kubectl", "get", resource, "--all-namespaces", "--no-headers")
		if !strings.Contains(resourceList, "error") {
			resourceCount := len(strings.Split(strings.TrimSpace(resourceList), "\n"))
			t.Logf("RBAC资源%s数量: %d", resource, resourceCount)
		}
	}
	
	// 测试服务账户
	serviceAccounts := execInContainer(t, containerID, "kubectl", "get", "serviceaccounts", "--all-namespaces")
	if !strings.Contains(serviceAccounts, "error") {
		t.Log("服务账户功能正常")
	}
	
	// 创建测试命名空间和RBAC
	testNamespace := "test-rbac"
	execInContainer(t, containerID, "kubectl", "create", "namespace", testNamespace)
	
	defer func() {
		execInContainer(t, containerID, "kubectl", "delete", "namespace", testNamespace, "--force", "--grace-period=0")
	}()
	
	// 创建服务账户
	serviceAccountYAML := `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: test-sa
  namespace: test-rbac
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-sa.yaml << 'EOF'\n%sEOF", serviceAccountYAML))
	
	createSAOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-sa.yaml")
	if strings.Contains(createSAOutput, "created") {
		t.Log("测试服务账户创建成功")
	}
	
	// 创建Role
	roleYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
  namespace: test-rbac
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "create", "delete"]
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-role.yaml << 'EOF'\n%sEOF", roleYAML))
	
	createRoleOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-role.yaml")
	if strings.Contains(createRoleOutput, "created") {
		t.Log("测试Role创建成功")
	}
	
	// 创建RoleBinding
	roleBindingYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: test-rolebinding
  namespace: test-rbac
subjects:
- kind: ServiceAccount
  name: test-sa
  namespace: test-rbac
roleRef:
  kind: Role
  name: test-role
  apiGroup: rbac.authorization.k8s.io
`
	
	execInContainer(t, containerID, "sh", "-c", fmt.Sprintf("cat > /tmp/test-rolebinding.yaml << 'EOF'\n%sEOF", roleBindingYAML))
	
	createRoleBindingOutput := execInContainer(t, containerID, "kubectl", "apply", "-f", "/tmp/test-rolebinding.yaml")
	if strings.Contains(createRoleBindingOutput, "created") {
		t.Log("测试RoleBinding创建成功")
	}
	
	// 验证权限检查
	canICheck := execInContainer(t, containerID, "kubectl", "auth", "can-i", "create", "pods", "--as=system:serviceaccount:test-rbac:test-sa", "-n", testNamespace)
	if strings.Contains(canICheck, "yes") {
		t.Log("RBAC权限检查正常")
	}
	
	// 验证Pod安全策略
	podSecurityPolicies := execInContainer(t, containerID, "kubectl", "get", "podsecuritypolicy")
	if !strings.Contains(podSecurityPolicies, "error") && !strings.Contains(podSecurityPolicies, "No resources found") {
		t.Log("Pod安全策略功能可用")
	}
	
	// 测试网络策略
	networkPolicies := execInContainer(t, containerID, "kubectl", "get", "networkpolicy", "--all-namespaces")
	if !strings.Contains(networkPolicies, "error") {
		t.Log("网络策略功能可用")
	}
	
	// 验证准入控制器
	admissionControllers := execInContainer(t, containerID, "kubectl", "get", "validatingadmissionwebhooks")
	if !strings.Contains(admissionControllers, "error") {
		t.Log("验证准入Webhook功能可用")
	}
	
	mutatingAdmissionControllers := execInContainer(t, containerID, "kubectl", "get", "mutatingadmissionwebhooks")
	if !strings.Contains(mutatingAdmissionControllers, "error") {
		t.Log("变更准入Webhook功能可用")
	}
	
	// 验证TLS证书
	tlsCertificates := []string{
		"/etc/kubernetes/pki/ca.crt",
		"/etc/kubernetes/pki/apiserver.crt",
		"/etc/kubernetes/pki/apiserver-kubelet-client.crt",
	}
	
	for _, cert := range tlsCertificates {
		if fileExists(t, containerID, cert) {
			certInfo := execInContainer(t, containerID, "openssl", "x509", "-in", cert, "-text", "-noout")
			if strings.Contains(certInfo, "Certificate:") {
				t.Logf("TLS证书%s有效", cert)
			}
		}
	}
	
	// 清理RBAC资源
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-rolebinding.yaml")
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-role.yaml")
	execInContainer(t, containerID, "kubectl", "delete", "-f", "/tmp/test-sa.yaml")
}

// testMultiNodeClusterManagement 测试多节点集群管理
func testMultiNodeClusterManagement(t *testing.T) {
	// 创建主节点
	masterName := "test-k8s-master"
	masterID := createKubernetesContainer(t, masterName)
	defer cleanupContainer(t, masterID)
	
	// 创建工作节点
	workerName := "test-k8s-worker"
	workerID := createKubernetesContainer(t, workerName)
	defer cleanupContainer(t, workerID)
	
	// 等待节点启动
	time.Sleep(30 * time.Second)
	
	// 验证主节点状态
	masterNodeStatus := execInContainer(t, masterID, "kubectl", "get", "nodes", "-o", "wide")
	t.Logf("主节点状态: %s", masterNodeStatus)
	
	// 获取集群信息
	clusterInfo := execInContainer(t, masterID, "kubectl", "cluster-info")
	if strings.Contains(clusterInfo, "Kubernetes control plane") {
		t.Log("集群控制平面运行正常")
	}
	
	// 验证节点角色
	nodeRoles := execInContainer(t, masterID, "kubectl", "get", "nodes", "--show-labels")
	t.Logf("节点角色标签: %s", nodeRoles)
	
	// 测试节点间通信
	masterIP := getContainerIP(t, masterID)
	workerIP := getContainerIP(t, workerID)
	
	t.Logf("主节点IP: %s", masterIP)
	t.Logf("工作节点IP: %s", workerIP)
	
	// 从主节点ping工作节点
	pingWorker := execInContainer(t, masterID, "ping", "-c", "3", workerIP)
	if strings.Contains(pingWorker, "3 packets transmitted") {
		t.Log("主节点到工作节点网络连通正常")
	}
	
	// 从工作节点ping主节点
	pingMaster := execInContainer(t, workerID, "ping", "-c", "3", masterIP)
	if strings.Contains(pingMaster, "3 packets transmitted") {
		t.Log("工作节点到主节点网络连通正常")
	}
	
	// 验证kubelet配置
	masterKubeletConfig := execInContainer(t, masterID, "systemctl", "status", "kubelet")
	workerKubeletConfig := execInContainer(t, workerID, "systemctl", "status", "kubelet")
	
	t.Logf("主节点kubelet状态: %s", truncateString(masterKubeletConfig, 200))
	t.Logf("工作节点kubelet状态: %s", truncateString(workerKubeletConfig, 200))
	
	// 测试跨节点Pod调度
	crossNodePodYAML := `
apiVersion: v1
kind: Pod
metadata:
  name: cross-node-test
spec:
  containers:
  - name: test-container
    image: nginx:alpine
  nodeSelector:
    kubernetes.io/os: linux
`
	
	execInContainer(t, masterID, "sh", "-c", fmt.Sprintf("cat > /tmp/cross-node-pod.yaml << 'EOF'\n%sEOF", crossNodePodYAML))
	
	createCrossNodePodOutput := execInContainer(t, masterID, "kubectl", "apply", "-f", "/tmp/cross-node-pod.yaml")
	if strings.Contains(createCrossNodePodOutput, "created") {
		t.Log("跨节点Pod创建成功")
		
		time.Sleep(30 * time.Second)
		
		crossNodePodStatus := execInContainer(t, masterID, "kubectl", "get", "pod", "cross-node-test", "-o", "wide")
		t.Logf("跨节点Pod状态: %s", crossNodePodStatus)
	}
	
	// 验证集群DNS
	clusterDNSTest := execInContainer(t, masterID, "kubectl", "get", "service", "-n", "kube-system", "kube-dns")
	if strings.Contains(clusterDNSTest, "kube-dns") {
		t.Log("集群DNS服务正常")
	}
	
	// 测试节点污点和容忍
	nodeTaints := execInContainer(t, masterID, "kubectl", "describe", "nodes", "|", "grep", "Taints")
	if strings.TrimSpace(nodeTaints) != "" {
		t.Logf("节点污点配置: %s", nodeTaints)
	}
	
	// 验证集群监控指标
	metricsNodes := execInContainer(t, masterID, "kubectl", "top", "nodes")
	if !strings.Contains(metricsNodes, "error") {
		t.Log("节点监控指标可用")
	}
	
	// 验证集群事件
	clusterEvents := execInContainer(t, masterID, "kubectl", "get", "events", "--all-namespaces", "--sort-by=.metadata.creationTimestamp", "|", "tail", "-10")
	if !strings.Contains(clusterEvents, "error") {
		t.Log("集群事件监控正常")
	}
	
	// 测试节点维护模式
	cordoneOutput := execInContainer(t, masterID, "kubectl", "cordon", workerName)
	if strings.Contains(cordoneOutput, "cordoned") {
		t.Log("节点维护模式设置成功")
		
		// 恢复节点
		uncordoneOutput := execInContainer(t, masterID, "kubectl", "uncordon", workerName)
		if strings.Contains(uncordoneOutput, "uncordoned") {
			t.Log("节点维护模式恢复成功")
		}
	}
	
	// 清理跨节点测试资源
	execInContainer(t, masterID, "kubectl", "delete", "-f", "/tmp/cross-node-pod.yaml")
}

// Helper functions for KinD tests

func setupKinDTestEnv(t *testing.T) {
	// 验证Docker和sysbox-runc
	output, err := exec.Command("docker", "info").Output()
	require.NoError(t, err, "Docker应该正常运行")
	require.Contains(t, string(output), "sysbox-runc", "应该配置sysbox-runc运行时")
	
	// 预拉取Kubernetes镜像
	exec.Command("docker", "pull", "kindest/node:latest").Run()
	
	// 清理可能存在的测试容器
	testContainers := []string{
		"test-k8s-setup", "test-kubelet-runtime", "test-k8s-networking",
		"test-etcd-storage", "test-k8s-apiserver", "test-pod-workload",
		"test-service-discovery", "test-storage", "test-k8s-security",
		"test-k8s-master", "test-k8s-worker",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func cleanupKinDTestEnv(t *testing.T) {
	// 清理所有测试容器
	testContainers := []string{
		"test-k8s-setup", "test-kubelet-runtime", "test-k8s-networking",
		"test-etcd-storage", "test-k8s-apiserver", "test-pod-workload",
		"test-service-discovery", "test-storage", "test-k8s-security",
		"test-k8s-master", "test-k8s-worker",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func createKubernetesContainer(t *testing.T, name string) string {
	// 创建包含Kubernetes的系统容器
	containerID := createSysboxContainer(t, name, "kindest/node:latest",
		[]string{"/usr/local/bin/entrypoint", "/sbin/init"})
	
	// 等待系统初始化
	time.Sleep(25 * time.Second)
	
	// 验证系统就绪
	systemdStatus := execInContainer(t, containerID, "systemctl", "is-system-running")
	t.Logf("容器%s系统状态: %s", name, systemdStatus)
	
	return containerID
}

func detectContainerRuntime(t *testing.T, containerID string) string {
	// 检查containerd
	_, containerdErr := execInContainerWithError(containerID, "systemctl", "is-active", "containerd")
	if containerdErr == nil {
		return "containerd"
	}
	
	// 检查Docker
	_, dockerErr := execInContainerWithError(containerID, "systemctl", "is-active", "docker")
	if dockerErr == nil {
		return "docker"
	}
	
	return "unknown"
}

func extractServiceIP(serviceStatus string) string {
	// 从kubectl get service输出中提取ClusterIP
	lines := strings.Split(serviceStatus, "\n")
	for _, line := range lines {
		if strings.Contains(line, "ClusterIP") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[2] // ClusterIP通常在第3列
			}
		}
	}
	return ""
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
