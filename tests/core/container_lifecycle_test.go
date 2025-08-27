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

// ContainerState 表示容器状态
type ContainerState struct {
	Status     string
	Running    bool
	Paused     bool
	Restarting bool
	OOMKilled  bool
	Dead       bool
	Pid        int
	ExitCode   int
	StartedAt  string
	FinishedAt string
}

// TestContainerLifecycleManagement 测试容器生命周期管理核心流程
func TestContainerLifecycleManagement(t *testing.T) {
	setupLifecycleTestEnv(t)
	defer cleanupLifecycleTestEnv(t)

	t.Run("容器创建和初始化", func(t *testing.T) {
		testContainerCreationAndInitialization(t)
	})

	t.Run("容器启动和运行状态管理", func(t *testing.T) {
		testContainerStartupAndRunning(t)
	})

	t.Run("容器暂停和恢复", func(t *testing.T) {
		testContainerPauseAndResume(t)
	})

	t.Run("容器停止和重启", func(t *testing.T) {
		testContainerStopAndRestart(t)
	})

	t.Run("容器删除和清理", func(t *testing.T) {
		testContainerRemovalAndCleanup(t)
	})

	t.Run("容器健康检查和监控", func(t *testing.T) {
		testContainerHealthCheckAndMonitoring(t)
	})

	t.Run("容器资源限制和约束", func(t *testing.T) {
		testContainerResourceConstraints(t)
	})

	t.Run("容器异常处理和恢复", func(t *testing.T) {
		testContainerExceptionHandlingAndRecovery(t)
	})

	t.Run("容器元数据和标签管理", func(t *testing.T) {
		testContainerMetadataAndLabels(t)
	})

	t.Run("容器生命周期事件和钩子", func(t *testing.T) {
		testContainerLifecycleEventsAndHooks(t)
	})
}

// testContainerCreationAndInitialization 测试容器创建和初始化
func testContainerCreationAndInitialization(t *testing.T) {
	containerName := "test-creation-init"
	
	// 测试容器创建但不启动
	createOutput, err := exec.Command("docker", "create", "--name", containerName, 
		"--runtime=sysbox-runc", "ubuntu:20.04", "sleep", "300").Output()
	require.NoError(t, err, "容器创建应该成功")
	
	containerID := strings.TrimSpace(string(createOutput))
	require.NotEmpty(t, containerID, "容器ID不应该为空")
	
	defer cleanupContainer(t, containerID)
	
	// 验证容器状态为created
	state := getContainerState(t, containerID)
	assert.Equal(t, "created", state.Status, "容器状态应该是created")
	assert.False(t, state.Running, "容器不应该在运行")
	
	// 验证容器配置
	inspectOutput := execCommand(t, "docker", "inspect", containerID)
	var containerInfo []map[string]interface{}
	err = json.Unmarshal([]byte(inspectOutput), &containerInfo)
	require.NoError(t, err, "容器信息应该能够解析")
	require.Len(t, containerInfo, 1, "应该返回一个容器信息")
	
	config := containerInfo[0]
	assert.Equal(t, containerName, config["Name"], "容器名称应该正确")
	assert.Equal(t, "sysbox-runc", config["HostConfig"].(map[string]interface{})["Runtime"], 
		"运行时应该是sysbox-runc")
	
	// 验证容器文件系统准备
	containerFSPath := fmt.Sprintf("/var/lib/docker/containers/%s", containerID)
	if _, err := os.Stat(containerFSPath); err == nil {
		t.Log("容器文件系统路径已创建")
	}
	
	// 测试容器初始化
	startOutput := execCommand(t, "docker", "start", containerID)
	assert.Contains(t, startOutput, containerID, "启动输出应该包含容器ID")
	
	// 等待容器完全启动
	time.Sleep(3 * time.Second)
	
	// 验证启动后状态
	stateAfterStart := getContainerState(t, containerID)
	assert.Equal(t, "running", stateAfterStart.Status, "容器状态应该是running")
	assert.True(t, stateAfterStart.Running, "容器应该在运行")
	assert.Greater(t, stateAfterStart.Pid, 0, "容器应该有PID")
	
	// 验证容器初始化日志
	logs := execCommand(t, "docker", "logs", containerID)
	t.Logf("容器初始化日志: %s", logs)
	
	// 验证容器内进程
	processOutput := execInContainer(t, containerID, "ps", "aux")
	assert.Contains(t, processOutput, "sleep", "容器内应该有sleep进程")
	
	// 验证容器网络初始化
	networkOutput := execInContainer(t, containerID, "ip", "addr", "show")
	assert.Contains(t, networkOutput, "lo", "容器应该有lo接口")
	assert.Contains(t, networkOutput, "eth0", "容器应该有eth0接口")
	
	// 验证容器挂载点初始化
	mountOutput := execInContainer(t, containerID, "mount")
	assert.Contains(t, mountOutput, "/proc", "容器应该挂载/proc")
	assert.Contains(t, mountOutput, "/sys", "容器应该挂载/sys")
	assert.Contains(t, mountOutput, "/dev", "容器应该挂载/dev")
	
	// 验证容器环境变量
	envOutput := execInContainer(t, containerID, "env")
	assert.Contains(t, envOutput, "PATH=", "容器应该有PATH环境变量")
	assert.Contains(t, envOutput, "HOME=", "容器应该有HOME环境变量")
}

// testContainerStartupAndRunning 测试容器启动和运行状态管理
func testContainerStartupAndRunning(t *testing.T) {
	containerName := "test-startup-running"
	
	// 测试直接创建并启动容器
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "600"})
	defer cleanupContainer(t, containerID)
	
	// 验证启动过程
	state := getContainerState(t, containerID)
	assert.Equal(t, "running", state.Status, "容器应该处于运行状态")
	assert.True(t, state.Running, "Running标志应该为true")
	assert.False(t, state.Paused, "Paused标志应该为false")
	assert.False(t, state.Restarting, "Restarting标志应该为false")
	
	// 验证容器启动时间
	startTime, err := time.Parse(time.RFC3339Nano, state.StartedAt)
	assert.NoError(t, err, "启动时间应该能够解析")
	assert.True(t, time.Since(startTime) < 5*time.Minute, "启动时间应该是最近的")
	
	// 验证容器进程ID
	assert.Greater(t, state.Pid, 0, "容器PID应该大于0")
	
	// 从主机验证进程存在
	_, err = os.Stat(fmt.Sprintf("/proc/%d", state.Pid))
	assert.NoError(t, err, "容器进程应该在主机上可见")
	
	// 验证容器运行时统计
	statsOutput := execCommand(t, "docker", "stats", "--no-stream", containerID)
	assert.Contains(t, statsOutput, containerName, "统计信息应该包含容器名称")
	
	// 解析统计信息
	statsLines := strings.Split(statsOutput, "\n")
	if len(statsLines) >= 2 {
		statsFields := strings.Fields(statsLines[1])
		if len(statsFields) >= 4 {
			t.Logf("容器CPU使用率: %s", statsFields[2])
			t.Logf("容器内存使用: %s", statsFields[3])
		}
	}
	
	// 测试容器内命令执行
	execTests := []struct {
		cmd      []string
		expected string
	}{
		{[]string{"whoami"}, "root"},
		{[]string{"pwd"}, "/"},
		{[]string{"echo", "test"}, "test"},
		{[]string{"uname", "-s"}, "Linux"},
	}
	
	for _, test := range execTests {
		output := execInContainer(t, containerID, test.cmd...)
		assert.Contains(t, output, test.expected, 
			fmt.Sprintf("命令%v应该返回包含%s的输出", test.cmd, test.expected))
	}
	
	// 验证容器文件系统可写性
	writeTest := execInContainer(t, containerID, "touch", "/tmp/lifecycle-test")
	assert.Equal(t, "", strings.TrimSpace(writeTest), "文件创建应该成功")
	
	readTest := execInContainer(t, containerID, "ls", "/tmp/lifecycle-test")
	assert.Contains(t, readTest, "lifecycle-test", "创建的文件应该存在")
	
	// 验证容器端口监听
	portTest := execInContainer(t, containerID, "python3", "-c", `
import socket
s = socket.socket()
s.bind(('0.0.0.0', 8080))
s.listen(1)
print("Port 8080 listening")
s.close()
`)
	assert.Contains(t, portTest, "Port 8080 listening", "容器应该能够监听端口")
	
	// 验证容器资源访问
	resourceTests := []string{
		"/proc/meminfo",
		"/proc/cpuinfo",
		"/sys/kernel/ostype",
	}
	
	for _, resource := range resourceTests {
		if fileExists(t, containerID, resource) {
			content := execInContainer(t, containerID, "head", "-1", resource)
			assert.NotEmpty(t, content, fmt.Sprintf("资源%s应该可读", resource))
		}
	}
	
	// 验证容器网络连通性
	connectivityTest := execInContainer(t, containerID, "ping", "-c", "1", "8.8.8.8")
	assert.Contains(t, connectivityTest, "1 packets transmitted", "容器应该有网络连通性")
}

// testContainerPauseAndResume 测试容器暂停和恢复
func testContainerPauseAndResume(t *testing.T) {
	containerName := "test-pause-resume"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 验证初始运行状态
	initialState := getContainerState(t, containerID)
	assert.Equal(t, "running", initialState.Status, "容器初始应该处于运行状态")
	assert.False(t, initialState.Paused, "容器初始不应该暂停")
	
	// 测试暂停容器
	pauseOutput := execCommand(t, "docker", "pause", containerID)
	assert.Contains(t, pauseOutput, containerID, "暂停输出应该包含容器ID")
	
	// 验证暂停状态
	pausedState := getContainerState(t, containerID)
	assert.Equal(t, "paused", pausedState.Status, "容器应该处于暂停状态")
	assert.True(t, pausedState.Paused, "Paused标志应该为true")
	assert.True(t, pausedState.Running, "Running标志仍应该为true（暂停时）")
	
	// 验证暂停时进程状态
	processStatus := getProcessStatus(t, pausedState.Pid)
	t.Logf("暂停时进程状态: %s", processStatus)
	
	// 验证暂停时无法执行命令
	_, execErr := execInContainerWithError(containerID, "echo", "paused-test")
	assert.Error(t, execErr, "暂停的容器不应该能执行命令")
	
	// 验证容器事件日志
	eventsOutput := execCommand(t, "docker", "events", "--since", "1m", "--filter", 
		fmt.Sprintf("container=%s", containerID), "--until", "now")
	assert.Contains(t, eventsOutput, "pause", "事件日志应该包含pause事件")
	
	// 等待一段时间确保暂停生效
	time.Sleep(2 * time.Second)
	
	// 测试恢复容器
	unpauseOutput := execCommand(t, "docker", "unpause", containerID)
	assert.Contains(t, unpauseOutput, containerID, "恢复输出应该包含容器ID")
	
	// 验证恢复状态
	resumedState := getContainerState(t, containerID)
	assert.Equal(t, "running", resumedState.Status, "容器应该恢复到运行状态")
	assert.False(t, resumedState.Paused, "Paused标志应该为false")
	assert.True(t, resumedState.Running, "Running标志应该为true")
	
	// 验证恢复后功能正常
	resumeTest := execInContainer(t, containerID, "echo", "resumed-test")
	assert.Contains(t, resumeTest, "resumed-test", "恢复后应该能正常执行命令")
	
	// 验证恢复后的进程状态
	resumedProcessStatus := getProcessStatus(t, resumedState.Pid)
	t.Logf("恢复后进程状态: %s", resumedProcessStatus)
	
	// 测试多次暂停恢复
	for i := 0; i < 3; i++ {
		t.Logf("第%d次暂停恢复循环", i+1)
		
		execCommand(t, "docker", "pause", containerID)
		pauseState := getContainerState(t, containerID)
		assert.True(t, pauseState.Paused, "容器应该暂停")
		
		time.Sleep(1 * time.Second)
		
		execCommand(t, "docker", "unpause", containerID)
		unpauseState := getContainerState(t, containerID)
		assert.False(t, unpauseState.Paused, "容器应该恢复")
		
		// 验证功能正常
		funcTest := execInContainer(t, containerID, "date")
		assert.NotEmpty(t, funcTest, "功能应该正常")
	}
	
	// 验证事件历史
	finalEventsOutput := execCommand(t, "docker", "events", "--since", "2m", "--filter", 
		fmt.Sprintf("container=%s", containerID), "--until", "now")
	pauseCount := strings.Count(finalEventsOutput, "pause")
	unpauseCount := strings.Count(finalEventsOutput, "unpause")
	
	assert.GreaterOrEqual(t, pauseCount, 4, "应该有至少4次pause事件")
	assert.GreaterOrEqual(t, unpauseCount, 4, "应该有至少4次unpause事件")
}

// testContainerStopAndRestart 测试容器停止和重启
func testContainerStopAndRestart(t *testing.T) {
	containerName := "test-stop-restart"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 记录初始状态
	initialState := getContainerState(t, containerID)
	initialPid := initialState.Pid
	assert.Equal(t, "running", initialState.Status, "容器初始应该运行")
	
	// 测试优雅停止
	stopOutput := execCommand(t, "docker", "stop", containerID)
	assert.Contains(t, stopOutput, containerID, "停止输出应该包含容器ID")
	
	// 验证停止状态
	stoppedState := getContainerState(t, containerID)
	assert.Equal(t, "exited", stoppedState.Status, "容器应该处于退出状态")
	assert.False(t, stoppedState.Running, "Running标志应该为false")
	assert.Equal(t, 0, stoppedState.ExitCode, "退出码应该是0（正常退出）")
	
	// 验证停止时间
	finishTime, err := time.Parse(time.RFC3339Nano, stoppedState.FinishedAt)
	assert.NoError(t, err, "结束时间应该能够解析")
	assert.True(t, time.Since(finishTime) < 1*time.Minute, "结束时间应该是最近的")
	
	// 验证进程不再存在
	_, err = os.Stat(fmt.Sprintf("/proc/%d", initialPid))
	assert.True(t, os.IsNotExist(err), "原进程应该不再存在")
	
	// 验证无法执行命令
	_, execErr := execInContainerWithError(containerID, "echo", "stopped-test")
	assert.Error(t, execErr, "停止的容器不应该能执行命令")
	
	// 测试重启容器
	restartOutput := execCommand(t, "docker", "restart", containerID)
	assert.Contains(t, restartOutput, containerID, "重启输出应该包含容器ID")
	
	// 等待重启完成
	time.Sleep(3 * time.Second)
	
	// 验证重启后状态
	restartedState := getContainerState(t, containerID)
	assert.Equal(t, "running", restartedState.Status, "容器应该重新运行")
	assert.True(t, restartedState.Running, "Running标志应该为true")
	assert.NotEqual(t, initialPid, restartedState.Pid, "重启后应该有新的PID")
	
	// 验证重启后功能正常
	restartTest := execInContainer(t, containerID, "echo", "restarted-test")
	assert.Contains(t, restartTest, "restarted-test", "重启后应该能正常执行命令")
	
	// 验证重启后环境
	restartEnvTest := execInContainer(t, containerID, "whoami")
	assert.Contains(t, restartEnvTest, "root", "重启后环境应该正确")
	
	// 测试强制停止
	killOutput := execCommand(t, "docker", "kill", containerID)
	assert.Contains(t, killOutput, containerID, "强制停止输出应该包含容器ID")
	
	// 验证强制停止状态
	killedState := getContainerState(t, containerID)
	assert.Equal(t, "exited", killedState.Status, "容器应该处于退出状态")
	assert.False(t, killedState.Running, "Running标志应该为false")
	
	// 测试指定信号停止
	execCommand(t, "docker", "start", containerID)
	time.Sleep(2 * time.Second)
	
	signalOutput := execCommand(t, "docker", "kill", "-s", "SIGUSR1", containerID)
	assert.Contains(t, signalOutput, containerID, "信号发送输出应该包含容器ID")
	
	// 等待信号处理
	time.Sleep(1 * time.Second)
	
	// 验证容器仍在运行（SIGUSR1通常不会终止进程）
	signalState := getContainerState(t, containerID)
	if signalState.Running {
		t.Log("容器正确处理了SIGUSR1信号并继续运行")
	}
	
	// 测试超时停止
	timeoutStopOutput := execCommand(t, "docker", "stop", "-t", "2", containerID)
	assert.Contains(t, timeoutStopOutput, containerID, "超时停止应该成功")
	
	// 验证停止事件
	stopEventsOutput := execCommand(t, "docker", "events", "--since", "2m", "--filter", 
		fmt.Sprintf("container=%s", containerID), "--until", "now")
	assert.Contains(t, stopEventsOutput, "stop", "事件日志应该包含stop事件")
	assert.Contains(t, stopEventsOutput, "start", "事件日志应该包含start事件")
}

// testContainerRemovalAndCleanup 测试容器删除和清理
func testContainerRemovalAndCleanup(t *testing.T) {
	containerName := "test-removal-cleanup"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	
	// 在容器中创建一些文件
	execInContainer(t, containerID, "touch", "/tmp/test-file")
	execInContainer(t, containerID, "mkdir", "/tmp/test-dir")
	execInContainer(t, containerID, "echo", "test data", ">", "/tmp/test-file")
	
	// 验证文件创建成功
	fileTest := execInContainer(t, containerID, "cat", "/tmp/test-file")
	assert.Contains(t, fileTest, "test data", "测试文件应该包含数据")
	
	// 记录容器信息用于后续验证
	initialInfo := getContainerInfo(t, containerID)
	containerFSPath := initialInfo["GraphDriver"].(map[string]interface{})["Data"].(map[string]interface{})["MergedDir"].(string)
	
	// 停止容器
	execCommand(t, "docker", "stop", containerID)
	
	// 验证停止状态
	stoppedState := getContainerState(t, containerID)
	assert.Equal(t, "exited", stoppedState.Status, "容器应该处于退出状态")
	
	// 测试删除运行中的容器（应该失败）
	runningContainerID := createSysboxContainer(t, "test-running-removal", "ubuntu:20.04", []string{"sleep", "300"})
	
	_, removeRunningErr := execCommandWithError("docker", "rm", runningContainerID)
	assert.Error(t, removeRunningErr, "删除运行中的容器应该失败")
	
	// 强制删除运行中的容器
	forceRemoveOutput := execCommand(t, "docker", "rm", "-f", runningContainerID)
	assert.Contains(t, forceRemoveOutput, runningContainerID, "强制删除应该成功")
	
	// 验证强制删除后容器不存在
	_, inspectErr := execCommandWithError("docker", "inspect", runningContainerID)
	assert.Error(t, inspectErr, "强制删除后容器不应该存在")
	
	// 测试正常删除已停止的容器
	removeOutput := execCommand(t, "docker", "rm", containerID)
	assert.Contains(t, removeOutput, containerID, "删除输出应该包含容器ID")
	
	// 验证容器删除后不存在
	_, removedInspectErr := execCommandWithError("docker", "inspect", containerID)
	assert.Error(t, removedInspectErr, "删除后容器不应该存在")
	
	// 验证容器不在列表中
	psOutput := execCommand(t, "docker", "ps", "-a")
	assert.NotContains(t, psOutput, containerName, "删除后容器不应该在列表中")
	assert.NotContains(t, psOutput, containerID, "删除后容器ID不应该在列表中")
	
	// 验证文件系统清理
	if _, err := os.Stat(containerFSPath); err != nil && os.IsNotExist(err) {
		t.Log("容器文件系统路径已清理")
	} else {
		t.Log("容器文件系统路径可能仍存在（延迟清理）")
	}
	
	// 测试卷清理（如果有匿名卷）
	volumeContainerID := createSysboxContainerWithOptions(t, "test-volume-cleanup", "ubuntu:20.04", 
		[]string{"sleep", "300"}, "-v", "/tmp/volume-test")
	
	// 在卷中创建数据
	execInContainer(t, volumeContainerID, "echo", "volume data", ">", "/tmp/volume-test/data.txt")
	
	// 停止并删除容器
	execCommand(t, "docker", "stop", volumeContainerID)
	
	// 删除容器但保留卷
	execCommand(t, "docker", "rm", volumeContainerID)
	
	// 删除容器及其卷
	volumeContainer2ID := createSysboxContainerWithOptions(t, "test-volume-cleanup-2", "ubuntu:20.04", 
		[]string{"sleep", "300"}, "-v", "/tmp/volume-test-2")
	
	execCommand(t, "docker", "stop", volumeContainer2ID)
	removeVolumeOutput := execCommand(t, "docker", "rm", "-v", volumeContainer2ID)
	assert.Contains(t, removeVolumeOutput, volumeContainer2ID, "删除包含卷的容器应该成功")
	
	// 测试批量删除
	batchContainers := make([]string, 3)
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("test-batch-cleanup-%d", i)
		batchContainers[i] = createSysboxContainer(t, name, "ubuntu:20.04", []string{"sleep", "60"})
	}
	
	// 停止所有容器
	for _, cid := range batchContainers {
		execCommand(t, "docker", "stop", cid)
	}
	
	// 批量删除
	args := append([]string{"rm"}, batchContainers...)
	batchRemoveOutput := execCommand(t, "docker", args...)
	
	for _, cid := range batchContainers {
		assert.Contains(t, batchRemoveOutput, cid, "批量删除输出应该包含所有容器ID")
	}
	
	// 验证批量删除后都不存在
	for _, cid := range batchContainers {
		_, err := execCommandWithError("docker", "inspect", cid)
		assert.Error(t, err, "批量删除后容器不应该存在")
	}
	
	// 测试清理僵尸容器
	zombieContainerID := createSysboxContainer(t, "test-zombie", "ubuntu:20.04", []string{"sh", "-c", "exit 1"})
	
	// 等待容器退出
	time.Sleep(3 * time.Second)
	
	zombieState := getContainerState(t, zombieContainerID)
	assert.Equal(t, "exited", zombieState.Status, "容器应该已退出")
	assert.Equal(t, 1, zombieState.ExitCode, "退出码应该是1")
	
	// 清理僵尸容器
	execCommand(t, "docker", "rm", zombieContainerID)
	
	// 验证系统资源清理
	pruneOutput := execCommand(t, "docker", "system", "prune", "-f")
	t.Logf("系统清理输出: %s", pruneOutput)
}

// testContainerHealthCheckAndMonitoring 测试容器健康检查和监控
func testContainerHealthCheckAndMonitoring(t *testing.T) {
	containerName := "test-health-monitoring"
	
	// 创建带健康检查的容器
	healthcheckContainerID := createSysboxContainerWithOptions(t, containerName, "nginx:alpine", 
		[]string{}, "--health-cmd", "curl -f http://localhost:80/ || exit 1", 
		"--health-interval", "10s", "--health-timeout", "3s", "--health-retries", "3")
	defer cleanupContainer(t, healthcheckContainerID)
	
	// 等待健康检查开始
	time.Sleep(15 * time.Second)
	
	// 验证健康检查状态
	healthState := getContainerHealth(t, healthcheckContainerID)
	t.Logf("容器健康状态: %s", healthState)
	
	// 验证健康检查历史
	healthHistory := getContainerHealthHistory(t, healthcheckContainerID)
	assert.Greater(t, len(healthHistory), 0, "应该有健康检查历史记录")
	
	for i, check := range healthHistory {
		t.Logf("健康检查 %d: 状态=%s, 耗时=%s", i, check["ExitCode"], check["Duration"])
	}
	
	// 测试容器监控指标
	statsOutput := execCommand(t, "docker", "stats", "--no-stream", "--format", 
		"table {{.Container}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.NetIO}}\\t{{.BlockIO}}", healthcheckContainerID)
	assert.Contains(t, statsOutput, containerName, "统计信息应该包含容器")
	
	// 解析监控数据
	statsLines := strings.Split(statsOutput, "\n")
	if len(statsLines) >= 2 {
		statsData := strings.Split(statsLines[1], "\t")
		if len(statsData) >= 5 {
			t.Logf("CPU使用率: %s", statsData[1])
			t.Logf("内存使用: %s", statsData[2])
			t.Logf("网络IO: %s", statsData[3])
			t.Logf("磁盘IO: %s", statsData[4])
		}
	}
	
	// 测试容器事件监控
	eventsOutput := execCommand(t, "docker", "events", "--since", "1m", "--filter", 
		fmt.Sprintf("container=%s", healthcheckContainerID), "--until", "now")
	assert.Contains(t, eventsOutput, "start", "事件应该包含启动")
	
	if strings.Contains(eventsOutput, "health_status") {
		t.Log("检测到健康检查事件")
	}
	
	// 测试容器日志监控
	logsOutput := execCommand(t, "docker", "logs", "--timestamps", healthcheckContainerID)
	assert.NotEmpty(t, logsOutput, "容器应该有日志输出")
	
	// 验证日志时间戳格式
	logLines := strings.Split(logsOutput, "\n")
	for _, line := range logLines {
		if strings.TrimSpace(line) != "" {
			parts := strings.SplitN(line, " ", 2)
			if len(parts) >= 2 {
				_, err := time.Parse(time.RFC3339Nano, parts[0])
				if err == nil {
					t.Log("日志时间戳格式正确")
					break
				}
			}
		}
	}
	
	// 测试容器进程监控
	topOutput := execCommand(t, "docker", "top", healthcheckContainerID)
	assert.Contains(t, topOutput, "PID", "top输出应该包含进程信息")
	assert.Contains(t, topOutput, "nginx", "应该看到nginx进程")
	
	// 测试容器端口监控
	portOutput := execCommand(t, "docker", "port", healthcheckContainerID)
	if strings.TrimSpace(portOutput) != "" {
		t.Logf("容器端口映射: %s", portOutput)
	}
	
	// 创建测试监控容器（消耗资源）
	monitoringContainerID := createSysboxContainer(t, "test-resource-monitoring", "ubuntu:20.04", 
		[]string{"sh", "-c", "while true; do dd if=/dev/zero of=/tmp/test bs=1M count=10; sleep 1; done"})
	defer cleanupContainer(t, monitoringContainerID)
	
	// 监控资源使用变化
	time.Sleep(5 * time.Second)
	
	initialStats := getContainerStats(t, monitoringContainerID)
	t.Logf("初始资源使用: CPU=%s, 内存=%s", initialStats["CPUPerc"], initialStats["MemUsage"])
	
	time.Sleep(10 * time.Second)
	
	laterStats := getContainerStats(t, monitoringContainerID)
	t.Logf("后续资源使用: CPU=%s, 内存=%s", laterStats["CPUPerc"], laterStats["MemUsage"])
	
	// 验证资源使用有变化
	assert.NotEqual(t, initialStats["MemUsage"], laterStats["MemUsage"], "内存使用应该有变化")
}

// testContainerResourceConstraints 测试容器资源限制和约束
func testContainerResourceConstraints(t *testing.T) {
	containerName := "test-resource-constraints"
	
	// 创建带资源限制的容器
	constrainedContainerID := createSysboxContainerWithOptions(t, containerName, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--memory=128m", "--cpus=0.5", "--pids-limit=50")
	defer cleanupContainer(t, constrainedContainerID)
	
	// 验证内存限制
	memoryLimit := getContainerResourceLimit(t, constrainedContainerID, "Memory")
	expectedMemory := int64(128 * 1024 * 1024) // 128MB
	assert.InDelta(t, expectedMemory, memoryLimit, float64(expectedMemory)*0.1, 
		"内存限制应该接近设置值")
	
	// 测试内存限制执行
	memoryTest := execInContainer(t, constrainedContainerID, "python3", "-c", `
import sys
try:
    # 尝试分配超过限制的内存
    data = bytearray(150 * 1024 * 1024)  # 150MB > 128MB limit
    print("Memory allocation succeeded")
except MemoryError:
    print("Memory limit enforced")
    sys.exit(0)
except Exception as e:
    print(f"Memory test error: {e}")
    sys.exit(1)
`)
	
	t.Logf("内存限制测试结果: %s", memoryTest)
	
	// 验证CPU限制
	cpuTest := execInContainer(t, constrainedContainerID, "python3", "-c", `
import time
import threading

def cpu_task():
    end_time = time.time() + 5
    while time.time() < end_time:
        pass

start_time = time.time()
threads = []
for i in range(4):  # 启动4个CPU密集型线程
    t = threading.Thread(target=cpu_task)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

actual_time = time.time() - start_time
print(f"CPU test completed in {actual_time:.2f} seconds")
# 受CPU限制，实际时间应该比理论时间长
`)
	
	t.Logf("CPU限制测试结果: %s", cpuTest)
	
	// 测试PID限制
	pidTest := execInContainer(t, constrainedContainerID, "python3", "-c", `
import os
import signal

child_pids = []
try:
    for i in range(60):  # 尝试创建超过50个进程
        try:
            pid = os.fork()
            if pid == 0:
                # 子进程
                import time
                time.sleep(30)
                os._exit(0)
            else:
                child_pids.append(pid)
                print(f"Created process {i+1}: PID {pid}")
        except OSError as e:
            print(f"Failed to create process {i+1}: {e}")
            break
    
    print(f"Total processes created: {len(child_pids)}")
    
finally:
    # 清理子进程
    for pid in child_pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except:
            pass
`)
	
	t.Logf("PID限制测试结果: %s", pidTest)
	
	// 验证磁盘IO限制（如果设置）
	ioTest := execInContainer(t, constrainedContainerID, "dd", "if=/dev/zero", "of=/tmp/io-test", 
		"bs=1M", "count=10", "2>&1")
	t.Logf("磁盘IO测试: %s", ioTest)
	
	// 测试网络限制（如果支持）
	networkTest := execInContainer(t, constrainedContainerID, "ping", "-c", "5", "8.8.8.8")
	if strings.Contains(networkTest, "5 packets transmitted") {
		t.Log("网络连通性正常")
	}
	
	// 验证ulimit设置
	ulimitTest := execInContainer(t, constrainedContainerID, "ulimit", "-a")
	assert.Contains(t, ulimitTest, "core file size", "ulimit信息应该可获取")
	
	// 测试文件描述符限制
	fdTest := execInContainer(t, constrainedContainerID, "python3", "-c", `
import tempfile
import resource

# 获取文件描述符限制
soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
print(f"FD limit: soft={soft_limit}, hard={hard_limit}")

# 尝试打开大量文件
files = []
try:
    for i in range(min(1024, int(soft_limit) - 10)):
        f = tempfile.TemporaryFile()
        files.append(f)
    print(f"Opened {len(files)} files successfully")
except OSError as e:
    print(f"FD limit reached: {e}")
finally:
    for f in files:
        f.close()
`)
	
	t.Logf("文件描述符限制测试: %s", fdTest)
	
	// 验证cgroup设置
	cgroupMemory := execInContainer(t, constrainedContainerID, "cat", "/sys/fs/cgroup/memory/memory.limit_in_bytes")
	if !strings.Contains(cgroupMemory, "No such file") {
		memoryLimitFromCgroup := parseBytes(t, strings.TrimSpace(cgroupMemory))
		t.Logf("Cgroup内存限制: %d bytes", memoryLimitFromCgroup)
	}
}

// testContainerExceptionHandlingAndRecovery 测试容器异常处理和恢复
func testContainerExceptionHandlingAndRecovery(t *testing.T) {
	containerName := "test-exception-recovery"
	
	// 测试容器异常退出
	crashContainerID := createSysboxContainer(t, "test-crash", "ubuntu:20.04", 
		[]string{"sh", "-c", "sleep 5; exit 42"})
	
	// 等待容器异常退出
	time.Sleep(8 * time.Second)
	
	crashState := getContainerState(t, crashContainerID)
	assert.Equal(t, "exited", crashState.Status, "容器应该已退出")
	assert.Equal(t, 42, crashState.ExitCode, "退出码应该是42")
	
	// 清理崩溃容器
	execCommand(t, "docker", "rm", crashContainerID)
	
	// 测试容器重启策略
	restartPolicyContainerID := createSysboxContainerWithOptions(t, "test-restart-policy", "ubuntu:20.04", 
		[]string{"sh", "-c", "sleep 3; exit 1"}, "--restart=on-failure:3")
	defer cleanupContainer(t, restartPolicyContainerID)
	
	// 等待重启策略生效
	time.Sleep(15 * time.Second)
	
	restartState := getContainerState(t, restartPolicyContainerID)
	restartCount := getContainerRestartCount(t, restartPolicyContainerID)
	
	t.Logf("重启策略容器状态: %s, 重启次数: %d", restartState.Status, restartCount)
	assert.Greater(t, restartCount, 0, "容器应该已重启至少一次")
	
	// 测试OOM情况处理
	oomContainerID := createSysboxContainerWithOptions(t, "test-oom", "ubuntu:20.04", 
		[]string{"python3", "-c", "data = bytearray(500 * 1024 * 1024); import time; time.sleep(10)"}, 
		"--memory=64m")
	defer cleanupContainer(t, oomContainerID)
	
	// 等待OOM发生
	time.Sleep(10 * time.Second)
	
	oomState := getContainerState(t, oomContainerID)
	if oomState.OOMKilled {
		t.Log("容器因OOM被终止，处理正确")
	} else {
		t.Log("容器未被OOM终止，可能内存分配失败")
	}
	
	// 测试信号处理
	signalContainerID := createSysboxContainer(t, "test-signal-handling", "ubuntu:20.04", 
		[]string{"sh", "-c", "trap 'echo SIGUSR1 received; exit 10' USR1; sleep 300"})
	defer cleanupContainer(t, signalContainerID)
	
	time.Sleep(3 * time.Second)
	
	// 发送SIGUSR1信号
	execCommand(t, "docker", "kill", "-s", "SIGUSR1", signalContainerID)
	
	// 等待信号处理
	time.Sleep(5 * time.Second)
	
	signalState := getContainerState(t, signalContainerID)
	if signalState.Status == "exited" && signalState.ExitCode == 10 {
		t.Log("容器正确处理了SIGUSR1信号")
	}
	
	// 测试容器僵尸进程处理
	zombieContainerID := createSysboxContainer(t, "test-zombie", "ubuntu:20.04", 
		[]string{"sh", "-c", "sleep 5 & wait"})
	defer cleanupContainer(t, zombieContainerID)
	
	time.Sleep(8 * time.Second)
	
	zombieProcesses := execInContainer(t, zombieContainerID, "ps", "aux")
	zombieCount := strings.Count(zombieProcesses, "<defunct>")
	t.Logf("僵尸进程数量: %d", zombieCount)
	
	// 测试容器网络故障恢复
	networkContainerID := createSysboxContainer(t, "test-network-recovery", "ubuntu:20.04", 
		[]string{"sleep", "300"})
	defer cleanupContainer(t, networkContainerID)
	
	// 测试网络连通性
	initialConnectivity := execInContainer(t, networkContainerID, "ping", "-c", "1", "8.8.8.8")
	if strings.Contains(initialConnectivity, "1 packets transmitted") {
		t.Log("初始网络连通性正常")
		
		// 模拟网络问题恢复（重启网络接口）
		execInContainer(t, networkContainerID, "ip", "link", "set", "eth0", "down")
		time.Sleep(1 * time.Second)
		execInContainer(t, networkContainerID, "ip", "link", "set", "eth0", "up")
		time.Sleep(3 * time.Second)
		
		recoveryConnectivity := execInContainer(t, networkContainerID, "ping", "-c", "1", "8.8.8.8")
		if strings.Contains(recoveryConnectivity, "1 packets transmitted") {
			t.Log("网络故障恢复成功")
		}
	}
	
	// 测试文件系统错误处理
	fsContainerID := createSysboxContainer(t, "test-fs-error", "ubuntu:20.04", 
		[]string{"sleep", "300"})
	defer cleanupContainer(t, fsContainerID)
	
	// 尝试访问不存在的文件
	_, fsErr := execInContainerWithError(fsContainerID, "cat", "/nonexistent/file")
	assert.Error(t, fsErr, "访问不存在文件应该返回错误")
	
	// 验证容器仍然运行
	fsState := getContainerState(t, fsContainerID)
	assert.Equal(t, "running", fsState.Status, "文件系统错误不应该影响容器运行")
	
	// 测试权限错误处理
	permissionTest := execInContainer(t, fsContainerID, "useradd", "testuser")
	if strings.TrimSpace(permissionTest) == "" {
		// 以普通用户身份尝试特权操作
		_, permErr := execInContainerWithError(fsContainerID, "su", "-c", "mount /tmp /mnt", "testuser")
		assert.Error(t, permErr, "普通用户不应该能执行特权操作")
	}
}

// testContainerMetadataAndLabels 测试容器元数据和标签管理
func testContainerMetadataAndLabels(t *testing.T) {
	containerName := "test-metadata-labels"
	
	// 创建带标签的容器
	labels := map[string]string{
		"app":         "test-application",
		"version":     "1.0.0",
		"environment": "testing",
		"team":        "qa",
	}
	
	labelArgs := []string{}
	for key, value := range labels {
		labelArgs = append(labelArgs, "--label", fmt.Sprintf("%s=%s", key, value))
	}
	
	args := append([]string{"run", "-d", "--name", containerName, "--runtime=sysbox-runc"}, labelArgs...)
	args = append(args, "ubuntu:20.04", "sleep", "300")
	
	output, err := exec.Command("docker", args...).Output()
	require.NoError(t, err, "带标签的容器创建应该成功")
	
	containerID := strings.TrimSpace(string(output))
	defer cleanupContainer(t, containerID)
	
	// 验证标签设置
	containerInfo := getContainerInfo(t, containerID)
	containerLabels := containerInfo["Config"].(map[string]interface{})["Labels"].(map[string]interface{})
	
	for key, expectedValue := range labels {
		actualValue, exists := containerLabels[key]
		assert.True(t, exists, fmt.Sprintf("标签%s应该存在", key))
		assert.Equal(t, expectedValue, actualValue, fmt.Sprintf("标签%s的值应该正确", key))
	}
	
	// 测试标签过滤
	filterOutput := execCommand(t, "docker", "ps", "--filter", "label=app=test-application", "--format", "{{.Names}}")
	assert.Contains(t, filterOutput, containerName, "标签过滤应该找到容器")
	
	// 测试多标签过滤
	multiFilterOutput := execCommand(t, "docker", "ps", "--filter", "label=app=test-application", 
		"--filter", "label=environment=testing", "--format", "{{.Names}}")
	assert.Contains(t, multiFilterOutput, containerName, "多标签过滤应该找到容器")
	
	// 验证容器注解
	annotations := containerInfo["Config"].(map[string]interface{})["Labels"]
	if annotations != nil {
		t.Logf("容器注解数量: %d", len(annotations.(map[string]interface{})))
	}
	
	// 测试环境变量元数据
	envContainerID := createSysboxContainerWithOptions(t, "test-env-metadata", "ubuntu:20.04", 
		[]string{"sleep", "300"}, "-e", "APP_NAME=test-app", "-e", "APP_VERSION=2.0.0")
	defer cleanupContainer(t, envContainerID)
	
	envInfo := getContainerInfo(t, envContainerID)
	envVars := envInfo["Config"].(map[string]interface{})["Env"].([]interface{})
	
	foundAppName := false
	foundAppVersion := false
	for _, env := range envVars {
		envStr := env.(string)
		if envStr == "APP_NAME=test-app" {
			foundAppName = true
		}
		if envStr == "APP_VERSION=2.0.0" {
			foundAppVersion = true
		}
	}
	
	assert.True(t, foundAppName, "应该找到APP_NAME环境变量")
	assert.True(t, foundAppVersion, "应该找到APP_VERSION环境变量")
	
	// 验证容器内环境变量
	envOutput := execInContainer(t, envContainerID, "env")
	assert.Contains(t, envOutput, "APP_NAME=test-app", "容器内应该有APP_NAME环境变量")
	assert.Contains(t, envOutput, "APP_VERSION=2.0.0", "容器内应该有APP_VERSION环境变量")
	
	// 测试工作目录元数据
	workdirContainerID := createSysboxContainerWithOptions(t, "test-workdir-metadata", "ubuntu:20.04", 
		[]string{"pwd"}, "-w", "/tmp")
	defer cleanupContainer(t, workdirContainerID)
	
	// 等待容器执行完成
	time.Sleep(3 * time.Second)
	
	workdirLogs := execCommand(t, "docker", "logs", workdirContainerID)
	assert.Contains(t, workdirLogs, "/tmp", "工作目录应该设置正确")
	
	// 验证用户元数据
	userContainerID := createSysboxContainerWithOptions(t, "test-user-metadata", "ubuntu:20.04", 
		[]string{"whoami"}, "-u", "1000:1000")
	defer cleanupContainer(t, userContainerID)
	
	time.Sleep(3 * time.Second)
	
	userLogs := execCommand(t, "docker", "logs", userContainerID)
	// 注意：在用户命名空间中，用户可能仍显示为其他值
	t.Logf("容器用户输出: %s", userLogs)
	
	// 测试容器命令元数据
	cmdInfo := getContainerInfo(t, containerID)
	cmd := cmdInfo["Config"].(map[string]interface{})["Cmd"].([]interface{})
	
	assert.Len(t, cmd, 2, "命令应该有2个参数")
	assert.Equal(t, "sleep", cmd[0], "第一个参数应该是sleep")
	assert.Equal(t, "300", cmd[1], "第二个参数应该是300")
	
	// 验证入口点元数据
	entrypoint := cmdInfo["Config"].(map[string]interface{})["Entrypoint"]
	if entrypoint != nil {
		t.Logf("容器入口点: %v", entrypoint)
	}
	
	// 测试端口元数据
	portContainerID := createSysboxContainerWithOptions(t, "test-port-metadata", "nginx:alpine", 
		[]string{}, "-p", "8080:80")
	defer cleanupContainer(t, portContainerID)
	
	portInfo := getContainerInfo(t, portContainerID)
	portBindings := portInfo["HostConfig"].(map[string]interface{})["PortBindings"].(map[string]interface{})
	
	if len(portBindings) > 0 {
		t.Log("发现端口绑定配置")
		for port, bindings := range portBindings {
			t.Logf("端口 %s 绑定: %v", port, bindings)
		}
	}
	
	// 验证网络元数据
	networkSettings := containerInfo["NetworkSettings"].(map[string]interface{})
	networks := networkSettings["Networks"].(map[string]interface{})
	
	for networkName, networkConfig := range networks {
		t.Logf("网络 %s 配置: %v", networkName, networkConfig)
	}
}

// testContainerLifecycleEventsAndHooks 测试容器生命周期事件和钩子
func testContainerLifecycleEventsAndHooks(t *testing.T) {
	containerName := "test-lifecycle-events"
	
	// 开始监听事件
	eventsCmd := exec.Command("docker", "events", "--since", "now", "--filter", 
		fmt.Sprintf("container=%s", containerName))
	eventsOutput, err := eventsCmd.StdoutPipe()
	require.NoError(t, err, "事件监听应该成功启动")
	
	err = eventsCmd.Start()
	require.NoError(t, err, "事件监听进程应该启动")
	
	defer func() {
		eventsCmd.Process.Kill()
		eventsCmd.Wait()
	}()
	
	// 创建容器
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 执行生命周期操作
	operations := []struct {
		action string
		cmd    []string
	}{
		{"pause", []string{"docker", "pause", containerID}},
		{"unpause", []string{"docker", "unpause", containerID}},
		{"restart", []string{"docker", "restart", containerID}},
		{"stop", []string{"docker", "stop", containerID}},
		{"start", []string{"docker", "start", containerID}},
	}
	
	for _, op := range operations {
		t.Logf("执行操作: %s", op.action)
		execCommand(t, op.cmd[0], op.cmd[1:]...)
		time.Sleep(2 * time.Second)
	}
	
	// 停止事件监听
	eventsCmd.Process.Kill()
	eventsCmd.Wait()
	
	// 读取事件输出
	eventBytes, err := ioutil.ReadAll(eventsOutput)
	if err == nil {
		eventsList := string(eventBytes)
		t.Logf("捕获的事件: %s", eventsList)
		
		// 验证各种事件
		expectedEvents := []string{"create", "start", "pause", "unpause", "restart", "stop"}
		for _, event := range expectedEvents {
			if strings.Contains(eventsList, event) {
				t.Logf("✓ 检测到%s事件", event)
			}
		}
	}
	
	// 测试事件过滤
	filteredEvents := execCommand(t, "docker", "events", "--since", "5m", "--until", "now", 
		"--filter", fmt.Sprintf("container=%s", containerID), "--filter", "event=start")
	
	if strings.Contains(filteredEvents, "start") {
		t.Log("事件过滤功能正常")
	}
	
	// 测试容器删除事件
	removeEvents := execCommand(t, "docker", "events", "--since", "now", "--filter", 
		fmt.Sprintf("container=%s", containerID), "--filter", "event=destroy")
	
	// 删除容器触发事件
	execCommand(t, "docker", "rm", "-f", containerID)
	
	time.Sleep(2 * time.Second)
	
	// 验证删除事件
	finalEvents := execCommand(t, "docker", "events", "--since", "1m", "--until", "now", 
		"--filter", fmt.Sprintf("container=%s", containerID))
	
	if strings.Contains(finalEvents, "destroy") {
		t.Log("容器删除事件正常记录")
	}
	
	// 测试自定义事件标签
	labeledContainerID := createSysboxContainerWithOptions(t, "test-labeled-events", "ubuntu:20.04", 
		[]string{"sleep", "60"}, "--label", "event-test=true")
	
	defer cleanupContainer(t, labeledContainerID)
	
	labeledEvents := execCommand(t, "docker", "events", "--since", "30s", "--until", "now", 
		"--filter", "label=event-test=true")
	
	if strings.Contains(labeledEvents, "create") {
		t.Log("标签事件过滤功能正常")
	}
	
	// 测试事件格式化
	formattedEvents := execCommand(t, "docker", "events", "--since", "2m", "--until", "now", 
		"--filter", fmt.Sprintf("container=%s", labeledContainerID), 
		"--format", "{{.Time}} {{.Action}} {{.Type}}")
	
	if strings.TrimSpace(formattedEvents) != "" {
		t.Log("事件格式化功能正常")
		eventLines := strings.Split(strings.TrimSpace(formattedEvents), "\n")
		for _, line := range eventLines {
			if strings.TrimSpace(line) != "" {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					t.Logf("格式化事件: 时间=%s, 动作=%s, 类型=%s", parts[0], parts[1], parts[2])
				}
			}
		}
	}
	
	// 测试实时事件流
	realtimeEventsCmd := exec.Command("docker", "events", "--filter", 
		fmt.Sprintf("container=%s", labeledContainerID))
	
	realtimeOutput, err := realtimeEventsCmd.StdoutPipe()
	if err == nil {
		realtimeEventsCmd.Start()
		
		// 执行操作触发事件
		go func() {
			time.Sleep(1 * time.Second)
			execCommand(t, "docker", "pause", labeledContainerID)
			time.Sleep(1 * time.Second)
			execCommand(t, "docker", "unpause", labeledContainerID)
		}()
		
		// 读取实时事件
		time.Sleep(5 * time.Second)
		realtimeEventsCmd.Process.Kill()
		realtimeEventsCmd.Wait()
		
		realtimeBytes, _ := ioutil.ReadAll(realtimeOutput)
		realtimeEventsList := string(realtimeBytes)
		
		if strings.Contains(realtimeEventsList, "pause") && strings.Contains(realtimeEventsList, "unpause") {
			t.Log("实时事件流功能正常")
		}
	}
}

// Helper functions for lifecycle tests

func setupLifecycleTestEnv(t *testing.T) {
	// 验证Docker和sysbox-runc
	output, err := exec.Command("docker", "info").Output()
	require.NoError(t, err, "Docker应该正常运行")
	require.Contains(t, string(output), "sysbox-runc", "应该配置sysbox-runc运行时")
	
	// 清理可能存在的测试容器
	testContainers := []string{
		"test-creation-init", "test-startup-running", "test-pause-resume",
		"test-stop-restart", "test-removal-cleanup", "test-running-removal",
		"test-volume-cleanup", "test-volume-cleanup-2", "test-batch-cleanup-0",
		"test-batch-cleanup-1", "test-batch-cleanup-2", "test-zombie",
		"test-health-monitoring", "test-resource-monitoring", "test-resource-constraints",
		"test-exception-recovery", "test-crash", "test-restart-policy", "test-oom",
		"test-signal-handling", "test-network-recovery", "test-fs-error",
		"test-metadata-labels", "test-env-metadata", "test-workdir-metadata",
		"test-user-metadata", "test-port-metadata", "test-lifecycle-events",
		"test-labeled-events",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func cleanupLifecycleTestEnv(t *testing.T) {
	// 清理所有测试容器
	testContainers := []string{
		"test-creation-init", "test-startup-running", "test-pause-resume",
		"test-stop-restart", "test-removal-cleanup", "test-running-removal",
		"test-volume-cleanup", "test-volume-cleanup-2", "test-batch-cleanup-0",
		"test-batch-cleanup-1", "test-batch-cleanup-2", "test-zombie",
		"test-health-monitoring", "test-resource-monitoring", "test-resource-constraints",
		"test-exception-recovery", "test-crash", "test-restart-policy", "test-oom",
		"test-signal-handling", "test-network-recovery", "test-fs-error",
		"test-metadata-labels", "test-env-metadata", "test-workdir-metadata",
		"test-user-metadata", "test-port-metadata", "test-lifecycle-events",
		"test-labeled-events",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func getContainerState(t *testing.T, containerID string) ContainerState {
	output := execCommand(t, "docker", "inspect", containerID)
	
	var containerInfo []map[string]interface{}
	err := json.Unmarshal([]byte(output), &containerInfo)
	require.NoError(t, err, "容器信息应该能够解析")
	require.Len(t, containerInfo, 1, "应该返回一个容器信息")
	
	stateInfo := containerInfo[0]["State"].(map[string]interface{})
	
	return ContainerState{
		Status:     stateInfo["Status"].(string),
		Running:    stateInfo["Running"].(bool),
		Paused:     stateInfo["Paused"].(bool),
		Restarting: stateInfo["Restarting"].(bool),
		OOMKilled:  stateInfo["OOMKilled"].(bool),
		Dead:       stateInfo["Dead"].(bool),
		Pid:        int(stateInfo["Pid"].(float64)),
		ExitCode:   int(stateInfo["ExitCode"].(float64)),
		StartedAt:  stateInfo["StartedAt"].(string),
		FinishedAt: stateInfo["FinishedAt"].(string),
	}
}

func getContainerInfo(t *testing.T, containerID string) map[string]interface{} {
	output := execCommand(t, "docker", "inspect", containerID)
	
	var containerInfo []map[string]interface{}
	err := json.Unmarshal([]byte(output), &containerInfo)
	require.NoError(t, err, "容器信息应该能够解析")
	require.Len(t, containerInfo, 1, "应该返回一个容器信息")
	
	return containerInfo[0]
}

func getContainerHealth(t *testing.T, containerID string) string {
	info := getContainerInfo(t, containerID)
	
	if state, exists := info["State"].(map[string]interface{})["Health"]; exists {
		return state.(map[string]interface{})["Status"].(string)
	}
	
	return "none"
}

func getContainerHealthHistory(t *testing.T, containerID string) []map[string]interface{} {
	info := getContainerInfo(t, containerID)
	
	if state, exists := info["State"].(map[string]interface{})["Health"]; exists {
		if log, exists := state.(map[string]interface{})["Log"]; exists {
			logEntries := log.([]interface{})
			result := make([]map[string]interface{}, len(logEntries))
			for i, entry := range logEntries {
				result[i] = entry.(map[string]interface{})
			}
			return result
		}
	}
	
	return []map[string]interface{}{}
}

func getContainerStats(t *testing.T, containerID string) map[string]string {
	output := execCommand(t, "docker", "stats", "--no-stream", "--format", 
		"{{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.NetIO}},{{.BlockIO}}", containerID)
	
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) >= 1 {
		parts := strings.Split(lines[0], ",")
		if len(parts) >= 5 {
			return map[string]string{
				"Container": parts[0],
				"CPUPerc":   parts[1],
				"MemUsage":  parts[2],
				"NetIO":     parts[3],
				"BlockIO":   parts[4],
			}
		}
	}
	
	return map[string]string{}
}

func getContainerResourceLimit(t *testing.T, containerID string, resource string) int64 {
	info := getContainerInfo(t, containerID)
	hostConfig := info["HostConfig"].(map[string]interface{})
	
	switch resource {
	case "Memory":
		if memory, exists := hostConfig["Memory"]; exists {
			return int64(memory.(float64))
		}
	case "CPUs":
		if cpus, exists := hostConfig["NanoCpus"]; exists {
			return int64(cpus.(float64))
		}
	}
	
	return 0
}

func getContainerRestartCount(t *testing.T, containerID string) int {
	info := getContainerInfo(t, containerID)
	state := info["State"].(map[string]interface{})
	
	if restartCount, exists := state["RestartCount"]; exists {
		return int(restartCount.(float64))
	}
	
	return 0
}

func getProcessStatus(t *testing.T, pid int) string {
	statusFile := fmt.Sprintf("/proc/%d/status", pid)
	content, err := ioutil.ReadFile(statusFile)
	if err != nil {
		return "not found"
	}
	
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "State:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "State:"))
		}
	}
	
	return "unknown"
}

func execCommand(t *testing.T, name string, args ...string) string {
	output, err := exec.Command(name, args...).Output()
	require.NoError(t, err, "命令执行应该成功: %s %v", name, args)
	return string(output)
}

func execCommandWithError(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).Output()
	return string(output), err
}