package core

import (
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

// TestCgroupManagement 测试Sysbox Cgroup管理核心流程
func TestCgroupManagement(t *testing.T) {
	setupCgroupTestEnv(t)
	defer cleanupCgroupTestEnv(t)

	t.Run("Cgroup层次结构和挂载", func(t *testing.T) {
		testCgroupHierarchyAndMounts(t)
	})

	t.Run("内存Cgroup管理", func(t *testing.T) {
		testMemoryCgroupManagement(t)
	})

	t.Run("CPU Cgroup管理", func(t *testing.T) {
		testCPUCgroupManagement(t)
	})

	t.Run("PID Cgroup管理", func(t *testing.T) {
		testPIDCgroupManagement(t)
	})

	t.Run("设备Cgroup管理", func(t *testing.T) {
		testDeviceCgroupManagement(t)
	})

	t.Run("网络Cgroup管理", func(t *testing.T) {
		testNetworkCgroupManagement(t)
	})

	t.Run("Cgroup v1和v2兼容性", func(t *testing.T) {
		testCgroupV1V2Compatibility(t)
	})

	t.Run("容器间Cgroup隔离", func(t *testing.T) {
		testInterContainerCgroupIsolation(t)
	})

	t.Run("Cgroup资源监控", func(t *testing.T) {
		testCgroupResourceMonitoring(t)
	})

	t.Run("Cgroup限制违规处理", func(t *testing.T) {
		testCgroupLimitViolationHandling(t)
	})
}

// testCgroupHierarchyAndMounts 测试Cgroup层次结构和挂载
func testCgroupHierarchyAndMounts(t *testing.T) {
	containerName := "test-cgroup-hierarchy"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 检查cgroup文件系统挂载
	mountOutput := execInContainer(t, containerID, "mount", "|", "grep", "cgroup")
	assert.Contains(t, mountOutput, "cgroup", "应该挂载cgroup文件系统")
	
	// 检查cgroup根目录
	cgroupRoot := "/sys/fs/cgroup"
	cgroupContent := execInContainer(t, containerID, "ls", "-la", cgroupRoot)
	assert.NotEmpty(t, cgroupContent, "cgroup根目录应该存在")
	
	// 检查主要的cgroup子系统
	expectedSubsystems := []string{
		"memory",
		"cpu",
		"cpuset", 
		"devices",
		"freezer",
		"pids",
	}
	
	for _, subsystem := range expectedSubsystems {
		subsystemPath := filepath.Join(cgroupRoot, subsystem)
		if fileExists(t, containerID, subsystemPath) {
			t.Logf("Cgroup子系统%s存在", subsystem)
			
			// 验证子系统目录结构
			subsystemContent := execInContainer(t, containerID, "ls", subsystemPath)
			assert.NotEmpty(t, subsystemContent, fmt.Sprintf("%s子系统目录应该不为空", subsystem))
		} else {
			t.Logf("Cgroup子系统%s不存在（可能是cgroup v2或不同配置）", subsystem)
		}
	}
	
	// 检查容器的cgroup信息
	cgroupInfo := execInContainer(t, containerID, "cat", "/proc/self/cgroup")
	assert.NotEmpty(t, cgroupInfo, "进程应该有cgroup信息")
	assert.Contains(t, cgroupInfo, "docker", "进程应该在Docker的cgroup中")
	
	// 解析cgroup路径
	cgroupLines := strings.Split(strings.TrimSpace(cgroupInfo), "\n")
	cgroupPaths := make(map[string]string)
	
	for _, line := range cgroupLines {
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			hierarchy := parts[0]
			subsystems := parts[1]
			path := parts[2]
			cgroupPaths[subsystems] = path
			t.Logf("Cgroup路径 - 层次结构:%s, 子系统:%s, 路径:%s", hierarchy, subsystems, path)
		}
	}
	
	// 验证cgroup路径格式
	for subsystem, path := range cgroupPaths {
		assert.True(t, strings.HasPrefix(path, "/"), fmt.Sprintf("Cgroup路径应该以/开头: %s", path))
		if subsystem != "" {
			assert.Contains(t, path, "docker", fmt.Sprintf("Cgroup路径应该包含docker: %s", path))
		}
	}
	
	// 测试cgroup文件权限
	if fileExists(t, containerID, "/sys/fs/cgroup/memory") {
		memoryPerms := execInContainer(t, containerID, "ls", "-ld", "/sys/fs/cgroup/memory")
		assert.Contains(t, memoryPerms, "dr-xr-xr-x", "cgroup目录权限应该正确")
	}
	
	// 检查cgroup控制器可用性
	if fileExists(t, containerID, "/sys/fs/cgroup/cgroup.controllers") {
		// cgroup v2
		controllers := execInContainer(t, containerID, "cat", "/sys/fs/cgroup/cgroup.controllers")
		t.Logf("可用的cgroup v2控制器: %s", controllers)
	} else {
		// cgroup v1
		t.Log("使用cgroup v1")
	}
}

// testMemoryCgroupManagement 测试内存Cgroup管理
func testMemoryCgroupManagement(t *testing.T) {
	containerName := "test-memory-cgroup"
	
	// 创建带内存限制的容器
	containerID := createSysboxContainerWithOptions(t, containerName, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--memory=256m")
	defer cleanupContainer(t, containerID)
	
	// 检查内存cgroup配置
	memCgroupPath := findMemoryCgroupPath(t, containerID)
	if memCgroupPath == "" {
		t.Skip("未找到内存cgroup路径，跳过测试")
		return
	}
	
	// 验证内存限制设置
	memLimitFile := filepath.Join(memCgroupPath, "memory.limit_in_bytes")
	if fileExists(t, containerID, memLimitFile) {
		memLimit := execInContainer(t, containerID, "cat", memLimitFile)
		memLimitBytes := parseBytes(t, strings.TrimSpace(memLimit))
		expectedBytes := int64(256 * 1024 * 1024) // 256MB
		
		assert.InDelta(t, expectedBytes, memLimitBytes, float64(expectedBytes)*0.1,
			"内存限制应该接近设置值")
	}
	
	// 检查内存使用统计
	memUsageFile := filepath.Join(memCgroupPath, "memory.usage_in_bytes")
	if fileExists(t, containerID, memUsageFile) {
		memUsage := execInContainer(t, containerID, "cat", memUsageFile)
		memUsageBytes := parseBytes(t, strings.TrimSpace(memUsage))
		assert.Greater(t, memUsageBytes, int64(0), "内存使用量应该大于0")
		
		t.Logf("当前内存使用: %d bytes", memUsageBytes)
	}
	
	// 检查内存统计详情
	memStatFile := filepath.Join(memCgroupPath, "memory.stat")
	if fileExists(t, containerID, memStatFile) {
		memStat := execInContainer(t, containerID, "cat", memStatFile)
		assert.Contains(t, memStat, "rss", "内存统计应该包含RSS信息")
		assert.Contains(t, memStat, "cache", "内存统计应该包含缓存信息")
		
		// 解析内存统计
		memStats := parseMemoryStats(memStat)
		for key, value := range memStats {
			if value > 0 {
				t.Logf("内存统计 %s: %d", key, value)
			}
		}
	}
	
	// 测试内存分配和监控
	memAllocTest := execInContainer(t, containerID, "python3", "-c", `
import time
import gc

print("开始内存分配测试")

# 分配100MB内存
chunks = []
chunk_size = 10 * 1024 * 1024  # 10MB

for i in range(10):
    chunk = bytearray(chunk_size)
    chunks.append(chunk)
    print(f"分配了 {(i+1) * 10}MB 内存")
    time.sleep(0.5)

print("内存分配完成，等待5秒")
time.sleep(5)

# 释放内存
chunks.clear()
gc.collect()
print("内存释放完成")
`)
	
	assert.Contains(t, memAllocTest, "内存分配完成", "内存分配测试应该成功")
	
	// 再次检查内存使用
	if fileExists(t, containerID, memUsageFile) {
		finalMemUsage := execInContainer(t, containerID, "cat", memUsageFile)
		finalMemUsageBytes := parseBytes(t, strings.TrimSpace(finalMemUsage))
		t.Logf("最终内存使用: %d bytes", finalMemUsageBytes)
	}
	
	// 测试内存压力处理
	memPressureTest := execInContainer(t, containerID, "python3", "-c", `
import sys
try:
    # 尝试分配超过限制的内存
    big_chunk = bytearray(300 * 1024 * 1024)  # 300MB > 256MB limit
    print("大内存块分配成功")
except MemoryError:
    print("内存限制生效，分配失败")
except Exception as e:
    print(f"内存分配异常: {e}")
`)
	
	t.Logf("内存压力测试结果: %s", memPressureTest)
	
	// 检查OOM事件
	oomControlFile := filepath.Join(memCgroupPath, "memory.oom_control")
	if fileExists(t, containerID, oomControlFile) {
		oomControl := execInContainer(t, containerID, "cat", oomControlFile)
		t.Logf("OOM控制设置: %s", oomControl)
	}
}

// testCPUCgroupManagement 测试CPU Cgroup管理
func testCPUCgroupManagement(t *testing.T) {
	containerName := "test-cpu-cgroup"
	
	// 创建带CPU限制的容器
	containerID := createSysboxContainerWithOptions(t, containerName, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--cpus=0.5")
	defer cleanupContainer(t, containerID)
	
	// 检查CPU cgroup配置
	cpuCgroupPath := findCPUCgroupPath(t, containerID)
	if cpuCgroupPath == "" {
		t.Skip("未找到CPU cgroup路径，跳过测试")
		return
	}
	
	// 验证CPU配额设置
	cpuQuotaFile := filepath.Join(cpuCgroupPath, "cpu.cfs_quota_us")
	cpuPeriodFile := filepath.Join(cpuCgroupPath, "cpu.cfs_period_us")
	
	if fileExists(t, containerID, cpuQuotaFile) && fileExists(t, containerID, cpuPeriodFile) {
		cpuQuota := execInContainer(t, containerID, "cat", cpuQuotaFile)
		cpuPeriod := execInContainer(t, containerID, "cat", cpuPeriodFile)
		
		quotaValue, err := strconv.Atoi(strings.TrimSpace(cpuQuota))
		if err == nil && quotaValue > 0 {
			periodValue, err := strconv.Atoi(strings.TrimSpace(cpuPeriod))
			if err == nil {
				cpuRatio := float64(quotaValue) / float64(periodValue)
				t.Logf("CPU配额: %d微秒, 周期: %d微秒, 比率: %.2f", quotaValue, periodValue, cpuRatio)
				assert.InDelta(t, 0.5, cpuRatio, 0.1, "CPU比率应该接近0.5")
			}
		}
	}
	
	// 检查CPU份额设置
	cpuSharesFile := filepath.Join(cpuCgroupPath, "cpu.shares")
	if fileExists(t, containerID, cpuSharesFile) {
		cpuShares := execInContainer(t, containerID, "cat", cpuSharesFile)
		sharesValue, err := strconv.Atoi(strings.TrimSpace(cpuShares))
		if err == nil {
			t.Logf("CPU份额: %d", sharesValue)
			assert.Greater(t, sharesValue, 0, "CPU份额应该大于0")
		}
	}
	
	// 检查CPU统计
	cpuStatFile := filepath.Join(cpuCgroupPath, "cpuacct.stat")
	if fileExists(t, containerID, cpuStatFile) {
		cpuStat := execInContainer(t, containerID, "cat", cpuStatFile)
		assert.Contains(t, cpuStat, "user", "CPU统计应该包含用户时间")
		assert.Contains(t, cpuStat, "system", "CPU统计应该包含系统时间")
		
		t.Logf("CPU统计: %s", cpuStat)
	}
	
	// 测试CPU密集型任务
	cpuIntensiveTest := execInContainer(t, containerID, "python3", "-c", `
import time
import threading
import multiprocessing

def cpu_task(duration):
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        count += 1
    return count

print("开始CPU密集型测试")
start_time = time.time()

# 启动多个CPU密集型线程
threads = []
for i in range(2):
    t = threading.Thread(target=cpu_task, args=(3,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

end_time = time.time()
print(f"CPU密集型任务完成，耗时: {end_time - start_time:.2f}秒")
`)
	
	assert.Contains(t, cpuIntensiveTest, "CPU密集型任务完成", "CPU测试应该成功")
	
	// 再次检查CPU统计
	if fileExists(t, containerID, cpuStatFile) {
		finalCpuStat := execInContainer(t, containerID, "cat", cpuStatFile)
		t.Logf("最终CPU统计: %s", finalCpuStat)
	}
	
	// 检查CPU使用限制
	cpuUsageFile := filepath.Join(cpuCgroupPath, "cpuacct.usage")
	if fileExists(t, containerID, cpuUsageFile) {
		cpuUsage := execInContainer(t, containerID, "cat", cpuUsageFile)
		usageValue, err := strconv.ParseInt(strings.TrimSpace(cpuUsage), 10, 64)
		if err == nil {
			t.Logf("CPU使用时间: %d纳秒", usageValue)
			assert.Greater(t, usageValue, int64(0), "CPU使用时间应该大于0")
		}
	}
	
	// 测试CPU套件绑定（如果支持）
	cpusetCpusFile := filepath.Join(cpuCgroupPath, "cpuset.cpus")
	if fileExists(t, containerID, cpusetCpusFile) {
		cpusetCpus := execInContainer(t, containerID, "cat", cpusetCpusFile)
		t.Logf("CPU集合: %s", strings.TrimSpace(cpusetCpus))
	}
}

// testPIDCgroupManagement 测试PID Cgroup管理
func testPIDCgroupManagement(t *testing.T) {
	containerName := "test-pid-cgroup"
	
	// 创建带PID限制的容器
	containerID := createSysboxContainerWithOptions(t, containerName, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--pids-limit=50")
	defer cleanupContainer(t, containerID)
	
	// 检查PID cgroup配置
	pidCgroupPath := findPIDCgroupPath(t, containerID)
	if pidCgroupPath == "" {
		t.Skip("未找到PID cgroup路径，跳过测试")
		return
	}
	
	// 验证PID限制设置
	pidMaxFile := filepath.Join(pidCgroupPath, "pids.max")
	if fileExists(t, containerID, pidMaxFile) {
		pidMax := execInContainer(t, containerID, "cat", pidMaxFile)
		pidMaxValue := strings.TrimSpace(pidMax)
		
		if pidMaxValue != "max" {
			maxPids, err := strconv.Atoi(pidMaxValue)
			if err == nil {
				t.Logf("PID限制: %d", maxPids)
				assert.Equal(t, 50, maxPids, "PID限制应该是50")
			}
		} else {
			t.Log("PID限制设置为无限制")
		}
	}
	
	// 检查当前PID数量
	pidCurrentFile := filepath.Join(pidCgroupPath, "pids.current")
	if fileExists(t, containerID, pidCurrentFile) {
		pidCurrent := execInContainer(t, containerID, "cat", pidCurrentFile)
		currentPids, err := strconv.Atoi(strings.TrimSpace(pidCurrent))
		if err == nil {
			t.Logf("当前PID数量: %d", currentPids)
			assert.Greater(t, currentPids, 0, "当前PID数量应该大于0")
		}
	}
	
	// 测试进程创建和PID限制
	pidLimitTest := execInContainer(t, containerID, "python3", "-c", `
import os
import signal
import time

def create_child_process():
    try:
        pid = os.fork()
        if pid == 0:
            # 子进程
            time.sleep(10)
            os._exit(0)
        return pid
    except OSError as e:
        print(f"创建进程失败: {e}")
        return None

print("开始PID限制测试")
child_pids = []

try:
    for i in range(60):  # 尝试创建超过限制的进程
        pid = create_child_process()
        if pid is not None:
            child_pids.append(pid)
            print(f"创建进程 {i+1}: PID {pid}")
        else:
            print(f"进程创建失败，达到第 {i+1} 个进程")
            break
        
        if i % 10 == 9:
            time.sleep(0.1)  # 短暂暂停
    
    print(f"总共创建了 {len(child_pids)} 个子进程")
    
finally:
    # 清理子进程
    for pid in child_pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except:
            pass
    
    # 等待子进程退出
    for pid in child_pids:
        try:
            os.waitpid(pid, 0)
        except:
            pass
    
    print("子进程清理完成")
`)
	
	t.Logf("PID限制测试结果: %s", pidLimitTest)
	
	// 再次检查PID数量
	if fileExists(t, containerID, pidCurrentFile) {
		finalPidCurrent := execInContainer(t, containerID, "cat", pidCurrentFile)
		finalCurrentPids, err := strconv.Atoi(strings.TrimSpace(finalPidCurrent))
		if err == nil {
			t.Logf("最终PID数量: %d", finalCurrentPids)
		}
	}
	
	// 检查PID事件统计
	pidEventsFile := filepath.Join(pidCgroupPath, "pids.events")
	if fileExists(t, containerID, pidEventsFile) {
		pidEvents := execInContainer(t, containerID, "cat", pidEventsFile)
		t.Logf("PID事件统计: %s", pidEvents)
		
		if strings.Contains(pidEvents, "max") {
			// 解析max事件计数
			lines := strings.Split(pidEvents, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "max ") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						maxEvents, err := strconv.Atoi(parts[1])
						if err == nil && maxEvents > 0 {
							t.Logf("PID限制违规事件: %d次", maxEvents)
						}
					}
				}
			}
		}
	}
	
	// 验证进程树隔离
	processTree := execInContainer(t, containerID, "pstree", "-p")
	if !strings.Contains(processTree, "command not found") {
		t.Logf("进程树: %s", processTree)
	}
}

// testDeviceCgroupManagement 测试设备Cgroup管理
func testDeviceCgroupManagement(t *testing.T) {
	containerName := "test-device-cgroup"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 检查设备cgroup配置
	deviceCgroupPath := findDeviceCgroupPath(t, containerID)
	if deviceCgroupPath == "" {
		t.Skip("未找到设备cgroup路径，跳过测试")
		return
	}
	
	// 检查设备允许列表
	deviceAllowFile := filepath.Join(deviceCgroupPath, "devices.allow")
	if fileExists(t, containerID, deviceAllowFile) {
		deviceAllow := execInContainer(t, containerID, "cat", deviceAllowFile)
		t.Logf("设备允许列表: %s", deviceAllow)
	}
	
	// 检查设备拒绝列表
	deviceDenyFile := filepath.Join(deviceCgroupPath, "devices.deny")
	if fileExists(t, containerID, deviceDenyFile) {
		deviceDeny := execInContainer(t, containerID, "cat", deviceDenyFile)
		t.Logf("设备拒绝列表: %s", deviceDeny)
	}
	
	// 检查设备列表
	deviceListFile := filepath.Join(deviceCgroupPath, "devices.list")
	if fileExists(t, containerID, deviceListFile) {
		deviceList := execInContainer(t, containerID, "cat", deviceListFile)
		t.Logf("设备列表: %s", deviceList)
		
		// 验证基本设备权限
		assert.Contains(t, deviceList, "c 1:3", "应该允许访问/dev/null")
		assert.Contains(t, deviceList, "c 1:5", "应该允许访问/dev/zero")
		assert.Contains(t, deviceList, "c 1:8", "应该允许访问/dev/random")
		assert.Contains(t, deviceList, "c 1:9", "应该允许访问/dev/urandom")
	}
	
	// 测试设备访问
	deviceAccessTests := []struct {
		device      string
		shouldWork  bool
		description string
	}{
		{"/dev/null", true, "null设备应该可访问"},
		{"/dev/zero", true, "zero设备应该可访问"},
		{"/dev/random", true, "random设备应该可访问"},
		{"/dev/urandom", true, "urandom设备应该可访问"},
		{"/dev/kmsg", false, "kmsg设备应该被限制"},
		{"/dev/mem", false, "mem设备应该被限制"},
	}
	
	for _, test := range deviceAccessTests {
		if fileExists(t, containerID, test.device) {
			_, err := execInContainerWithError(containerID, "head", "-c", "1", test.device)
			if test.shouldWork {
				if err == nil {
					t.Logf("✓ %s", test.description)
				} else {
					t.Errorf("✗ %s (错误: %v)", test.description, err)
				}
			} else {
				if err != nil {
					t.Logf("✓ %s", test.description)
				} else {
					t.Logf("! %s (未被限制，可能有特殊处理)", test.description)
				}
			}
		}
	}
	
	// 测试设备节点创建限制
	mknodTest := execInContainer(t, containerID, "python3", "-c", `
import os
import stat

try:
    # 尝试创建字符设备节点
    os.mknod('/tmp/test-char-device', stat.S_IFCHR | 0o666, os.makedev(1, 1))
    print("字符设备节点创建成功")
except PermissionError:
    print("字符设备节点创建被拒绝")
except Exception as e:
    print(f"字符设备节点创建失败: {e}")

try:
    # 尝试创建块设备节点
    os.mknod('/tmp/test-block-device', stat.S_IFBLK | 0o666, os.makedev(8, 0))
    print("块设备节点创建成功")
except PermissionError:
    print("块设备节点创建被拒绝")
except Exception as e:
    print(f"块设备节点创建失败: {e}")
`)
	
	t.Logf("设备节点创建测试: %s", mknodTest)
	
	// 测试特殊设备文件权限
	specialDevices := []string{"/dev/tty", "/dev/console", "/dev/pts/ptmx"}
	for _, device := range specialDevices {
		if fileExists(t, containerID, device) {
			devicePerms := execInContainer(t, containerID, "ls", "-l", device)
			t.Logf("设备权限 %s: %s", device, devicePerms)
		}
	}
}

// testNetworkCgroupManagement 测试网络Cgroup管理
func testNetworkCgroupManagement(t *testing.T) {
	containerName := "test-network-cgroup"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 检查网络cgroup配置
	netCgroupPath := findNetworkCgroupPath(t, containerID)
	if netCgroupPath == "" {
		t.Skip("未找到网络cgroup路径，跳过测试")
		return
	}
	
	// 检查网络分类ID
	netClsIdFile := filepath.Join(netCgroupPath, "net_cls.classid")
	if fileExists(t, containerID, netClsIdFile) {
		netClsId := execInContainer(t, containerID, "cat", netClsIdFile)
		t.Logf("网络分类ID: %s", strings.TrimSpace(netClsId))
	}
	
	// 检查网络优先级
	netPrioIfPrioMapFile := filepath.Join(netCgroupPath, "net_prio.ifpriomap")
	if fileExists(t, containerID, netPrioIfPrioMapFile) {
		netPrioMap := execInContainer(t, containerID, "cat", netPrioIfPrioMapFile)
		t.Logf("网络接口优先级映射: %s", netPrioMap)
	}
	
	// 测试网络带宽控制（如果支持）
	networkBandwidthTest := execInContainer(t, containerID, "python3", "-c", `
import socket
import time
import threading

def network_test():
    try:
        # 创建TCP连接测试网络性能
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        start_time = time.time()
        try:
            sock.connect(('8.8.8.8', 53))
            end_time = time.time()
            print(f"网络连接测试: {(end_time - start_time) * 1000:.2f}ms")
        except Exception as e:
            print(f"网络连接失败: {e}")
        finally:
            sock.close()
            
    except Exception as e:
        print(f"网络测试错误: {e}")

# 运行网络测试
network_test()
`)
	
	t.Logf("网络性能测试: %s", networkBandwidthTest)
	
	// 检查网络命名空间
	netNSInfo := execInContainer(t, containerID, "ls", "-la", "/proc/self/ns/net")
	t.Logf("网络命名空间: %s", netNSInfo)
	
	// 检查网络接口统计
	netDevStats := execInContainer(t, containerID, "cat", "/proc/net/dev")
	t.Logf("网络接口统计: %s", netDevStats)
	
	// 测试网络流量控制
	trafficControlTest := execInContainer(t, containerID, "python3", "-c", `
import subprocess
import time

try:
    # 测试网络流量统计
    start_stats = subprocess.check_output(['cat', '/proc/net/dev']).decode()
    
    # 生成一些网络流量
    subprocess.run(['ping', '-c', '3', '8.8.8.8'], 
                   capture_output=True, timeout=10)
    
    end_stats = subprocess.check_output(['cat', '/proc/net/dev']).decode()
    
    print("网络流量测试完成")
    
except Exception as e:
    print(f"网络流量测试错误: {e}")
`)
	
	t.Logf("网络流量控制测试: %s", trafficControlTest)
}

// testCgroupV1V2Compatibility 测试Cgroup v1和v2兼容性
func testCgroupV1V2Compatibility(t *testing.T) {
	containerName := "test-cgroup-compatibility"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 检查cgroup版本
	cgroupVersion := detectCgroupVersion(t, containerID)
	t.Logf("检测到的cgroup版本: %s", cgroupVersion)
	
	switch cgroupVersion {
	case "v1":
		testCgroupV1Features(t, containerID)
	case "v2":
		testCgroupV2Features(t, containerID)
	case "hybrid":
		t.Log("检测到混合cgroup模式")
		testCgroupV1Features(t, containerID)
		testCgroupV2Features(t, containerID)
	default:
		t.Log("无法确定cgroup版本")
	}
	
	// 通用cgroup功能测试
	testCommonCgroupFeatures(t, containerID)
}

func testCgroupV1Features(t *testing.T, containerID string) {
	t.Log("测试Cgroup v1特性")
	
	// 检查v1特定的文件结构
	v1Paths := []string{
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
		"/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
		"/sys/fs/cgroup/devices/devices.list",
	}
	
	for _, path := range v1Paths {
		if fileExists(t, containerID, path) {
			t.Logf("Cgroup v1文件存在: %s", path)
		}
	}
	
	// 测试v1特有功能
	if fileExists(t, containerID, "/sys/fs/cgroup/memory/memory.stat") {
		memStat := execInContainer(t, containerID, "cat", "/sys/fs/cgroup/memory/memory.stat")
		if strings.Contains(memStat, "hierarchical_memory_limit") {
			t.Log("Cgroup v1内存层次结构功能正常")
		}
	}
}

func testCgroupV2Features(t *testing.T, containerID string) {
	t.Log("测试Cgroup v2特性")
	
	// 检查v2特定的文件结构
	v2Paths := []string{
		"/sys/fs/cgroup/cgroup.controllers",
		"/sys/fs/cgroup/cgroup.procs",
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/cpu.max",
	}
	
	for _, path := range v2Paths {
		if fileExists(t, containerID, path) {
			t.Logf("Cgroup v2文件存在: %s", path)
		}
	}
	
	// 检查v2控制器
	if fileExists(t, containerID, "/sys/fs/cgroup/cgroup.controllers") {
		controllers := execInContainer(t, containerID, "cat", "/sys/fs/cgroup/cgroup.controllers")
		t.Logf("Cgroup v2控制器: %s", controllers)
		
		expectedControllers := []string{"memory", "cpu", "pids"}
		for _, controller := range expectedControllers {
			if strings.Contains(controllers, controller) {
				t.Logf("Cgroup v2控制器%s可用", controller)
			}
		}
	}
	
	// 测试v2统一层次结构
	if fileExists(t, containerID, "/sys/fs/cgroup/cgroup.subtree_control") {
		subtreeControl := execInContainer(t, containerID, "cat", "/sys/fs/cgroup/cgroup.subtree_control")
		t.Logf("Cgroup v2子树控制: %s", subtreeControl)
	}
}

func testCommonCgroupFeatures(t *testing.T, containerID string) {
	t.Log("测试通用cgroup功能")
	
	// 测试进程迁移
	cgroupProcs := execInContainer(t, containerID, "cat", "/proc/self/cgroup")
	assert.NotEmpty(t, cgroupProcs, "进程应该有cgroup信息")
	
	// 测试cgroup事件通知
	cgroupEvents := []string{
		"/sys/fs/cgroup/memory.events",
		"/sys/fs/cgroup/memory/memory.events",
	}
	
	for _, eventFile := range cgroupEvents {
		if fileExists(t, containerID, eventFile) {
			events := execInContainer(t, containerID, "cat", eventFile)
			t.Logf("Cgroup事件 %s: %s", eventFile, events)
		}
	}
	
	// 测试cgroup限制继承
	parentCgroup := execInContainer(t, containerID, "cat", "/proc/1/cgroup")
	currentCgroup := execInContainer(t, containerID, "cat", "/proc/self/cgroup")
	
	t.Logf("父进程cgroup: %s", parentCgroup)
	t.Logf("当前进程cgroup: %s", currentCgroup)
}

// testInterContainerCgroupIsolation 测试容器间Cgroup隔离
func testInterContainerCgroupIsolation(t *testing.T) {
	container1Name := "test-cgroup-isolation-1"
	container2Name := "test-cgroup-isolation-2"
	
	// 创建两个带不同资源限制的容器
	container1ID := createSysboxContainerWithOptions(t, container1Name, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--memory=128m", "--cpus=0.3")
	container2ID := createSysboxContainerWithOptions(t, container2Name, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--memory=256m", "--cpus=0.7")
	
	defer func() {
		cleanupContainer(t, container1ID)
		cleanupContainer(t, container2ID)
	}()
	
	// 验证不同容器的cgroup路径不同
	container1Cgroup := execInContainer(t, container1ID, "cat", "/proc/self/cgroup")
	container2Cgroup := execInContainer(t, container2ID, "cat", "/proc/self/cgroup")
	
	assert.NotEqual(t, container1Cgroup, container2Cgroup, "不同容器应该有不同的cgroup路径")
	
	// 验证各自的资源限制独立
	// 检查容器1的内存限制
	mem1Path := findMemoryCgroupPath(t, container1ID)
	if mem1Path != "" {
		mem1LimitFile := filepath.Join(mem1Path, "memory.limit_in_bytes")
		if fileExists(t, container1ID, mem1LimitFile) {
			mem1Limit := execInContainer(t, container1ID, "cat", mem1LimitFile)
			mem1LimitBytes := parseBytes(t, strings.TrimSpace(mem1Limit))
			expectedBytes1 := int64(128 * 1024 * 1024) // 128MB
			assert.InDelta(t, expectedBytes1, mem1LimitBytes, float64(expectedBytes1)*0.1,
				"容器1内存限制应该是128MB")
		}
	}
	
	// 检查容器2的内存限制
	mem2Path := findMemoryCgroupPath(t, container2ID)
	if mem2Path != "" {
		mem2LimitFile := filepath.Join(mem2Path, "memory.limit_in_bytes")
		if fileExists(t, container2ID, mem2LimitFile) {
			mem2Limit := execInContainer(t, container2ID, "cat", mem2LimitFile)
			mem2LimitBytes := parseBytes(t, strings.TrimSpace(mem2Limit))
			expectedBytes2 := int64(256 * 1024 * 1024) // 256MB
			assert.InDelta(t, expectedBytes2, mem2LimitBytes, float64(expectedBytes2)*0.1,
				"容器2内存限制应该是256MB")
		}
	}
	
	// 测试资源使用隔离
	// 在容器1中分配内存
	mem1Test := execInContainer(t, container1ID, "python3", "-c", `
import time
data = bytearray(50 * 1024 * 1024)  # 50MB
print("容器1: 分配了50MB内存")
time.sleep(2)
`)
	
	// 在容器2中分配内存
	mem2Test := execInContainer(t, container2ID, "python3", "-c", `
import time
data = bytearray(100 * 1024 * 1024)  # 100MB
print("容器2: 分配了100MB内存")
time.sleep(2)
`)
	
	assert.Contains(t, mem1Test, "分配了50MB内存", "容器1内存分配应该成功")
	assert.Contains(t, mem2Test, "分配了100MB内存", "容器2内存分配应该成功")
	
	// 验证进程在不同cgroup中
	container1PID := getContainerPID(t, container1ID)
	container2PID := getContainerPID(t, container2ID)
	
	assert.NotEqual(t, container1PID, container2PID, "不同容器应该有不同的主进程PID")
	
	// 验证cgroup进程列表隔离
	if mem1Path != "" {
		mem1ProcsFile := filepath.Join(mem1Path, "cgroup.procs")
		if fileExists(t, container1ID, mem1ProcsFile) {
			mem1Procs := execInContainer(t, container1ID, "cat", mem1ProcsFile)
			assert.Contains(t, mem1Procs, container1PID, "容器1的进程应该在其cgroup中")
			assert.NotContains(t, mem1Procs, container2PID, "容器1的cgroup不应该包含容器2的进程")
		}
	}
}

// testCgroupResourceMonitoring 测试Cgroup资源监控
func testCgroupResourceMonitoring(t *testing.T) {
	containerName := "test-cgroup-monitoring"
	
	containerID := createSysboxContainerWithOptions(t, containerName, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--memory=256m", "--cpus=0.5")
	defer cleanupContainer(t, containerID)
	
	// 收集初始资源使用情况
	initialMetrics := collectResourceMetrics(t, containerID)
	t.Logf("初始资源指标: %+v", initialMetrics)
	
	// 执行资源密集型任务
	resourceIntensiveTask := execInContainer(t, containerID, "python3", "-c", `
import time
import threading

def memory_task():
    data = []
    for i in range(50):
        chunk = bytearray(1024 * 1024)  # 1MB
        data.append(chunk)
        time.sleep(0.1)
    time.sleep(5)
    print("内存任务完成")

def cpu_task():
    end_time = time.time() + 5
    while time.time() < end_time:
        sum(range(1000))
    print("CPU任务完成")

# 启动并发任务
threads = []
threads.append(threading.Thread(target=memory_task))
threads.append(threading.Thread(target=cpu_task))

for t in threads:
    t.start()

for t in threads:
    t.join()

print("所有任务完成")
`)
	
	assert.Contains(t, resourceIntensiveTask, "所有任务完成", "资源密集型任务应该完成")
	
	// 收集任务后的资源使用情况
	finalMetrics := collectResourceMetrics(t, containerID)
	t.Logf("最终资源指标: %+v", finalMetrics)
	
	// 验证资源使用变化
	if initialMetrics.MemoryUsage > 0 && finalMetrics.MemoryUsage > 0 {
		memoryIncrease := finalMetrics.MemoryUsage - initialMetrics.MemoryUsage
		t.Logf("内存使用增加: %d bytes", memoryIncrease)
	}
	
	if initialMetrics.CPUUsage > 0 && finalMetrics.CPUUsage > 0 {
		cpuIncrease := finalMetrics.CPUUsage - initialMetrics.CPUUsage
		t.Logf("CPU使用增加: %d nanoseconds", cpuIncrease)
	}
	
	// 测试实时监控
	realtimeMonitoring := execInContainer(t, containerID, "python3", "-c", `
import time
import subprocess

def get_memory_usage():
    try:
        with open('/sys/fs/cgroup/memory/memory.usage_in_bytes', 'r') as f:
            return int(f.read().strip())
    except:
        return 0

print("开始实时监控")
for i in range(5):
    mem_usage = get_memory_usage()
    print(f"时间 {i+1}: 内存使用 {mem_usage} bytes")
    time.sleep(1)

print("实时监控完成")
`)
	
	t.Logf("实时监控结果: %s", realtimeMonitoring)
}

// testCgroupLimitViolationHandling 测试Cgroup限制违规处理
func testCgroupLimitViolationHandling(t *testing.T) {
	containerName := "test-cgroup-violation"
	
	// 创建严格资源限制的容器
	containerID := createSysboxContainerWithOptions(t, containerName, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "--memory=64m", "--pids-limit=20")
	defer cleanupContainer(t, containerID)
	
	// 测试内存限制违规
	memoryViolationTest := execInContainer(t, containerID, "python3", "-c", `
import sys
import time

print("开始内存限制违规测试")

try:
    # 尝试分配超过限制的内存（64MB限制，尝试分配100MB）
    big_data = bytearray(100 * 1024 * 1024)
    print("内存分配成功（未触发限制）")
    time.sleep(1)
except MemoryError:
    print("内存限制生效：MemoryError")
except Exception as e:
    print(f"内存分配异常: {e}")

print("内存限制违规测试完成")
`)
	
	t.Logf("内存限制违规测试: %s", memoryViolationTest)
	
	// 检查OOM事件
	memPath := findMemoryCgroupPath(t, containerID)
	if memPath != "" {
		oomControlFile := filepath.Join(memPath, "memory.oom_control")
		if fileExists(t, containerID, oomControlFile) {
			oomControl := execInContainer(t, containerID, "cat", oomControlFile)
			t.Logf("OOM控制状态: %s", oomControl)
			
			if strings.Contains(oomControl, "oom_kill_disable 0") {
				t.Log("OOM killer已启用")
			}
		}
		
		// 检查内存事件
		memEventsFile := filepath.Join(memPath, "memory.events")
		if fileExists(t, containerID, memEventsFile) {
			memEvents := execInContainer(t, containerID, "cat", memEventsFile)
			t.Logf("内存事件: %s", memEvents)
		}
	}
	
	// 测试PID限制违规
	pidViolationTest := execInContainer(t, containerID, "python3", "-c", `
import os
import signal
import time

print("开始PID限制违规测试")
child_pids = []

try:
    for i in range(30):  # 尝试创建超过20个进程
        try:
            pid = os.fork()
            if pid == 0:
                # 子进程
                time.sleep(30)
                os._exit(0)
            else:
                child_pids.append(pid)
                print(f"创建进程 {i+1}: PID {pid}")
        except OSError as e:
            print(f"进程创建失败 (第{i+1}个): {e}")
            break
    
    print(f"成功创建了 {len(child_pids)} 个进程")
    
except Exception as e:
    print(f"PID限制测试异常: {e}")

finally:
    # 清理子进程
    for pid in child_pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except:
            pass

print("PID限制违规测试完成")
`)
	
	t.Logf("PID限制违规测试: %s", pidViolationTest)
	
	// 检查PID事件
	pidPath := findPIDCgroupPath(t, containerID)
	if pidPath != "" {
		pidEventsFile := filepath.Join(pidPath, "pids.events")
		if fileExists(t, containerID, pidEventsFile) {
			pidEvents := execInContainer(t, containerID, "cat", pidEventsFile)
			t.Logf("PID事件: %s", pidEvents)
			
			if strings.Contains(pidEvents, "max") {
				t.Log("检测到PID限制违规事件")
			}
		}
	}
	
	// 测试CPU限制处理
	cpuStressTest := execInContainer(t, containerID, "python3", "-c", `
import time
import threading

def cpu_stress(duration):
    end_time = time.time() + duration
    while time.time() < end_time:
        pass

print("开始CPU压力测试")
start_time = time.time()

# 启动多个CPU密集型线程
threads = []
for i in range(4):  # 启动4个线程竞争0.5个CPU
    t = threading.Thread(target=cpu_stress, args=(5,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

end_time = time.time()
actual_duration = end_time - start_time

print(f"CPU压力测试完成，实际耗时: {actual_duration:.2f}秒")
print(f"预期耗时: 5秒 (受CPU限制影响)")
`)
	
	t.Logf("CPU压力测试: %s", cpuStressTest)
	
	// 验证容器仍然响应
	healthCheck := execInContainer(t, containerID, "echo", "容器健康检查")
	assert.Contains(t, healthCheck, "容器健康检查", "容器应该仍然响应")
}

// Helper functions for cgroup tests

type ResourceMetrics struct {
	MemoryUsage int64
	CPUUsage    int64
	PIDCount    int
}

func setupCgroupTestEnv(t *testing.T) {
	// 验证cgroup支持
	if _, err := os.Stat("/sys/fs/cgroup"); os.IsNotExist(err) {
		t.Skip("系统不支持cgroup，跳过测试")
	}
	
	// 验证Docker和sysbox-runc
	output, err := exec.Command("docker", "info").Output()
	require.NoError(t, err, "Docker应该正常运行")
	require.Contains(t, string(output), "sysbox-runc", "应该配置sysbox-runc运行时")
	
	// 清理测试容器
	testContainers := []string{
		"test-cgroup-hierarchy", "test-memory-cgroup", "test-cpu-cgroup",
		"test-pid-cgroup", "test-device-cgroup", "test-network-cgroup",
		"test-cgroup-compatibility", "test-cgroup-isolation-1", "test-cgroup-isolation-2",
		"test-cgroup-monitoring", "test-cgroup-violation",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func cleanupCgroupTestEnv(t *testing.T) {
	// 清理所有测试容器
	testContainers := []string{
		"test-cgroup-hierarchy", "test-memory-cgroup", "test-cpu-cgroup",
		"test-pid-cgroup", "test-device-cgroup", "test-network-cgroup",
		"test-cgroup-compatibility", "test-cgroup-isolation-1", "test-cgroup-isolation-2",
		"test-cgroup-monitoring", "test-cgroup-violation",
	}
	
	for _, container := range testContainers {
		exec.Command("docker", "rm", "-f", container).Run()
	}
}

func findMemoryCgroupPath(t *testing.T, containerID string) string {
	// 尝试多种可能的内存cgroup路径
	possiblePaths := []string{
		"/sys/fs/cgroup/memory",
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup",
	}
	
	for _, path := range possiblePaths {
		if fileExists(t, containerID, path) {
			if fileExists(t, containerID, filepath.Join(path, "memory.limit_in_bytes")) ||
			   fileExists(t, containerID, filepath.Join(path, "memory.max")) {
				return path
			}
		}
	}
	
	return ""
}

func findCPUCgroupPath(t *testing.T, containerID string) string {
	possiblePaths := []string{
		"/sys/fs/cgroup/cpu",
		"/sys/fs/cgroup/cpu.max",
		"/sys/fs/cgroup",
	}
	
	for _, path := range possiblePaths {
		if fileExists(t, containerID, path) {
			if fileExists(t, containerID, filepath.Join(path, "cpu.cfs_quota_us")) ||
			   fileExists(t, containerID, filepath.Join(path, "cpu.max")) {
				return path
			}
		}
	}
	
	return ""
}

func findPIDCgroupPath(t *testing.T, containerID string) string {
	possiblePaths := []string{
		"/sys/fs/cgroup/pids",
		"/sys/fs/cgroup/pids.max",
		"/sys/fs/cgroup",
	}
	
	for _, path := range possiblePaths {
		if fileExists(t, containerID, path) {
			if fileExists(t, containerID, filepath.Join(path, "pids.max")) {
				return path
			}
		}
	}
	
	return ""
}

func findDeviceCgroupPath(t *testing.T, containerID string) string {
	possiblePaths := []string{
		"/sys/fs/cgroup/devices",
		"/sys/fs/cgroup",
	}
	
	for _, path := range possiblePaths {
		if fileExists(t, containerID, path) {
			if fileExists(t, containerID, filepath.Join(path, "devices.list")) {
				return path
			}
		}
	}
	
	return ""
}

func findNetworkCgroupPath(t *testing.T, containerID string) string {
	possiblePaths := []string{
		"/sys/fs/cgroup/net_cls",
		"/sys/fs/cgroup/net_prio",
		"/sys/fs/cgroup",
	}
	
	for _, path := range possiblePaths {
		if fileExists(t, containerID, path) {
			if fileExists(t, containerID, filepath.Join(path, "net_cls.classid")) ||
			   fileExists(t, containerID, filepath.Join(path, "net_prio.ifpriomap")) {
				return path
			}
		}
	}
	
	return ""
}

func detectCgroupVersion(t *testing.T, containerID string) string {
	// 检查cgroup v2统一层次结构
	if fileExists(t, containerID, "/sys/fs/cgroup/cgroup.controllers") {
		return "v2"
	}
	
	// 检查cgroup v1层次结构
	if fileExists(t, containerID, "/sys/fs/cgroup/memory/memory.limit_in_bytes") {
		return "v1"
	}
	
	// 检查混合模式
	cgroupInfo := execInContainer(t, containerID, "mount", "|", "grep", "cgroup")
	if strings.Contains(cgroupInfo, "cgroup2") && strings.Contains(cgroupInfo, "cgroup") {
		return "hybrid"
	}
	
	return "unknown"
}

func parseMemoryStats(statContent string) map[string]int64 {
	stats := make(map[string]int64)
	lines := strings.Split(statContent, "\n")
	
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := parts[0]
			value, err := strconv.ParseInt(parts[1], 10, 64)
			if err == nil {
				stats[key] = value
			}
		}
	}
	
	return stats
}

func collectResourceMetrics(t *testing.T, containerID string) ResourceMetrics {
	metrics := ResourceMetrics{}
	
	// 收集内存使用
	memPath := findMemoryCgroupPath(t, containerID)
	if memPath != "" {
		memUsageFile := filepath.Join(memPath, "memory.usage_in_bytes")
		if fileExists(t, containerID, memUsageFile) {
			memUsage := execInContainer(t, containerID, "cat", memUsageFile)
			metrics.MemoryUsage = parseBytes(t, strings.TrimSpace(memUsage))
		}
	}
	
	// 收集CPU使用
	cpuPath := findCPUCgroupPath(t, containerID)
	if cpuPath != "" {
		cpuUsageFile := filepath.Join(cpuPath, "cpuacct.usage")
		if fileExists(t, containerID, cpuUsageFile) {
			cpuUsage := execInContainer(t, containerID, "cat", cpuUsageFile)
			usage, err := strconv.ParseInt(strings.TrimSpace(cpuUsage), 10, 64)
			if err == nil {
				metrics.CPUUsage = usage
			}
		}
	}
	
	// 收集PID数量
	pidPath := findPIDCgroupPath(t, containerID)
	if pidPath != "" {
		pidCurrentFile := filepath.Join(pidPath, "pids.current")
		if fileExists(t, containerID, pidCurrentFile) {
			pidCurrent := execInContainer(t, containerID, "cat", pidCurrentFile)
			count, err := strconv.Atoi(strings.TrimSpace(pidCurrent))
			if err == nil {
				metrics.PIDCount = count
			}
		}
	}
	
	return metrics
}
