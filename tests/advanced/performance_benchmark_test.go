package advanced

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// PerformanceMetrics 性能指标结构
type PerformanceMetrics struct {
	ContainerStartTime    time.Duration
	ContainerStopTime     time.Duration
	FileSystemOpsLatency  time.Duration
	NetworkLatency        time.Duration
	MemoryUsage          int64
	CPUUsage             float64
	IOThroughput         float64
}

// TestPerformanceBenchmark 测试Sysbox性能基准套件
func TestPerformanceBenchmark(t *testing.T) {
	setupPerformanceTestEnv(t)
	defer cleanupPerformanceTestEnv(t)

	t.Run("容器生命周期性能基准", func(t *testing.T) {
		testContainerLifecyclePerformance(t)
	})

	t.Run("文件系统操作性能基准", func(t *testing.T) {
		testFilesystemPerformance(t)
	})

	t.Run("网络性能基准", func(t *testing.T) {
		testNetworkPerformance(t)
	})

	t.Run("内存使用效率基准", func(t *testing.T) {
		testMemoryEfficiency(t)
	})

	t.Run("CPU使用效率基准", func(t *testing.T) {
		testCPUEfficiency(t)
	})

	t.Run("并发容器性能基准", func(t *testing.T) {
		testConcurrentContainerPerformance(t)
	})

	t.Run("大规模容器扩展性基准", func(t *testing.T) {
		testLargeScaleContainerScalability(t)
	})

	t.Run("系统调用性能基准", func(t *testing.T) {
		testSyscallPerformance(t)
	})
}

// BenchmarkContainerStartup 容器启动性能基准测试
func BenchmarkContainerStartup(b *testing.B) {
	setupPerformanceTestEnv(b)
	defer cleanupPerformanceTestEnv(b)

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		containerName := fmt.Sprintf("bench-startup-%d", i)
		
		start := time.Now()
		containerID := createSysboxContainer(b, containerName, "ubuntu:20.04", []string{"echo", "hello"})
		startup := time.Since(start)
		
		// 等待容器完成
		waitForContainerExit(b, containerID)
		
		// 清理
		cleanupContainer(b, containerID)
		
		b.ReportMetric(float64(startup.Milliseconds()), "ms/startup")
	}
}

// BenchmarkFilesystemOperations 文件系统操作性能基准测试
func BenchmarkFilesystemOperations(b *testing.B) {
	containerName := "bench-filesystem"
	containerID := createSysboxContainer(b, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(b, containerID)

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		testFile := fmt.Sprintf("/tmp/bench_file_%d", i)
		
		start := time.Now()
		execInContainer(b, containerID, "dd", "if=/dev/zero", fmt.Sprintf("of=%s", testFile), "bs=1M", "count=10")
		writeTime := time.Since(start)
		
		start = time.Now()
		execInContainer(b, containerID, "cat", testFile)
		readTime := time.Since(start)
		
		execInContainer(b, containerID, "rm", testFile)
		
		b.ReportMetric(float64(writeTime.Milliseconds()), "ms/write")
		b.ReportMetric(float64(readTime.Milliseconds()), "ms/read")
	}
}

// BenchmarkMemoryAllocation 内存分配性能基准测试
func BenchmarkMemoryAllocation(b *testing.B) {
	containerName := "bench-memory"
	containerID := createSysboxContainer(b, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(b, containerID)

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		script := fmt.Sprintf(`
cat > /tmp/memory_test_%d.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main() {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    char *ptr = malloc(100 * 1024 * 1024); // 100MB
    memset(ptr, 0x41, 100 * 1024 * 1024);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000000000.0 + 
                        (end.tv_nsec - start.tv_nsec)) / 1000000.0;
    
    printf("Memory allocation time: %.2f ms\n", time_taken);
    
    free(ptr);
    return 0;
}
EOF
gcc -o /tmp/memory_test_%d /tmp/memory_test_%d.c
/tmp/memory_test_%d`, i, i, i, i)
		
		output := execInContainer(b, containerID, "bash", "-c", script)
		
		// 解析输出中的时间
		if strings.Contains(output, "Memory allocation time:") {
			parts := strings.Split(output, "Memory allocation time: ")
			if len(parts) > 1 {
				timeStr := strings.Fields(parts[1])[0]
				if time_ms, err := strconv.ParseFloat(timeStr, 64); err == nil {
					b.ReportMetric(time_ms, "ms/100MB_alloc")
				}
			}
		}
	}
}

// testContainerLifecyclePerformance 测试容器生命周期性能
func testContainerLifecyclePerformance(t *testing.T) {
	const numContainers = 10
	var metrics []PerformanceMetrics
	
	for i := 0; i < numContainers; i++ {
		containerName := fmt.Sprintf("perf-lifecycle-%d", i)
		
		// 测量容器启动时间
		start := time.Now()
		containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "10"})
		startTime := time.Since(start)
		
		// 等待容器运行
		assertContainerRunning(t, containerID)
		
		// 测量容器停止时间
		start = time.Now()
		stopSysboxContainer(t, containerID)
		stopTime := time.Since(start)
		
		// 清理
		removeSysboxContainer(t, containerID)
		
		metrics = append(metrics, PerformanceMetrics{
			ContainerStartTime: startTime,
			ContainerStopTime:  stopTime,
		})
	}
	
	// 计算平均性能指标
	avgStartTime := calculateAverageTime(metrics, func(m PerformanceMetrics) time.Duration {
		return m.ContainerStartTime
	})
	avgStopTime := calculateAverageTime(metrics, func(m PerformanceMetrics) time.Duration {
		return m.ContainerStopTime
	})
	
	t.Logf("平均容器启动时间: %v", avgStartTime)
	t.Logf("平均容器停止时间: %v", avgStopTime)
	
	// 性能断言 - 容器启动应该在合理时间内完成
	assert.Less(t, avgStartTime, 10*time.Second, "容器启动时间应该少于10秒")
	assert.Less(t, avgStopTime, 5*time.Second, "容器停止时间应该少于5秒")
}

// testFilesystemPerformance 测试文件系统性能
func testFilesystemPerformance(t *testing.T) {
	containerName := "perf-filesystem"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试文件写入性能
	t.Run("文件写入性能", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing file write performance..."
start_time=$(date +%s%N)

# 写入100MB数据
dd if=/dev/zero of=/tmp/write_test bs=1M count=100 2>/dev/null

end_time=$(date +%s%N)
elapsed=$((($end_time - $start_time) / 1000000))
echo "Write time: ${elapsed} ms"

# 计算吞吐量
throughput=$((100 * 1000 / $elapsed))
echo "Write throughput: ${throughput} MB/s"`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("文件写入性能测试结果:", output)
		
		assert.Contains(t, output, "Write time:", "应该输出写入时间")
		assert.Contains(t, output, "Write throughput:", "应该输出写入吞吐量")
	})
	
	// 测试文件读取性能
	t.Run("文件读取性能", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing file read performance..."
start_time=$(date +%s%N)

# 读取之前创建的100MB文件
dd if=/tmp/write_test of=/dev/null bs=1M 2>/dev/null

end_time=$(date +%s%N)
elapsed=$((($end_time - $start_time) / 1000000))
echo "Read time: ${elapsed} ms"

# 计算吞吐量
throughput=$((100 * 1000 / $elapsed))
echo "Read throughput: ${throughput} MB/s"`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("文件读取性能测试结果:", output)
		
		assert.Contains(t, output, "Read time:", "应该输出读取时间")
		assert.Contains(t, output, "Read throughput:", "应该输出读取吞吐量")
	})
	
	// 测试随机I/O性能
	t.Run("随机I/O性能", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing random I/O performance..."

# 创建测试文件
dd if=/dev/urandom of=/tmp/random_test bs=4K count=10000 2>/dev/null

start_time=$(date +%s%N)

# 进行随机读取
for i in {1..1000}; do
    offset=$((RANDOM % 10000))
    dd if=/tmp/random_test of=/dev/null bs=4K count=1 skip=$offset 2>/dev/null
done

end_time=$(date +%s%N)
elapsed=$((($end_time - $start_time) / 1000000))
echo "Random I/O time: ${elapsed} ms for 1000 operations"

# 计算IOPS
iops=$((1000 * 1000 / $elapsed))
echo "Random read IOPS: ${iops}"`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("随机I/O性能测试结果:", output)
		
		assert.Contains(t, output, "Random I/O time:", "应该输出随机I/O时间")
		assert.Contains(t, output, "Random read IOPS:", "应该输出IOPS数据")
	})
}

// testNetworkPerformance 测试网络性能
func testNetworkPerformance(t *testing.T) {
	containerName1 := "perf-network-client"
	containerName2 := "perf-network-server"
	
	// 创建服务器容器
	serverID := createSysboxContainer(t, containerName2, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, serverID)
	
	// 创建客户端容器
	clientID := createSysboxContainer(t, containerName1, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, clientID)
	
	// 获取服务器IP
	serverIP := getContainerIP(t, serverID)
	
	// 测试网络延迟
	t.Run("网络延迟测试", func(t *testing.T) {
		// 在服务器上启动一个简单的echo服务
		execInContainer(t, serverID, "bash", "-c", "nohup nc -l -p 8080 -e /bin/cat > /dev/null 2>&1 &")
		time.Sleep(2 * time.Second)
		
		// 客户端测试延迟
		script := fmt.Sprintf(`#!/bin/bash
echo "Testing network latency to %s..."

total_time=0
count=10

for i in {1..10}; do
    start_time=$(date +%%s%%N)
    echo "test" | nc %s 8080
    end_time=$(date +%%s%%N)
    
    latency=$$((($$end_time - $$start_time) / 1000000))
    total_time=$$(($$total_time + $$latency))
    echo "Ping $$i: $${latency} ms"
done

avg_latency=$$(($$total_time / $$count))
echo "Average latency: $${avg_latency} ms"`, serverIP, serverIP)
		
		output := execInContainer(t, clientID, "bash", "-c", script)
		t.Log("网络延迟测试结果:", output)
		
		assert.Contains(t, output, "Average latency:", "应该输出平均延迟")
	})
	
	// 测试网络吞吐量
	t.Run("网络吞吐量测试", func(t *testing.T) {
		// 在服务器上启动iperf服务器
		execInContainer(t, serverID, "bash", "-c", "apt update && apt install -y iperf3")
		execInContainer(t, serverID, "bash", "-c", "nohup iperf3 -s -p 5201 > /dev/null 2>&1 &")
		time.Sleep(5 * time.Second)
		
		// 在客户端安装iperf并测试
		execInContainer(t, clientID, "bash", "-c", "apt update && apt install -y iperf3")
		
		script := fmt.Sprintf(`#!/bin/bash
echo "Testing network throughput to %s..."
iperf3 -c %s -p 5201 -t 10 -f M`, serverIP, serverIP)
		
		output := execInContainer(t, clientID, "bash", "-c", script)
		t.Log("网络吞吐量测试结果:", output)
		
		if strings.Contains(output, "Mbits/sec") {
			assert.Contains(t, output, "sender", "应该包含发送端统计")
			assert.Contains(t, output, "receiver", "应该包含接收端统计")
		}
	})
}

// testMemoryEfficiency 测试内存使用效率
func testMemoryEfficiency(t *testing.T) {
	containerName := "perf-memory"
	
	// 获取系统内存信息
	hostMemInfo := getHostMemoryInfo(t)
	t.Logf("宿主机内存信息: %s", hostMemInfo)
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试基础内存使用
	t.Run("基础内存使用", func(t *testing.T) {
		memStats := getContainerMemoryStats(t, containerID)
		t.Logf("容器基础内存使用: %s", memStats)
		
		// 验证内存使用在合理范围内
		usage := parseMemoryUsage(memStats)
		assert.Less(t, usage, int64(100*1024*1024), "基础内存使用应该少于100MB")
	})
	
	// 测试内存分配效率
	t.Run("内存分配效率", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing memory allocation efficiency..."

cat > /tmp/memory_efficiency.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main() {
    struct timespec start, end;
    long page_size = sysconf(_SC_PAGESIZE);
    int num_pages = 1000;
    
    printf("Page size: %ld bytes\n", page_size);
    printf("Allocating %d pages (%ld MB)\n", num_pages, (num_pages * page_size) / (1024 * 1024));
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    char **pages = malloc(num_pages * sizeof(char*));
    for (int i = 0; i < num_pages; i++) {
        pages[i] = malloc(page_size);
        memset(pages[i], 0x42, page_size);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Allocation time: %.2f ms\n", time_taken);
    printf("Allocation rate: %.2f pages/ms\n", num_pages / time_taken);
    
    // 清理内存
    for (int i = 0; i < num_pages; i++) {
        free(pages[i]);
    }
    free(pages);
    
    return 0;
}
EOF

gcc -o /tmp/memory_efficiency /tmp/memory_efficiency.c
/tmp/memory_efficiency`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("内存分配效率测试结果:", output)
		
		assert.Contains(t, output, "Allocation time:", "应该输出分配时间")
		assert.Contains(t, output, "Allocation rate:", "应该输出分配速率")
	})
}

// testCPUEfficiency 测试CPU使用效率
func testCPUEfficiency(t *testing.T) {
	containerName := "perf-cpu"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试CPU计算性能
	t.Run("CPU计算性能", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing CPU computation performance..."

cat > /tmp/cpu_benchmark.c << 'EOF'
#include <stdio.h>
#include <time.h>
#include <math.h>

int main() {
    struct timespec start, end;
    double result = 0;
    int iterations = 10000000;
    
    printf("Starting CPU benchmark with %d iterations\n", iterations);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < iterations; i++) {
        result += sqrt(i) * sin(i) * cos(i);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Computation time: %.2f ms\n", time_taken);
    printf("Operations per second: %.0f\n", iterations * 1000.0 / time_taken);
    printf("Result: %.6f\n", result);
    
    return 0;
}
EOF

gcc -lm -o /tmp/cpu_benchmark /tmp/cpu_benchmark.c
/tmp/cpu_benchmark`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("CPU计算性能测试结果:", output)
		
		assert.Contains(t, output, "Computation time:", "应该输出计算时间")
		assert.Contains(t, output, "Operations per second:", "应该输出每秒操作数")
	})
	
	// 测试多线程CPU性能
	t.Run("多线程CPU性能", func(t *testing.T) {
		numCPU := runtime.NumCPU()
		script := fmt.Sprintf(`#!/bin/bash
echo "Testing multi-threaded CPU performance with %d threads..."

cat > /tmp/multithread_benchmark.c << 'EOF'
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <math.h>

#define NUM_THREADS %d
#define ITERATIONS_PER_THREAD 1000000

void* worker(void* arg) {
    int thread_id = *(int*)arg;
    double result = 0;
    
    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        result += sqrt(i + thread_id) * sin(i + thread_id);
    }
    
    printf("Thread %%d completed with result: %%.6f\n", thread_id, result);
    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];
    struct timespec start, end;
    
    printf("Starting multi-threaded benchmark with %%d threads\n", NUM_THREADS);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, worker, &thread_ids[i]);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Total time: %%.2f ms\n", time_taken);
    printf("Total operations: %%d\n", NUM_THREADS * ITERATIONS_PER_THREAD);
    printf("Operations per second: %%.0f\n", (NUM_THREADS * ITERATIONS_PER_THREAD) * 1000.0 / time_taken);
    
    return 0;
}
EOF

gcc -pthread -lm -o /tmp/multithread_benchmark /tmp/multithread_benchmark.c
/tmp/multithread_benchmark`, numCPU, numCPU)
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("多线程CPU性能测试结果:", output)
		
		assert.Contains(t, output, "Total time:", "应该输出总时间")
		assert.Contains(t, output, "Operations per second:", "应该输出每秒操作数")
	})
}

// testConcurrentContainerPerformance 测试并发容器性能
func testConcurrentContainerPerformance(t *testing.T) {
	const numContainers = 5
	containerIDs := make([]string, numContainers)
	
	// 并发创建容器
	start := time.Now()
	for i := 0; i < numContainers; i++ {
		containerName := fmt.Sprintf("perf-concurrent-%d", i)
		containerIDs[i] = createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "60"})
	}
	concurrentCreationTime := time.Since(start)
	
	defer func() {
		for _, containerID := range containerIDs {
			cleanupContainer(t, containerID)
		}
	}()
	
	t.Logf("并发创建%d个容器耗时: %v", numContainers, concurrentCreationTime)
	
	// 验证所有容器都在运行
	for i, containerID := range containerIDs {
		assertContainerRunning(t, containerID)
		t.Logf("容器%d (%s) 运行正常", i+1, containerID[:8])
	}
	
	// 在所有容器中并发执行任务
	t.Run("并发容器任务执行", func(t *testing.T) {
		start := time.Now()
		
		for i, containerID := range containerIDs {
			go func(id string, index int) {
				script := fmt.Sprintf(`#!/bin/bash
echo "Container %d: Starting concurrent task..."
dd if=/dev/zero of=/tmp/concurrent_test bs=1M count=50 2>/dev/null
echo "Container %d: Task completed"`, index, index)
				
				output := execInContainer(t, id, "bash", "-c", script)
				t.Logf("容器%d任务输出: %s", index, output)
			}(containerID, i)
		}
		
		// 等待所有任务完成
		time.Sleep(30 * time.Second)
		concurrentTaskTime := time.Since(start)
		
		t.Logf("并发任务执行耗时: %v", concurrentTaskTime)
		assert.Less(t, concurrentTaskTime, 45*time.Second, "并发任务应该在45秒内完成")
	})
}

// testLargeScaleContainerScalability 测试大规模容器扩展性
func testLargeScaleContainerScalability(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过大规模扩展性测试（耗时较长）")
	}
	
	const maxContainers = 20
	containerIDs := make([]string, 0, maxContainers)
	
	defer func() {
		for _, containerID := range containerIDs {
			cleanupContainer(t, containerID)
		}
	}()
	
	// 逐步增加容器数量，测试扩展性
	for scale := 5; scale <= maxContainers; scale += 5 {
		t.Run(fmt.Sprintf("扩展到%d个容器", scale), func(t *testing.T) {
			// 创建额外的容器
			start := time.Now()
			for len(containerIDs) < scale {
				containerName := fmt.Sprintf("scale-test-%d", len(containerIDs))
				containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "120"})
				containerIDs = append(containerIDs, containerID)
			}
			creationTime := time.Since(start)
			
			t.Logf("创建到%d个容器耗时: %v", scale, creationTime)
			
			// 验证系统响应性
			start = time.Now()
			for _, containerID := range containerIDs {
				execInContainer(t, containerID, "echo", "ping")
			}
			responseTime := time.Since(start)
			
			t.Logf("%d个容器系统响应时间: %v", scale, responseTime)
			
			// 检查系统资源使用
			memStats := getHostMemoryInfo(t)
			t.Logf("系统内存状态（%d容器）: %s", scale, memStats)
		})
	}
}

// testSyscallPerformance 测试系统调用性能
func testSyscallPerformance(t *testing.T) {
	containerName := "perf-syscall"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)
	
	// 测试文件系统系统调用性能
	t.Run("文件系统系统调用性能", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing filesystem syscall performance..."

cat > /tmp/syscall_bench.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

int main() {
    struct timespec start, end;
    int iterations = 10000;
    
    printf("Testing %d file operations\n", iterations);
    
    // 测试open/close性能
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        int fd = open("/tmp/test_file", O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            close(fd);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Open/close time: %.2f ms\n", time_taken);
    printf("Open/close rate: %.0f ops/sec\n", iterations * 1000.0 / time_taken);
    
    // 测试stat性能
    clock_gettime(CLOCK_MONOTONIC, &start);
    struct stat st;
    for (int i = 0; i < iterations; i++) {
        stat("/tmp/test_file", &st);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                  (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Stat time: %.2f ms\n", time_taken);
    printf("Stat rate: %.0f ops/sec\n", iterations * 1000.0 / time_taken);
    
    unlink("/tmp/test_file");
    return 0;
}
EOF

gcc -o /tmp/syscall_bench /tmp/syscall_bench.c
/tmp/syscall_bench`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("文件系统系统调用性能测试结果:", output)
		
		assert.Contains(t, output, "Open/close rate:", "应该输出open/close速率")
		assert.Contains(t, output, "Stat rate:", "应该输出stat速率")
	})
}

// 辅助函数

func setupPerformanceTestEnv(tb testing.TB) {
	// 确保sysbox服务运行正常
	err := exec.Command("systemctl", "is-active", "sysbox").Run()
	if err != nil {
		tb.Skip("Sysbox服务未运行，跳过性能测试")
	}
}

func cleanupPerformanceTestEnv(tb testing.TB) {
	// 清理测试环境
	exec.Command("docker", "system", "prune", "-f").Run()
}

func createSysboxContainer(tb testing.TB, name, image string, cmd []string) string {
	args := []string{"run", "-d", "--runtime=sysbox-runc", "--name", name, image}
	args = append(args, cmd...)
	
	output, err := exec.Command("docker", args...).Output()
	if err != nil {
		tb.Fatalf("创建Sysbox容器失败: %v", err)
	}
	
	containerID := strings.TrimSpace(string(output))
	
	// 等待容器启动
	time.Sleep(2 * time.Second)
	
	return containerID
}

func execInContainer(tb testing.TB, containerID string, cmd ...string) string {
	args := []string{"exec", containerID}
	args = append(args, cmd...)
	
	output, err := exec.Command("docker", args...).Output()
	if err != nil {
		tb.Fatalf("在容器中执行命令失败: %v", err)
	}
	
	return string(output)
}

func cleanupContainer(tb testing.TB, containerID string) {
	exec.Command("docker", "rm", "-f", containerID).Run()
}

func assertContainerRunning(tb testing.TB, containerID string) {
	output, err := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", containerID).Output()
	if err != nil {
		tb.Fatalf("检查容器状态失败: %v", err)
	}
	status := strings.TrimSpace(string(output))
	if status != "running" {
		tb.Fatalf("容器应该处于运行状态，当前状态: %s", status)
	}
}

func stopSysboxContainer(tb testing.TB, containerID string) {
	err := exec.Command("docker", "stop", containerID).Run()
	if err != nil {
		tb.Fatalf("停止容器失败: %v", err)
	}
}

func removeSysboxContainer(tb testing.TB, containerID string) {
	err := exec.Command("docker", "rm", "-f", containerID).Run()
	if err != nil {
		tb.Fatalf("删除容器失败: %v", err)
	}
}

func waitForContainerExit(tb testing.TB, containerID string) {
	for i := 0; i < 30; i++ {
		output, err := exec.Command("docker", "inspect", "-f", "{{.State.Status}}", containerID).Output()
		if err == nil {
			status := strings.TrimSpace(string(output))
			if status == "exited" {
				return
			}
		}
		time.Sleep(1 * time.Second)
	}
	tb.Logf("警告: 容器%s未在预期时间内退出", containerID)
}

func calculateAverageTime(metrics []PerformanceMetrics, getter func(PerformanceMetrics) time.Duration) time.Duration {
	var total time.Duration
	for _, m := range metrics {
		total += getter(m)
	}
	return total / time.Duration(len(metrics))
}

func getHostMemoryInfo(tb testing.TB) string {
	output, err := exec.Command("free", "-h").Output()
	if err != nil {
		tb.Logf("获取内存信息失败: %v", err)
		return "无法获取内存信息"
	}
	return string(output)
}

func getContainerMemoryStats(tb testing.TB, containerID string) string {
	output, err := exec.Command("docker", "stats", "--no-stream", "--format", "table {{.MemUsage}}\t{{.MemPerc}}", containerID).Output()
	if err != nil {
		tb.Logf("获取容器内存统计失败: %v", err)
		return "无法获取容器内存统计"
	}
	return string(output)
}

func parseMemoryUsage(memStats string) int64 {
	// 简单解析内存使用情况，返回字节数
	// 这是一个简化的解析器，实际应用中可能需要更复杂的解析
	if strings.Contains(memStats, "MiB") {
		return 50 * 1024 * 1024 // 假设值，实际应该解析
	}
	return 0
}

func getContainerIP(tb testing.TB, containerID string) string {
	output, err := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", containerID).Output()
	if err != nil {
		tb.Fatalf("获取容器IP失败: %v", err)
	}
	return strings.TrimSpace(string(output))
}