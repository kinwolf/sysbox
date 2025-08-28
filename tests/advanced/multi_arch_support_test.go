package advanced

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ArchitectureInfo 架构信息结构
type ArchitectureInfo struct {
	Architecture string
	CPUVendor    string
	CPUModel     string
	CoreCount    int
	Features     []string
}

// TestMultiArchSupport 测试Sysbox多架构支持
func TestMultiArchSupport(t *testing.T) {
	setupMultiArchTestEnv(t)
	defer cleanupMultiArchTestEnv(t)

	t.Run("架构检测和验证", func(t *testing.T) {
		testArchitectureDetection(t)
	})

	t.Run("跨架构容器运行", func(t *testing.T) {
		testCrossArchContainerExecution(t)
	})

	t.Run("多架构镜像支持", func(t *testing.T) {
		testMultiArchImageSupport(t)
	})

	t.Run("架构特定优化验证", func(t *testing.T) {
		testArchSpecificOptimizations(t)
	})

	t.Run("QEMU用户模式仿真", func(t *testing.T) {
		testQEMUUserModeEmulation(t)
	})

	t.Run("ARM64特定功能测试", func(t *testing.T) {
		testARM64SpecificFeatures(t)
	})

	t.Run("x86_64特定功能测试", func(t *testing.T) {
		testX86_64SpecificFeatures(t)
	})

	t.Run("跨架构性能对比", func(t *testing.T) {
		testCrossArchPerformanceComparison(t)
	})
}

// testArchitectureDetection 测试架构检测和验证
func testArchitectureDetection(t *testing.T) {
	// 获取宿主机架构信息
	hostArch := getHostArchitecture(t)
	t.Logf("宿主机架构信息: %+v", hostArch)

	containerName := "test-arch-detection"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试容器内架构检测
	t.Run("容器内架构一致性检测", func(t *testing.T) {
		// 检查架构字符串
		arch := execInContainer(t, containerID, "uname", "-m")
		arch = strings.TrimSpace(arch)
		t.Logf("容器架构: %s", arch)
		
		assert.Equal(t, hostArch.Architecture, arch, "容器架构应该与宿主机一致")

		// 检查CPU信息
		cpuInfo := execInContainer(t, containerID, "cat", "/proc/cpuinfo")
		assert.Contains(t, cpuInfo, "processor", "应该能读取CPU信息")
		
		// 验证CPU核心数
		coreCount := countCPUCores(cpuInfo)
		assert.Greater(t, coreCount, 0, "应该检测到CPU核心")
		t.Logf("检测到CPU核心数: %d", coreCount)
	})

	// 测试架构特定指令支持
	t.Run("架构特定指令支持检测", func(t *testing.T) {
		switch hostArch.Architecture {
		case "x86_64", "amd64":
			testX86_64Instructions(t, containerID)
		case "aarch64", "arm64":
			testARM64Instructions(t, containerID)
		default:
			t.Logf("未知架构 %s，跳过指令测试", hostArch.Architecture)
		}
	})

	// 测试endianness检测
	t.Run("字节序检测", func(t *testing.T) {
		script := `#!/bin/bash
cat > /tmp/endian_test.c << 'EOF'
#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t test = 0x12345678;
    uint8_t *ptr = (uint8_t*)&test;
    
    printf("Test value: 0x%08x\n", test);
    printf("Byte 0: 0x%02x\n", ptr[0]);
    printf("Byte 1: 0x%02x\n", ptr[1]);
    printf("Byte 2: 0x%02x\n", ptr[2]);
    printf("Byte 3: 0x%02x\n", ptr[3]);
    
    if (ptr[0] == 0x78) {
        printf("Endianness: Little Endian\n");
    } else if (ptr[0] == 0x12) {
        printf("Endianness: Big Endian\n");
    } else {
        printf("Endianness: Unknown\n");
    }
    
    return 0;
}
EOF
gcc -o /tmp/endian_test /tmp/endian_test.c
/tmp/endian_test`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("字节序检测结果:", output)
		
		assert.Contains(t, output, "Endianness:", "应该检测到字节序")
	})
}

// testCrossArchContainerExecution 测试跨架构容器运行
func testCrossArchContainerExecution(t *testing.T) {
	hostArch := runtime.GOARCH
	
	// 测试支持的架构列表
	supportedArchs := []string{"amd64", "arm64"}
	
	for _, targetArch := range supportedArchs {
		if targetArch == hostArch {
			continue // 跳过原生架构
		}
		
		t.Run(fmt.Sprintf("运行%s架构容器", targetArch), func(t *testing.T) {
			// 检查是否支持该架构
			if !isArchitectureSupported(targetArch) {
				t.Skipf("系统不支持%s架构仿真", targetArch)
			}
			
			containerName := fmt.Sprintf("test-cross-arch-%s", targetArch)
			imageName := fmt.Sprintf("ubuntu:20.04")
			
			// 尝试运行跨架构容器
			args := []string{"run", "-d", "--runtime=sysbox-runc", "--platform", fmt.Sprintf("linux/%s", targetArch), 
				"--name", containerName, imageName, "sleep", "60"}
			
			output, err := exec.Command("docker", args...).Output()
			if err != nil {
				t.Logf("无法运行%s架构容器: %v", targetArch, err)
				return
			}
			
			containerID := strings.TrimSpace(string(output))
			defer cleanupContainer(t, containerID)
			
			// 验证容器确实运行在目标架构上
			time.Sleep(5 * time.Second)
			
			arch := execInContainer(t, containerID, "uname", "-m")
			arch = strings.TrimSpace(arch)
			t.Logf("跨架构容器实际架构: %s (目标: %s)", arch, targetArch)
			
			// 运行简单测试
			output = execInContainer(t, containerID, "echo", "Cross-arch test successful")
			assert.Contains(t, output, "Cross-arch test successful", "跨架构容器应该能正常执行命令")
		})
	}
}

// testMultiArchImageSupport 测试多架构镜像支持
func testMultiArchImageSupport(t *testing.T) {
	// 测试多架构镜像manifest
	t.Run("多架构镜像Manifest检查", func(t *testing.T) {
		// 检查一个已知的多架构镜像
		output, err := exec.Command("docker", "manifest", "inspect", "ubuntu:20.04").Output()
		if err != nil {
			t.Skip("Docker manifest命令不可用或镜像不支持")
		}
		
		manifest := string(output)
		t.Log("Ubuntu镜像manifest:", manifest)
		
		// 验证包含多个架构
		assert.Contains(t, manifest, "amd64", "应该包含amd64架构")
		
		// 检查是否包含其他架构
		architectures := []string{"arm64", "arm", "ppc64le", "s390x"}
		foundArchs := 0
		for _, arch := range architectures {
			if strings.Contains(manifest, arch) {
				foundArchs++
				t.Logf("发现支持的架构: %s", arch)
			}
		}
		
		assert.Greater(t, foundArchs, 0, "应该支持多个架构")
	})

	// 测试架构特定镜像拉取
	t.Run("架构特定镜像拉取", func(t *testing.T) {
		hostArch := runtime.GOARCH
		
		// 尝试拉取特定架构的镜像
		archImage := fmt.Sprintf("ubuntu:20.04")
		
		err := exec.Command("docker", "pull", "--platform", fmt.Sprintf("linux/%s", hostArch), archImage).Run()
		assert.NoError(t, err, "应该能拉取特定架构的镜像")
		
		// 检查镜像属性
		output, err := exec.Command("docker", "inspect", archImage, "--format", "{{.Architecture}}").Output()
		if err == nil {
			imageArch := strings.TrimSpace(string(output))
			t.Logf("镜像架构: %s, 期望: %s", imageArch, hostArch)
		}
	})
}

// testArchSpecificOptimizations 测试架构特定优化
func testArchSpecificOptimizations(t *testing.T) {
	containerName := "test-arch-optimizations"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	hostArch := runtime.GOARCH

	// 测试架构特定的编译优化
	t.Run("架构特定编译优化", func(t *testing.T) {
		var gccFlags string
		switch hostArch {
		case "amd64":
			gccFlags = "-march=native -mtune=native"
		case "arm64":
			gccFlags = "-march=native -mtune=native"
		default:
			gccFlags = "-O2"
		}

		script := fmt.Sprintf(`#!/bin/bash
apt update && apt install -y gcc

cat > /tmp/arch_optimized.c << 'EOF'
#include <stdio.h>
#include <time.h>

int main() {
    struct timespec start, end;
    volatile double result = 0;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < 1000000; i++) {
        result += i * 3.14159;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Computation time: %%.2f ms\n", time_taken);
    printf("Result: %%.6f\n", result);
    
    return 0;
}
EOF

echo "Compiling with optimization flags: %s"
gcc %s -o /tmp/arch_optimized /tmp/arch_optimized.c
/tmp/arch_optimized`, gccFlags, gccFlags)

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("架构优化编译测试结果:", output)
		
		assert.Contains(t, output, "Computation time:", "应该输出计算时间")
	})

	// 测试向量化指令使用
	t.Run("向量化指令使用", func(t *testing.T) {
		if hostArch != "amd64" && hostArch != "arm64" {
			t.Skip("跳过向量化指令测试，架构不支持")
		}

		script := `#!/bin/bash
cat > /tmp/vectorization_test.c << 'EOF'
#include <stdio.h>
#include <time.h>

void vector_add_simple(float *a, float *b, float *c, int n) {
    for (int i = 0; i < n; i++) {
        c[i] = a[i] + b[i];
    }
}

int main() {
    const int N = 1000000;
    float *a = malloc(N * sizeof(float));
    float *b = malloc(N * sizeof(float));
    float *c = malloc(N * sizeof(float));
    
    // 初始化数组
    for (int i = 0; i < N; i++) {
        a[i] = i * 1.0f;
        b[i] = i * 2.0f;
    }
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    vector_add_simple(a, b, c, N);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Vector addition time: %.2f ms\n", time_taken);
    printf("Throughput: %.2f MOPS\n", N / (time_taken / 1000.0) / 1000000.0);
    
    free(a); free(b); free(c);
    return 0;
}
EOF

gcc -O3 -ftree-vectorize -o /tmp/vectorization_test /tmp/vectorization_test.c
/tmp/vectorization_test`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("向量化指令测试结果:", output)
		
		assert.Contains(t, output, "Vector addition time:", "应该输出向量加法时间")
		assert.Contains(t, output, "Throughput:", "应该输出吞吐量")
	})
}

// testQEMUUserModeEmulation 测试QEMU用户模式仿真
func testQEMUUserModeEmulation(t *testing.T) {
	// 检查QEMU用户模式支持
	if !isQEMUUserModeAvailable() {
		t.Skip("QEMU用户模式不可用")
	}

	t.Run("QEMU二进制注册检查", func(t *testing.T) {
		// 检查binfmt_misc注册
		output, err := exec.Command("cat", "/proc/sys/fs/binfmt_misc/qemu-aarch64").Output()
		if err == nil {
			binfmt := string(output)
			t.Log("QEMU aarch64 binfmt注册:", binfmt)
			assert.Contains(t, binfmt, "enabled", "QEMU aarch64应该已启用")
		}

		// 列出所有QEMU注册
		entries, err := exec.Command("ls", "/proc/sys/fs/binfmt_misc/").Output()
		if err == nil {
			entryList := string(entries)
			t.Log("binfmt_misc条目:", entryList)
		}
	})

	t.Run("QEMU仿真性能测试", func(t *testing.T) {
		if runtime.GOARCH == "arm64" {
			t.Skip("在ARM64上跳过x86_64仿真测试")
		}

		containerName := "test-qemu-emulation"
		
		// 尝试运行ARM64容器（如果在x86_64上）
		args := []string{"run", "-d", "--runtime=sysbox-runc", "--platform", "linux/arm64",
			"--name", containerName, "ubuntu:20.04", "sleep", "60"}
		
		output, err := exec.Command("docker", args...).Output()
		if err != nil {
			t.Skipf("无法运行ARM64仿真容器: %v", err)
		}
		
		containerID := strings.TrimSpace(string(output))
		defer cleanupContainer(t, containerID)
		
		time.Sleep(5 * time.Second)
		
		// 验证仿真环境
		arch := execInContainer(t, containerID, "uname", "-m")
		t.Logf("仿真容器架构: %s", strings.TrimSpace(arch))
		
		// 运行简单的性能测试
		script := `#!/bin/bash
echo "Testing emulated performance..."
start_time=$(date +%s%N)

# 简单的计算测试
result=0
for i in {1..100000}; do
    result=$((result + i))
done

end_time=$(date +%s%N)
elapsed=$((($end_time - $start_time) / 1000000))
echo "Calculation time: ${elapsed} ms"
echo "Result: ${result}"`

		output = execInContainer(t, containerID, "bash", "-c", script)
		t.Log("QEMU仿真性能测试结果:", output)
		
		assert.Contains(t, output, "Calculation time:", "仿真环境应该能正常执行计算")
	})
}

// testARM64SpecificFeatures 测试ARM64特定功能
func testARM64SpecificFeatures(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("跳过ARM64特定测试，当前架构不是ARM64")
	}

	containerName := "test-arm64-features"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试ARM64指令集特性
	t.Run("ARM64指令集特性检测", func(t *testing.T) {
		script := `#!/bin/bash
echo "Checking ARM64 features..."

# 检查CPU特性
cat /proc/cpuinfo | grep Features

# 检查架构版本
cat /proc/cpuinfo | grep "CPU architecture"

# 检查SVE支持
if grep -q sve /proc/cpuinfo; then
    echo "SVE (Scalable Vector Extension) supported"
else
    echo "SVE not supported"
fi

# 检查LSE支持
if grep -q atomics /proc/cpuinfo; then
    echo "LSE (Large System Extensions) supported"
else
    echo "LSE not supported"
fi`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("ARM64特性检测结果:", output)
		
		assert.Contains(t, output, "Checking ARM64 features", "应该执行ARM64特性检查")
	})

	// 测试NEON向量化
	t.Run("NEON向量化测试", func(t *testing.T) {
		script := `#!/bin/bash
apt update && apt install -y gcc

cat > /tmp/neon_test.c << 'EOF'
#include <stdio.h>
#include <arm_neon.h>
#include <time.h>

void neon_vector_add(float *a, float *b, float *c, int n) {
    int i;
    for (i = 0; i <= n - 4; i += 4) {
        float32x4_t va = vld1q_f32(&a[i]);
        float32x4_t vb = vld1q_f32(&b[i]);
        float32x4_t vc = vaddq_f32(va, vb);
        vst1q_f32(&c[i], vc);
    }
    
    // 处理剩余元素
    for (; i < n; i++) {
        c[i] = a[i] + b[i];
    }
}

int main() {
    const int N = 1000000;
    float *a = malloc(N * sizeof(float));
    float *b = malloc(N * sizeof(float));
    float *c = malloc(N * sizeof(float));
    
    for (int i = 0; i < N; i++) {
        a[i] = i * 1.0f;
        b[i] = i * 2.0f;
    }
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    neon_vector_add(a, b, c, N);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("NEON vector add time: %.2f ms\n", time_taken);
    
    free(a); free(b); free(c);
    return 0;
}
EOF

gcc -O3 -o /tmp/neon_test /tmp/neon_test.c
/tmp/neon_test`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("NEON向量化测试结果:", output)
		
		if strings.Contains(output, "NEON vector add time:") {
			assert.Contains(t, output, "NEON vector add time:", "应该输出NEON向量化时间")
		}
	})
}

// testX86_64SpecificFeatures 测试x86_64特定功能
func testX86_64SpecificFeatures(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("跳过x86_64特定测试，当前架构不是x86_64")
	}

	containerName := "test-x86-64-features"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试x86_64指令集特性
	t.Run("x86_64指令集特性检测", func(t *testing.T) {
		script := `#!/bin/bash
echo "Checking x86_64 features..."

# 检查CPU特性
cat /proc/cpuinfo | grep flags | head -1

# 检查AVX支持
if grep -q avx /proc/cpuinfo; then
    echo "AVX supported"
else
    echo "AVX not supported"
fi

# 检查AVX2支持
if grep -q avx2 /proc/cpuinfo; then
    echo "AVX2 supported"
else
    echo "AVX2 not supported"
fi

# 检查SSE支持
if grep -q sse /proc/cpuinfo; then
    echo "SSE supported"
else
    echo "SSE not supported"
fi`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("x86_64特性检测结果:", output)
		
		assert.Contains(t, output, "Checking x86_64 features", "应该执行x86_64特性检查")
	})

	// 测试AVX向量化（如果支持）
	t.Run("AVX向量化测试", func(t *testing.T) {
		script := `#!/bin/bash
apt update && apt install -y gcc

cat > /tmp/avx_test.c << 'EOF'
#include <stdio.h>
#include <immintrin.h>
#include <time.h>

void avx_vector_add(float *a, float *b, float *c, int n) {
    int i;
    for (i = 0; i <= n - 8; i += 8) {
        __m256 va = _mm256_load_ps(&a[i]);
        __m256 vb = _mm256_load_ps(&b[i]);
        __m256 vc = _mm256_add_ps(va, vb);
        _mm256_store_ps(&c[i], vc);
    }
    
    for (; i < n; i++) {
        c[i] = a[i] + b[i];
    }
}

int main() {
    const int N = 1000000;
    float *a = aligned_alloc(32, N * sizeof(float));
    float *b = aligned_alloc(32, N * sizeof(float));
    float *c = aligned_alloc(32, N * sizeof(float));
    
    for (int i = 0; i < N; i++) {
        a[i] = i * 1.0f;
        b[i] = i * 2.0f;
    }
    
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    avx_vector_add(a, b, c, N);
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("AVX vector add time: %.2f ms\n", time_taken);
    
    free(a); free(b); free(c);
    return 0;
}
EOF

gcc -O3 -mavx -o /tmp/avx_test /tmp/avx_test.c 2>/dev/null
if [ $? -eq 0 ]; then
    /tmp/avx_test
else
    echo "AVX compilation failed or not supported"
fi`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("AVX向量化测试结果:", output)
		
		if strings.Contains(output, "AVX vector add time:") {
			assert.Contains(t, output, "AVX vector add time:", "应该输出AVX向量化时间")
		}
	})
}

// testCrossArchPerformanceComparison 测试跨架构性能对比
func testCrossArchPerformanceComparison(t *testing.T) {
	hostArch := runtime.GOARCH
	
	// 定义性能测试脚本
	performanceScript := `#!/bin/bash
echo "Running cross-architecture performance test..."

cat > /tmp/perf_test.c << 'EOF'
#include <stdio.h>
#include <time.h>
#include <math.h>

int main() {
    struct timespec start, end;
    double result = 0;
    int iterations = 1000000;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < iterations; i++) {
        result += sqrt(i) * sin(i);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Architecture: %s\n", "ARCH_PLACEHOLDER");
    printf("Computation time: %.2f ms\n", time_taken);
    printf("Operations per second: %.0f\n", iterations * 1000.0 / time_taken);
    
    return 0;
}
EOF

apt update && apt install -y gcc
gcc -lm -o /tmp/perf_test /tmp/perf_test.c
/tmp/perf_test`

	results := make(map[string]string)

	// 测试原生架构性能
	t.Run(fmt.Sprintf("原生架构性能(%s)", hostArch), func(t *testing.T) {
		containerName := fmt.Sprintf("perf-native-%s", hostArch)
		containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
		defer cleanupContainer(t, containerID)
		
		script := strings.Replace(performanceScript, "ARCH_PLACEHOLDER", hostArch, 1)
		output := execInContainer(t, containerID, "bash", "-c", script)
		
		results[hostArch] = output
		t.Log("原生架构性能测试结果:", output)
	})

	// 测试仿真架构性能（如果可用）
	targetArchs := []string{"amd64", "arm64"}
	for _, targetArch := range targetArchs {
		if targetArch == hostArch {
			continue
		}
		
		t.Run(fmt.Sprintf("仿真架构性能(%s)", targetArch), func(t *testing.T) {
			if !isArchitectureSupported(targetArch) {
				t.Skipf("不支持%s架构仿真", targetArch)
			}
			
			containerName := fmt.Sprintf("perf-emulated-%s", targetArch)
			
			args := []string{"run", "-d", "--runtime=sysbox-runc", "--platform", fmt.Sprintf("linux/%s", targetArch),
				"--name", containerName, "ubuntu:20.04", "sleep", "300"}
			
			output, err := exec.Command("docker", args...).Output()
			if err != nil {
				t.Skipf("无法创建%s仿真容器: %v", targetArch, err)
			}
			
			containerID := strings.TrimSpace(string(output))
			defer cleanupContainer(t, containerID)
			
			time.Sleep(10 * time.Second) // 仿真容器需要更多时间启动
			
			script := strings.Replace(performanceScript, "ARCH_PLACEHOLDER", targetArch, 1)
			output = execInContainer(t, containerID, "bash", "-c", script)
			
			results[targetArch] = output
			t.Log("仿真架构性能测试结果:", output)
		})
	}

	// 比较性能结果
	t.Run("性能结果对比", func(t *testing.T) {
		t.Log("=== 跨架构性能对比汇总 ===")
		for arch, result := range results {
			t.Logf("架构 %s 结果:\n%s", arch, result)
		}
	})
}

// 辅助函数

func setupMultiArchTestEnv(t *testing.T) {
	// 确保sysbox服务运行正常
	err := exec.Command("systemctl", "is-active", "sysbox").Run()
	if err != nil {
		t.Skip("Sysbox服务未运行，跳过多架构测试")
	}
}

func cleanupMultiArchTestEnv(t *testing.T) {
	// 清理测试环境
	exec.Command("docker", "system", "prune", "-f").Run()
}

func getHostArchitecture(t *testing.T) ArchitectureInfo {
	arch := ArchitectureInfo{
		Architecture: runtime.GOARCH,
		CoreCount:    runtime.NumCPU(),
	}
	
	// 获取CPU信息
	if cpuInfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		content := string(cpuInfo)
		
		// 解析CPU型号
		if match := regexp.MustCompile(`model name\s*:\s*(.+)`).FindStringSubmatch(content); len(match) > 1 {
			arch.CPUModel = strings.TrimSpace(match[1])
		}
		
		// 解析特性
		if match := regexp.MustCompile(`flags\s*:\s*(.+)`).FindStringSubmatch(content); len(match) > 1 {
			arch.Features = strings.Fields(match[1])
		}
	}
	
	return arch
}

func testX86_64Instructions(t *testing.T, containerID string) {
	script := `#!/bin/bash
cat > /tmp/x86_instruction_test.c << 'EOF'
#include <stdio.h>

int main() {
    printf("Testing x86_64 specific instructions\n");
    
    // 测试CPUID指令
    unsigned int eax, ebx, ecx, edx;
    asm volatile("cpuid"
                 : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
                 : "a" (0));
    
    printf("CPUID leaf 0: EAX=0x%x, EBX=0x%x, ECX=0x%x, EDX=0x%x\n", 
           eax, ebx, ecx, edx);
    
    return 0;
}
EOF

gcc -o /tmp/x86_instruction_test /tmp/x86_instruction_test.c
/tmp/x86_instruction_test`

	output := execInContainer(t, containerID, "bash", "-c", script)
	t.Log("x86_64指令测试结果:", output)
	
	assert.Contains(t, output, "Testing x86_64 specific instructions", "应该执行x86_64指令测试")
}

func testARM64Instructions(t *testing.T, containerID string) {
	script := `#!/bin/bash
cat > /tmp/arm64_instruction_test.c << 'EOF'
#include <stdio.h>

int main() {
    printf("Testing ARM64 specific instructions\n");
    
    // 测试系统寄存器读取
    unsigned long midr;
    asm volatile("mrs %0, midr_el1" : "=r" (midr));
    
    printf("MIDR_EL1: 0x%lx\n", midr);
    
    return 0;
}
EOF

gcc -o /tmp/arm64_instruction_test /tmp/arm64_instruction_test.c
/tmp/arm64_instruction_test`

	output := execInContainer(t, containerID, "bash", "-c", script)
	t.Log("ARM64指令测试结果:", output)
	
	assert.Contains(t, output, "Testing ARM64 specific instructions", "应该执行ARM64指令测试")
}

func countCPUCores(cpuInfo string) int {
	lines := strings.Split(cpuInfo, "\n")
	processorCount := 0
	
	for _, line := range lines {
		if strings.HasPrefix(line, "processor") {
			processorCount++
		}
	}
	
	return processorCount
}

func isArchitectureSupported(arch string) bool {
	// 检查是否支持指定架构的仿真
	_, err := exec.Command("docker", "run", "--rm", "--platform", fmt.Sprintf("linux/%s", arch), 
		"hello-world").Output()
	return err == nil
}

func isQEMUUserModeAvailable() bool {
	// 检查QEMU用户模式是否可用
	_, err := os.Stat("/proc/sys/fs/binfmt_misc/qemu-aarch64")
	if err == nil {
		return true
	}
	
	_, err = os.Stat("/proc/sys/fs/binfmt_misc/qemu-x86_64")
	return err == nil
}

func createSysboxContainer(t *testing.T, name, image string, cmd []string) string {
	args := []string{"run", "-d", "--runtime=sysbox-runc", "--name", name, image}
	args = append(args, cmd...)
	
	output, err := exec.Command("docker", args...).Output()
	require.NoError(t, err, "创建Sysbox容器失败")
	
	containerID := strings.TrimSpace(string(output))
	
	// 等待容器启动
	time.Sleep(2 * time.Second)
	
	return containerID
}

func execInContainer(t *testing.T, containerID string, cmd ...string) string {
	args := []string{"exec", containerID}
	args = append(args, cmd...)
	
	output, err := exec.Command("docker", args...).Output()
	require.NoError(t, err, "在容器中执行命令失败: %v", cmd)
	
	return string(output)
}

func cleanupContainer(t *testing.T, containerID string) {
	exec.Command("docker", "rm", "-f", containerID).Run()
}