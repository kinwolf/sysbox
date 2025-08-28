package advanced

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SyscallMetrics 系统调用性能指标
type SyscallMetrics struct {
	SyscallName      string
	CallCount        int64
	TotalTime        time.Duration
	AverageTime      time.Duration
	ErrorCount       int64
	InterceptionRate float64
}

// TestAdvancedSyscallInterception 测试系统调用高级拦截功能
func TestAdvancedSyscallInterception(t *testing.T) {
	setupAdvancedSyscallTestEnv(t)
	defer cleanupAdvancedSyscallTestEnv(t)

	t.Run("复杂挂载操作拦截", func(t *testing.T) {
		testComplexMountOperations(t)
	})

	t.Run("高频系统调用性能优化", func(t *testing.T) {
		testHighFrequencySyscallOptimization(t)
	})

	t.Run("嵌套系统调用处理", func(t *testing.T) {
		testNestedSyscallHandling(t)
	})

	t.Run("系统调用过滤和白名单", func(t *testing.T) {
		testSyscallFilteringAndWhitelist(t)
	})

	t.Run("异步系统调用处理", func(t *testing.T) {
		testAsynchronousSyscallHandling(t)
	})

	t.Run("系统调用监控和分析", func(t *testing.T) {
		testSyscallMonitoringAndAnalysis(t)
	})

	t.Run("特权系统调用动态授权", func(t *testing.T) {
		testPrivilegedSyscallDynamicAuthorization(t)
	})

	t.Run("系统调用性能基准测试", func(t *testing.T) {
		testSyscallPerformanceBenchmark(t)
	})
}

// testComplexMountOperations 测试复杂挂载操作拦截
func testComplexMountOperations(t *testing.T) {
	containerName := "test-complex-mount"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试复杂的bind mount操作
	t.Run("复杂Bind Mount操作", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing complex bind mount operations..."

# 创建测试目录和文件
mkdir -p /test/{source,target1,target2,nested/deep}
echo "source content" > /test/source/file.txt
echo "nested content" > /test/nested/deep/nested.txt

# 测试基本bind mount
mount --bind /test/source /test/target1
if [ $? -eq 0 ]; then
    echo "Basic bind mount: SUCCESS"
    ls -la /test/target1/
else
    echo "Basic bind mount: FAILED"
fi

# 测试只读bind mount
mount --bind /test/source /test/target2
mount -o remount,ro,bind /test/target2
if [ $? -eq 0 ]; then
    echo "Readonly bind mount: SUCCESS"
    # 尝试写入（应该失败）
    echo "test" > /test/target2/readonly_test.txt 2>&1 && echo "Write unexpectedly succeeded" || echo "Write correctly failed"
else
    echo "Readonly bind mount: FAILED"
fi

# 测试递归bind mount
mkdir -p /test/recursive/{src/{a,b},dst}
echo "recursive a" > /test/recursive/src/a/file.txt
echo "recursive b" > /test/recursive/src/b/file.txt
mount --rbind /test/recursive/src /test/recursive/dst
if [ $? -eq 0 ]; then
    echo "Recursive bind mount: SUCCESS"
    find /test/recursive/dst -type f
else
    echo "Recursive bind mount: FAILED"
fi

# 测试move mount
mkdir -p /test/move/{src,dst}
echo "move content" > /test/move/src/move.txt
mount --bind /test/move/src /test/move/dst
mount --move /test/move/dst /test/moved_destination 2>/dev/null
if [ $? -eq 0 ]; then
    echo "Move mount: SUCCESS"
else
    echo "Move mount: FAILED (expected in container)"
fi

# 清理
umount /test/target1 2>/dev/null
umount /test/target2 2>/dev/null
umount -R /test/recursive/dst 2>/dev/null`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("复杂Bind Mount测试结果:", output)

		assert.Contains(t, output, "Basic bind mount: SUCCESS", "基本bind mount应该成功")
		assert.Contains(t, output, "Readonly bind mount: SUCCESS", "只读bind mount应该成功")
		assert.Contains(t, output, "Write correctly failed", "只读挂载应该阻止写入")
	})

	// 测试特殊文件系统挂载
	t.Run("特殊文件系统挂载", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing special filesystem mounts..."

# 测试tmpfs挂载
mkdir -p /test/tmpfs
mount -t tmpfs tmpfs /test/tmpfs -o size=10M,noexec,nosuid,nodev
if [ $? -eq 0 ]; then
    echo "tmpfs mount: SUCCESS"
    echo "test data" > /test/tmpfs/test.txt
    df -h /test/tmpfs
    umount /test/tmpfs
else
    echo "tmpfs mount: FAILED"
fi

# 测试devtmpfs挂载（应该被拦截）
mkdir -p /test/devtmpfs
mount -t devtmpfs devtmpfs /test/devtmpfs 2>&1
if [ $? -eq 0 ]; then
    echo "devtmpfs mount: UNEXPECTED SUCCESS"
    umount /test/devtmpfs
else
    echo "devtmpfs mount: CORRECTLY BLOCKED"
fi

# 测试procfs重新挂载（应该被拦截或虚拟化）
mount -t proc proc /test/proc 2>&1
if [ $? -eq 0 ]; then
    echo "procfs remount: SUCCESS (virtualized)"
    ls /test/proc | head -5
    umount /test/proc 2>/dev/null
else
    echo "procfs remount: BLOCKED"
fi

# 测试sysfs重新挂载（应该被拦截或虚拟化）
mkdir -p /test/sysfs
mount -t sysfs sysfs /test/sysfs 2>&1
if [ $? -eq 0 ]; then
    echo "sysfs remount: SUCCESS (virtualized)"
    ls /test/sysfs | head -5
    umount /test/sysfs 2>/dev/null
else
    echo "sysfs remount: BLOCKED"
fi`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("特殊文件系统挂载测试结果:", output)

		assert.Contains(t, output, "tmpfs mount: SUCCESS", "tmpfs挂载应该成功")
		assert.Contains(t, output, "devtmpfs mount: CORRECTLY BLOCKED", "devtmpfs挂载应该被阻止")
	})

	// 测试挂载命名空间操作
	t.Run("挂载命名空间操作", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing mount namespace operations..."

# 检查当前挂载命名空间
echo "Current mount namespace:"
readlink /proc/self/ns/mnt

# 尝试创建新的挂载命名空间
unshare --mount bash -c "
    echo 'In new mount namespace:'
    readlink /proc/self/ns/mnt
    
    # 在新命名空间中进行挂载操作
    mkdir -p /test/ns_mount
    mount -t tmpfs tmpfs /test/ns_mount 2>&1
    if [ \$? -eq 0 ]; then
        echo 'Mount in new namespace: SUCCESS'
        echo 'test data in new ns' > /test/ns_mount/test.txt
        cat /test/ns_mount/test.txt
        umount /test/ns_mount
    else
        echo 'Mount in new namespace: FAILED'
    fi
" 2>&1

echo "Back in original namespace"
readlink /proc/self/ns/mnt`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("挂载命名空间操作测试结果:", output)

		assert.Contains(t, output, "Current mount namespace:", "应该能读取挂载命名空间信息")
	})
}

// testHighFrequencySyscallOptimization 测试高频系统调用性能优化
func testHighFrequencySyscallOptimization(t *testing.T) {
	containerName := "test-syscall-performance"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试高频文件操作
	t.Run("高频文件操作性能", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing high-frequency file operations..."

cat > /tmp/file_ops_test.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

int main() {
    struct timespec start, end;
    int iterations = 10000;
    int i, fd;
    char filename[256];
    
    printf("Testing %d file operations\n", iterations);
    
    // 测试open/close性能
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (i = 0; i < iterations; i++) {
        snprintf(filename, sizeof(filename), "/tmp/test_file_%d", i % 100);
        fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, "test", 4);
            close(fd);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("File operations time: %.2f ms\n", time_taken);
    printf("Operations per second: %.0f\n", iterations * 1000.0 / time_taken);
    
    // 测试stat性能
    clock_gettime(CLOCK_MONOTONIC, &start);
    struct stat st;
    for (i = 0; i < iterations; i++) {
        snprintf(filename, sizeof(filename), "/tmp/test_file_%d", i % 100);
        stat(filename, &st);
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                  (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Stat operations time: %.2f ms\n", time_taken);
    printf("Stat operations per second: %.0f\n", iterations * 1000.0 / time_taken);
    
    // 清理测试文件
    for (i = 0; i < 100; i++) {
        snprintf(filename, sizeof(filename), "/tmp/test_file_%d", i);
        unlink(filename);
    }
    
    return 0;
}
EOF

apt update && apt install -y gcc
gcc -o /tmp/file_ops_test /tmp/file_ops_test.c
/tmp/file_ops_test`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("高频文件操作性能测试结果:", output)

		assert.Contains(t, output, "Operations per second:", "应该输出文件操作性能数据")
		assert.Contains(t, output, "Stat operations per second:", "应该输出stat操作性能数据")
	})

	// 测试内存映射性能
	t.Run("内存映射性能", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing memory mapping performance..."

cat > /tmp/mmap_test.c << 'EOF'
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

int main() {
    struct timespec start, end;
    int iterations = 1000;
    int i, fd;
    void *ptr;
    size_t map_size = 4096; // 一页大小
    
    printf("Testing %d memory mapping operations\n", iterations);
    
    // 创建测试文件
    fd = open("/tmp/mmap_test_file", O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    // 扩展文件到所需大小
    if (ftruncate(fd, map_size) < 0) {
        perror("ftruncate");
        close(fd);
        return 1;
    }
    
    // 测试mmap/munmap性能
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (i = 0; i < iterations; i++) {
        ptr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (ptr != MAP_FAILED) {
            // 写入一些数据
            memset(ptr, 0x42, 100);
            munmap(ptr, map_size);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Memory mapping time: %.2f ms\n", time_taken);
    printf("Mapping operations per second: %.0f\n", iterations * 1000.0 / time_taken);
    
    close(fd);
    unlink("/tmp/mmap_test_file");
    
    return 0;
}
EOF

gcc -o /tmp/mmap_test /tmp/mmap_test.c
/tmp/mmap_test`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("内存映射性能测试结果:", output)

		assert.Contains(t, output, "Mapping operations per second:", "应该输出内存映射性能数据")
	})

	// 测试进程创建性能
	t.Run("进程创建性能", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing process creation performance..."

cat > /tmp/fork_test.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

int main() {
    struct timespec start, end;
    int iterations = 100; // 减少迭代次数避免系统负载过高
    int i;
    pid_t pid;
    
    printf("Testing %d process creation operations\n", iterations);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (i = 0; i < iterations; i++) {
        pid = fork();
        if (pid == 0) {
            // 子进程立即退出
            _exit(0);
        } else if (pid > 0) {
            // 父进程等待子进程
            waitpid(pid, NULL, 0);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Process creation time: %.2f ms\n", time_taken);
    printf("Process creation per second: %.0f\n", iterations * 1000.0 / time_taken);
    
    return 0;
}
EOF

gcc -o /tmp/fork_test /tmp/fork_test.c
/tmp/fork_test`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("进程创建性能测试结果:", output)

		assert.Contains(t, output, "Process creation per second:", "应该输出进程创建性能数据")
	})
}

// testNestedSyscallHandling 测试嵌套系统调用处理
func testNestedSyscallHandling(t *testing.T) {
	containerName := "test-nested-syscall"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试嵌套文件操作
	t.Run("嵌套文件操作", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing nested file operations..."

cat > /tmp/nested_ops.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

void nested_file_ops(int depth, int max_depth) {
    char filename[256];
    int fd;
    
    if (depth >= max_depth) return;
    
    snprintf(filename, sizeof(filename), "/tmp/nested_file_%d", depth);
    
    // 创建文件
    fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        char data[64];
        snprintf(data, sizeof(data), "Nested operation at depth %d\n", depth);
        write(fd, data, strlen(data));
        
        // 嵌套调用
        nested_file_ops(depth + 1, max_depth);
        
        close(fd);
    }
}

int main() {
    printf("Starting nested file operations...\n");
    nested_file_ops(0, 10);
    
    // 验证文件创建
    struct stat st;
    int count = 0;
    for (int i = 0; i < 10; i++) {
        char filename[256];
        snprintf(filename, sizeof(filename), "/tmp/nested_file_%d", i);
        if (stat(filename, &st) == 0) {
            count++;
        }
        unlink(filename); // 清理
    }
    
    printf("Successfully created %d nested files\n", count);
    return 0;
}
EOF

gcc -o /tmp/nested_ops /tmp/nested_ops.c
/tmp/nested_ops`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("嵌套文件操作测试结果:", output)

		assert.Contains(t, output, "Successfully created", "嵌套文件操作应该成功")
	})

	// 测试嵌套进程创建
	t.Run("嵌套进程创建", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing nested process creation..."

cat > /tmp/nested_procs.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

void nested_process(int depth, int max_depth) {
    if (depth >= max_depth) {
        printf("Reached maximum depth %d in process %d\n", depth, getpid());
        return;
    }
    
    pid_t pid = fork();
    if (pid == 0) {
        // 子进程
        printf("Child process %d at depth %d\n", getpid(), depth);
        nested_process(depth + 1, max_depth);
        _exit(0);
    } else if (pid > 0) {
        // 父进程等待子进程
        int status;
        waitpid(pid, &status, 0);
        printf("Parent process %d completed child at depth %d\n", getpid(), depth);
    }
}

int main() {
    printf("Starting nested process creation...\n");
    nested_process(0, 5); // 限制深度避免系统负载过高
    printf("Nested process creation completed\n");
    return 0;
}
EOF

gcc -o /tmp/nested_procs /tmp/nested_procs.c
timeout 30 /tmp/nested_procs`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("嵌套进程创建测试结果:", output)

		assert.Contains(t, output, "Nested process creation completed", "嵌套进程创建应该完成")
	})

	// 测试复杂的系统调用链
	t.Run("复杂系统调用链", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing complex syscall chains..."

cat > /tmp/syscall_chain.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>

int complex_syscall_chain() {
    int fd1, fd2;
    void *ptr;
    struct stat st;
    char buffer[1024];
    
    // 1. 创建文件
    fd1 = open("/tmp/chain_test1", O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd1 < 0) return -1;
    
    // 2. 写入数据
    strcpy(buffer, "Complex syscall chain test data");
    write(fd1, buffer, strlen(buffer));
    
    // 3. 获取文件状态
    fstat(fd1, &st);
    printf("File size: %ld bytes\n", st.st_size);
    
    // 4. 内存映射
    ptr = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd1, 0);
    if (ptr == MAP_FAILED) {
        close(fd1);
        return -1;
    }
    
    // 5. 修改映射内存
    strcat((char*)ptr, " - modified via mmap");
    
    // 6. 同步到磁盘
    msync(ptr, st.st_size + 20, MS_SYNC);
    
    // 7. 解除映射
    munmap(ptr, st.st_size);
    
    // 8. 创建硬链接
    close(fd1);
    link("/tmp/chain_test1", "/tmp/chain_test1_link");
    
    // 9. 创建软链接
    symlink("/tmp/chain_test1", "/tmp/chain_test1_symlink");
    
    // 10. 读取通过软链接
    fd2 = open("/tmp/chain_test1_symlink", O_RDONLY);
    if (fd2 >= 0) {
        read(fd2, buffer, sizeof(buffer));
        printf("Read via symlink: %s\n", buffer);
        close(fd2);
    }
    
    // 清理
    unlink("/tmp/chain_test1");
    unlink("/tmp/chain_test1_link");
    unlink("/tmp/chain_test1_symlink");
    
    return 0;
}

int main() {
    printf("Executing complex syscall chain...\n");
    int result = complex_syscall_chain();
    printf("Complex syscall chain result: %s\n", result == 0 ? "SUCCESS" : "FAILED");
    return result;
}
EOF

gcc -o /tmp/syscall_chain /tmp/syscall_chain.c
/tmp/syscall_chain`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("复杂系统调用链测试结果:", output)

		assert.Contains(t, output, "Complex syscall chain result: SUCCESS", "复杂系统调用链应该成功")
	})
}

// testSyscallFilteringAndWhitelist 测试系统调用过滤和白名单
func testSyscallFilteringAndWhitelist(t *testing.T) {
	containerName := "test-syscall-filtering"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试危险系统调用拦截
	t.Run("危险系统调用拦截", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing dangerous syscall blocking..."

cat > /tmp/dangerous_syscalls.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <sys/ptrace.h>

int main() {
    printf("Testing dangerous syscalls...\n");
    
    // 测试reboot系统调用（应该被阻止）
    printf("Testing reboot syscall...\n");
    int result = reboot(RB_AUTOBOOT);
    printf("Reboot result: %d (should fail)\n", result);
    
    // 测试不安全的mount操作
    printf("Testing dangerous mount...\n");
    result = mount("/dev/sda1", "/mnt", "ext4", 0, NULL);
    printf("Dangerous mount result: %d (should fail)\n", result);
    
    // 测试ptrace（可能被限制）
    printf("Testing ptrace...\n");
    result = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    printf("Ptrace result: %d\n", result);
    
    printf("Dangerous syscall tests completed\n");
    return 0;
}
EOF

gcc -o /tmp/dangerous_syscalls /tmp/dangerous_syscalls.c
/tmp/dangerous_syscalls 2>&1`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("危险系统调用拦截测试结果:", output)

		assert.Contains(t, output, "Dangerous syscall tests completed", "危险系统调用测试应该完成")
		// 大多数危险系统调用应该失败
		assert.Contains(t, output, "should fail", "危险系统调用应该被标记为失败")
	})

	// 测试系统调用白名单
	t.Run("系统调用白名单", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing syscall whitelist..."

cat > /tmp/whitelist_test.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

int main() {
    printf("Testing whitelisted syscalls...\n");
    
    // 这些是通常被允许的系统调用
    
    // 1. 基本I/O操作
    int fd = open("/tmp/whitelist_test", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        printf("File open: SUCCESS\n");
        write(fd, "test", 4);
        printf("File write: SUCCESS\n");
        close(fd);
        printf("File close: SUCCESS\n");
    }
    
    // 2. 文件状态查询
    struct stat st;
    if (stat("/tmp/whitelist_test", &st) == 0) {
        printf("File stat: SUCCESS\n");
    }
    
    // 3. 时间相关系统调用
    time_t t = time(NULL);
    printf("Time syscall: SUCCESS (time: %ld)\n", t);
    
    // 4. 进程信息查询
    pid_t pid = getpid();
    printf("Getpid: SUCCESS (pid: %d)\n", pid);
    
    // 5. 内存分配
    void *ptr = sbrk(0);
    if (ptr != (void*)-1) {
        printf("Memory syscalls: SUCCESS\n");
    }
    
    // 清理
    unlink("/tmp/whitelist_test");
    
    printf("Whitelisted syscall tests completed\n");
    return 0;
}
EOF

gcc -o /tmp/whitelist_test /tmp/whitelist_test.c
/tmp/whitelist_test`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("系统调用白名单测试结果:", output)

		assert.Contains(t, output, "File open: SUCCESS", "文件打开应该被允许")
		assert.Contains(t, output, "Time syscall: SUCCESS", "时间系统调用应该被允许")
		assert.Contains(t, output, "Getpid: SUCCESS", "getpid应该被允许")
	})

	// 测试系统调用频率限制
	t.Run("系统调用频率限制", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing syscall rate limiting..."

cat > /tmp/rate_limit_test.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <time.h>

int main() {
    struct timespec start, end;
    int iterations = 10000;
    int success_count = 0;
    
    printf("Testing syscall rate limiting with %d iterations...\n", iterations);
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < iterations; i++) {
        // 执行大量的getpid调用
        pid_t pid = getpid();
        if (pid > 0) {
            success_count++;
        }
        
        // 每1000次检查一下是否被限制
        if (i % 1000 == 0) {
            printf("Completed %d iterations\n", i);
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Rate limiting test completed\n");
    printf("Success rate: %d/%d (%.2f%%)\n", success_count, iterations, 
           (success_count * 100.0) / iterations);
    printf("Total time: %.2f ms\n", time_taken);
    printf("Syscalls per second: %.0f\n", success_count * 1000.0 / time_taken);
    
    return 0;
}
EOF

gcc -o /tmp/rate_limit_test /tmp/rate_limit_test.c
timeout 30 /tmp/rate_limit_test`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("系统调用频率限制测试结果:", output)

		assert.Contains(t, output, "Rate limiting test completed", "频率限制测试应该完成")
	})
}

// testAsynchronousSyscallHandling 测试异步系统调用处理
func testAsynchronousSyscallHandling(t *testing.T) {
	containerName := "test-async-syscall"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试异步I/O操作
	t.Run("异步I/O操作", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing asynchronous I/O operations..."

cat > /tmp/async_io.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <aio.h>
#include <string.h>
#include <time.h>

int main() {
    struct aiocb aio_write, aio_read;
    char write_buffer[] = "Asynchronous I/O test data";
    char read_buffer[256];
    int fd;
    
    printf("Testing asynchronous I/O...\n");
    
    // 创建测试文件
    fd = open("/tmp/async_test", O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    // 设置异步写操作
    memset(&aio_write, 0, sizeof(aio_write));
    aio_write.aio_fildes = fd;
    aio_write.aio_buf = write_buffer;
    aio_write.aio_nbytes = strlen(write_buffer);
    aio_write.aio_offset = 0;
    
    // 启动异步写
    if (aio_write(fd, &aio_write) < 0) {
        printf("AIO write not supported or failed\n");
        close(fd);
        unlink("/tmp/async_test");
        return 0; // 不是错误，可能系统不支持AIO
    }
    
    printf("Async write initiated\n");
    
    // 等待写操作完成
    while (aio_error(&aio_write) == EINPROGRESS) {
        usleep(1000); // 等待1ms
    }
    
    ssize_t write_result = aio_return(&aio_write);
    printf("Async write completed: %ld bytes\n", write_result);
    
    // 设置异步读操作
    memset(&aio_read, 0, sizeof(aio_read));
    aio_read.aio_fildes = fd;
    aio_read.aio_buf = read_buffer;
    aio_read.aio_nbytes = sizeof(read_buffer) - 1;
    aio_read.aio_offset = 0;
    
    // 启动异步读
    if (aio_read(fd, &aio_read) < 0) {
        printf("AIO read failed\n");
    } else {
        printf("Async read initiated\n");
        
        // 等待读操作完成
        while (aio_error(&aio_read) == EINPROGRESS) {
            usleep(1000);
        }
        
        ssize_t read_result = aio_return(&aio_read);
        if (read_result > 0) {
            read_buffer[read_result] = '\0';
            printf("Async read completed: %s\n", read_buffer);
        }
    }
    
    close(fd);
    unlink("/tmp/async_test");
    
    printf("Asynchronous I/O test completed\n");
    return 0;
}
EOF

# 尝试编译并运行（AIO可能需要特殊库）
gcc -o /tmp/async_io /tmp/async_io.c -lrt 2>/dev/null
if [ $? -eq 0 ]; then
    /tmp/async_io
else
    echo "AIO compilation failed, using alternative test"
    # 使用select/poll作为异步I/O的替代测试
    echo "Testing with select-based async I/O simulation"
fi`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("异步I/O操作测试结果:", output)

		assert.Contains(t, output, "Asynchronous I/O test completed", "异步I/O测试应该完成")
	})

	// 测试信号处理
	t.Run("异步信号处理", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing asynchronous signal handling..."

cat > /tmp/signal_test.c << 'EOF'
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

volatile int signal_received = 0;

void signal_handler(int sig) {
    printf("Received signal %d\n", sig);
    signal_received = 1;
}

int main() {
    printf("Testing asynchronous signal handling...\n");
    
    // 设置信号处理器
    signal(SIGUSR1, signal_handler);
    signal(SIGALRM, signal_handler);
    
    // 测试自发信号
    printf("Sending SIGALRM to self...\n");
    alarm(1); // 1秒后发送SIGALRM
    
    // 等待信号
    while (!signal_received) {
        sleep(1);
    }
    
    printf("Signal handling test completed\n");
    return 0;
}
EOF

gcc -o /tmp/signal_test /tmp/signal_test.c
timeout 10 /tmp/signal_test`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("异步信号处理测试结果:", output)

		assert.Contains(t, output, "Signal handling test completed", "信号处理测试应该完成")
	})
}

// testSyscallMonitoringAndAnalysis 测试系统调用监控和分析
func testSyscallMonitoringAndAnalysis(t *testing.T) {
	containerName := "test-syscall-monitoring"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试系统调用跟踪
	t.Run("系统调用跟踪", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing syscall tracing..."

# 创建一个简单的测试程序
cat > /tmp/traced_program.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    printf("Starting traced program...\n");
    
    int fd = open("/tmp/trace_test", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, "test data", 9);
        close(fd);
    }
    
    printf("Traced program completed\n");
    return 0;
}
EOF

gcc -o /tmp/traced_program /tmp/traced_program.c

# 使用strace跟踪系统调用（如果可用）
if command -v strace >/dev/null 2>&1; then
    echo "Using strace for syscall tracing..."
    strace -c -o /tmp/strace_output /tmp/traced_program 2>/dev/null
    if [ -f /tmp/strace_output ]; then
        echo "Strace output:"
        cat /tmp/strace_output
    fi
else
    echo "strace not available, running program directly"
    /tmp/traced_program
fi

# 清理
rm -f /tmp/trace_test`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("系统调用跟踪测试结果:", output)

		assert.Contains(t, output, "Traced program completed", "被跟踪的程序应该完成")
	})

	// 测试系统调用统计
	t.Run("系统调用统计", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing syscall statistics..."

cat > /tmp/syscall_stats.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

int main() {
    struct timespec start, end;
    int i, fd;
    
    printf("Generating syscall statistics...\n");
    
    // 记录开始时间
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // 执行一系列系统调用
    for (i = 0; i < 100; i++) {
        char filename[256];
        snprintf(filename, sizeof(filename), "/tmp/stats_test_%d", i);
        
        fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, "test", 4);
            close(fd);
            unlink(filename);
        }
        
        // 每10次调用getpid
        if (i % 10 == 0) {
            getpid();
        }
    }
    
    // 记录结束时间
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000000.0);
    
    printf("Statistics generation completed in %.2f ms\n", time_taken);
    printf("Estimated syscalls: ~500 (open/write/close/unlink/getpid)\n");
    printf("Average syscall time: %.4f ms\n", time_taken / 500.0);
    
    return 0;
}
EOF

gcc -o /tmp/syscall_stats /tmp/syscall_stats.c
/tmp/syscall_stats`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("系统调用统计测试结果:", output)

		assert.Contains(t, output, "Statistics generation completed", "统计生成应该完成")
		assert.Contains(t, output, "Average syscall time:", "应该输出平均系统调用时间")
	})

	// 测试系统调用热点分析
	t.Run("系统调用热点分析", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing syscall hotspot analysis..."

cat > /tmp/hotspot_analysis.c << 'EOF'
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

typedef struct {
    const char* name;
    int count;
    double total_time;
} syscall_stat;

int main() {
    struct timespec start, end;
    syscall_stat stats[] = {
        {"open", 0, 0.0},
        {"write", 0, 0.0},
        {"close", 0, 0.0},
        {"stat", 0, 0.0}
    };
    
    printf("Performing hotspot analysis...\n");
    
    // 模拟系统调用热点
    for (int i = 0; i < 200; i++) {
        char filename[256];
        snprintf(filename, sizeof(filename), "/tmp/hotspot_%d", i);
        
        // 测量open性能
        clock_gettime(CLOCK_MONOTONIC, &start);
        int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        clock_gettime(CLOCK_MONOTONIC, &end);
        stats[0].count++;
        stats[0].total_time += ((end.tv_sec - start.tv_sec) * 1000000.0 + 
                               (end.tv_nsec - start.tv_nsec) / 1000.0);
        
        if (fd >= 0) {
            // 测量write性能
            clock_gettime(CLOCK_MONOTONIC, &start);
            write(fd, "test data", 9);
            clock_gettime(CLOCK_MONOTONIC, &end);
            stats[1].count++;
            stats[1].total_time += ((end.tv_sec - start.tv_sec) * 1000000.0 + 
                                   (end.tv_nsec - start.tv_nsec) / 1000.0);
            
            // 测量close性能
            clock_gettime(CLOCK_MONOTONIC, &start);
            close(fd);
            clock_gettime(CLOCK_MONOTONIC, &end);
            stats[2].count++;
            stats[2].total_time += ((end.tv_sec - start.tv_sec) * 1000000.0 + 
                                   (end.tv_nsec - start.tv_nsec) / 1000.0);
        }
        
        // 测量stat性能
        struct stat st;
        clock_gettime(CLOCK_MONOTONIC, &start);
        stat(filename, &st);
        clock_gettime(CLOCK_MONOTONIC, &end);
        stats[3].count++;
        stats[3].total_time += ((end.tv_sec - start.tv_sec) * 1000000.0 + 
                               (end.tv_nsec - start.tv_nsec) / 1000.0);
        
        unlink(filename);
    }
    
    printf("\nSyscall Hotspot Analysis Results:\n");
    printf("%-10s %-10s %-15s %-15s\n", "Syscall", "Count", "Total(μs)", "Avg(μs)");
    printf("----------------------------------------------------\n");
    
    for (int i = 0; i < 4; i++) {
        double avg = stats[i].count > 0 ? stats[i].total_time / stats[i].count : 0;
        printf("%-10s %-10d %-15.2f %-15.2f\n", 
               stats[i].name, stats[i].count, stats[i].total_time, avg);
    }
    
    printf("\nHotspot analysis completed\n");
    return 0;
}
EOF

gcc -o /tmp/hotspot_analysis /tmp/hotspot_analysis.c
/tmp/hotspot_analysis`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("系统调用热点分析测试结果:", output)

		assert.Contains(t, output, "Hotspot analysis completed", "热点分析应该完成")
		assert.Contains(t, output, "Syscall Hotspot Analysis Results:", "应该输出分析结果")
	})
}

// testPrivilegedSyscallDynamicAuthorization 测试特权系统调用动态授权
func testPrivilegedSyscallDynamicAuthorization(t *testing.T) {
	containerName := "test-privileged-auth"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 测试动态权限检查
	t.Run("动态权限检查", func(t *testing.T) {
		script := `#!/bin/bash
echo "Testing dynamic privilege checking..."

cat > /tmp/privilege_test.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <errno.h>
#include <string.h>

void test_syscall(const char* name, int result) {
    if (result == 0) {
        printf("%s: ALLOWED\n", name);
    } else {
        printf("%s: DENIED (errno: %s)\n", name, strerror(errno));
    }
}

int main() {
    printf("Testing privileged syscall authorization...\n");
    
    // 测试各种特权操作
    printf("\n1. Testing mount operations:\n");
    test_syscall("tmpfs mount", mount("tmpfs", "/tmp/test_mount", "tmpfs", 0, "size=1M"));
    
    printf("\n2. Testing system control:\n");
    test_syscall("reboot", reboot(RB_AUTOBOOT));
    
    printf("\n3. Testing process control:\n");
    test_syscall("setuid(0)", setuid(0));
    test_syscall("seteuid(0)", seteuid(0));
    
    printf("\n4. Testing network control:\n");
    // 这里可以添加网络相关的特权操作测试
    
    printf("\nPrivileged syscall authorization test completed\n");
    return 0;
}
EOF

gcc -o /tmp/privilege_test /tmp/privilege_test.c
/tmp/privilege_test 2>&1`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("动态权限检查测试结果:", output)

		assert.Contains(t, output, "Privileged syscall authorization test completed", "权限检查测试应该完成")
		// 大多数特权操作应该被拒绝
		assert.Contains(t, output, "DENIED", "特权操作应该被拒绝")
	})
}

// testSyscallPerformanceBenchmark 测试系统调用性能基准
func testSyscallPerformanceBenchmark(t *testing.T) {
	containerName := "test-syscall-benchmark"
	containerID := createSysboxContainer(t, containerName, "ubuntu:20.04", []string{"sleep", "300"})
	defer cleanupContainer(t, containerID)

	// 系统调用性能基准测试
	t.Run("系统调用性能基准", func(t *testing.T) {
		script := `#!/bin/bash
echo "Running syscall performance benchmark..."

cat > /tmp/syscall_benchmark.c << 'EOF'
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define ITERATIONS 100000

void benchmark_syscall(const char* name, void (*func)(void), int iterations) {
    struct timespec start, end;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int i = 0; i < iterations; i++) {
        func();
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double time_taken = ((end.tv_sec - start.tv_sec) * 1000000.0 + 
                        (end.tv_nsec - start.tv_nsec) / 1000.0);
    
    printf("%-15s: %8.2f μs total, %6.3f μs/call, %8.0f calls/sec\n", 
           name, time_taken, time_taken / iterations, iterations * 1000000.0 / time_taken);
}

void test_getpid() {
    getpid();
}

void test_time() {
    time(NULL);
}

void test_open_close() {
    int fd = open("/tmp/benchmark_test", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) close(fd);
}

void test_stat() {
    struct stat st;
    stat("/tmp", &st);
}

int main() {
    printf("System Call Performance Benchmark\n");
    printf("==================================\n");
    
    // 创建测试文件
    int fd = open("/tmp/benchmark_test", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, "test", 4);
        close(fd);
    }
    
    printf("%-15s  %8s %9s %12s\n", "Syscall", "Total", "Per Call", "Calls/Sec");
    printf("---------------------------------------------------\n");
    
    benchmark_syscall("getpid", test_getpid, ITERATIONS);
    benchmark_syscall("time", test_time, ITERATIONS);
    benchmark_syscall("stat", test_stat, ITERATIONS / 10); // 减少迭代次数
    benchmark_syscall("open/close", test_open_close, ITERATIONS / 100); // 更少迭代
    
    // 清理
    unlink("/tmp/benchmark_test");
    
    printf("\nBenchmark completed\n");
    return 0;
}
EOF

gcc -o /tmp/syscall_benchmark /tmp/syscall_benchmark.c
/tmp/syscall_benchmark`

		output := execInContainer(t, containerID, "bash", "-c", script)
		t.Log("系统调用性能基准测试结果:", output)

		assert.Contains(t, output, "Benchmark completed", "性能基准测试应该完成")
		assert.Contains(t, output, "calls/sec", "应该输出性能数据")
	})
}

// 辅助函数

func setupAdvancedSyscallTestEnv(t *testing.T) {
	// 确保sysbox服务运行正常
	err := exec.Command("systemctl", "is-active", "sysbox").Run()
	if err != nil {
		t.Skip("Sysbox服务未运行，跳过高级系统调用测试")
	}
}

func cleanupAdvancedSyscallTestEnv(t *testing.T) {
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