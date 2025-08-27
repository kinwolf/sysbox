#!/bin/bash

echo "=== Sysbox 核心测试文件验证 ==="
echo

# 检查测试文件是否存在
test_files=(
    "runtime_core_test.go"
    "fs_virtualization_test.go"
    "manager_service_test.go"
    "dind_workflow_test.go"
    "syscall_interception_test.go"
    "security_isolation_test.go"
    "cgroup_management_test.go"
    "kind_workflow_test.go"
    "container_lifecycle_test.go"
    "ipc_communication_test.go"
    "network_isolation_test.go"
    "mount_namespace_test.go"
)

echo "📁 检查测试文件存在性:"
missing_files=0
total_lines=0
total_test_functions=0

for file in "${test_files[@]}"; do
    if [ -f "$file" ]; then
        lines=$(wc -l < "$file")
        test_funcs=$(grep -c "func Test" "$file")
        total_lines=$((total_lines + lines))
        total_test_functions=$((total_test_functions + test_funcs))
        echo "  ✅ $file - $lines 行, $test_funcs 个测试函数"
    else
        echo "  ❌ $file - 文件不存在"
        missing_files=$((missing_files + 1))
    fi
done

echo
echo "📊 统计信息:"
echo "  • 总文件数: ${#test_files[@]}"
echo "  • 存在文件: $((${#test_files[@]} - missing_files))"
echo "  • 缺失文件: $missing_files"
echo "  • 总代码行数: $total_lines"
echo "  • 总测试函数: $total_test_functions"

# 检查语法结构
echo
echo "🔍 检查基本语法结构:"

syntax_errors=0
for file in "${test_files[@]}"; do
    if [ -f "$file" ]; then
        echo "  检查 $file..."
        
        # 检查包声明
        if ! grep -q "package core" "$file"; then
            echo "    ❌ 缺少正确的包声明 'package core'"
            syntax_errors=$((syntax_errors + 1))
        fi
        
        # 检查必要的导入
        if ! grep -q "testing" "$file"; then
            echo "    ❌ 缺少 testing 包导入"
            syntax_errors=$((syntax_errors + 1))
        fi
        
        if ! grep -q "testify" "$file"; then
            echo "    ⚠️  建议导入 testify 包用于断言"
        fi
        
        # 检查测试函数
        if ! grep -q "func Test" "$file"; then
            echo "    ❌ 没有找到测试函数"
            syntax_errors=$((syntax_errors + 1))
        fi
        
        # 检查设置和清理函数
        if grep -q "setup.*TestEnv" "$file" && grep -q "cleanup.*TestEnv" "$file"; then
            echo "    ✅ 找到设置和清理函数"
        else
            echo "    ⚠️  建议添加测试环境设置和清理函数"
        fi
        
        # 检查defer语句
        if grep -q "defer cleanup" "$file" || grep -q "defer clean" "$file"; then
            echo "    ✅ 找到资源清理defer语句"
        else
            echo "    ⚠️  建议在测试中使用defer进行资源清理"
        fi
    fi
done

# 检查依赖文件
echo
echo "📦 检查依赖文件:"

if [ -f "go.mod" ]; then
    echo "  ✅ go.mod 存在"
    if grep -q "testify" go.mod; then
        echo "  ✅ testify 依赖已添加"
    else
        echo "  ⚠️  testify 依赖未在 go.mod 中找到"
    fi
else
    echo "  ❌ go.mod 不存在"
fi

if [ -f "README.md" ]; then
    echo "  ✅ README.md 存在"
else
    echo "  ⚠️  建议添加 README.md 文档"
fi

# 生成报告
echo
echo "📋 验证报告:"
if [ $missing_files -eq 0 ] && [ $syntax_errors -eq 0 ]; then
    echo "  🎉 所有测试文件验证通过！"
    echo "  ✅ 12个测试文件全部存在"
    echo "  ✅ 基本语法结构正确"
    echo "  ✅ 总计 $total_test_functions 个测试函数"
    echo "  ✅ 总计 $total_lines 行测试代码"
else
    echo "  🔧 发现问题需要修复:"
    if [ $missing_files -gt 0 ]; then
        echo "    • $missing_files 个文件缺失"
    fi
    if [ $syntax_errors -gt 0 ]; then
        echo "    • $syntax_errors 个语法问题"
    fi
fi

echo
echo "🚀 运行测试的前置条件:"
echo "  1. 安装并配置 Docker"
echo "  2. 安装并配置 Sysbox 运行时"
echo "  3. 确保当前用户有 Docker 权限"
echo "  4. 系统为 Linux (Ubuntu 20.04+ 推荐)"

echo
echo "💡 推荐的测试运行命令:"
echo "  # 检查环境"
echo "  docker info | grep sysbox-runc"
echo
echo "  # 运行单个测试文件"
echo "  go test -v ./runtime_core_test.go"
echo
echo "  # 运行所有核心测试"
echo "  go test -v ./..."
echo
echo "  # 运行特定测试函数"
echo "  go test -v -run TestSysboxRuntimeCore"
echo
echo "  # 运行测试并生成覆盖率报告"
echo "  go test -v -coverprofile=coverage.out ./..."
echo "  go tool cover -html=coverage.out"

echo
echo "=== 验证完成 ==="