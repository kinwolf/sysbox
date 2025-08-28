package advanced

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// BuildResult 构建结果结构
type BuildResult struct {
	ImageID      string
	BuildTime    time.Duration
	ImageSize    int64
	LayerCount   int
	Success      bool
	ErrorMessage string
}

// TestImageBuilding 测试容器镜像构建功能
func TestImageBuilding(t *testing.T) {
	setupImageBuildingTestEnv(t)
	defer cleanupImageBuildingTestEnv(t)

	t.Run("基本Docker Build功能", func(t *testing.T) {
		testBasicDockerBuild(t)
	})

	t.Run("多阶段构建测试", func(t *testing.T) {
		testMultiStageBuild(t)
	})

	t.Run("Docker Buildx高级功能", func(t *testing.T) {
		testDockerBuildxAdvanced(t)
	})

	t.Run("BuildKit缓存优化", func(t *testing.T) {
		testBuildKitCacheOptimization(t)
	})

	t.Run("跨平台镜像构建", func(t *testing.T) {
		testCrossPlatformImageBuild(t)
	})

	t.Run("镜像安全扫描集成", func(t *testing.T) {
		testImageSecurityScanning(t)
	})

	t.Run("大型应用构建测试", func(t *testing.T) {
		testLargeApplicationBuild(t)
	})

	t.Run("构建性能优化测试", func(t *testing.T) {
		testBuildPerformanceOptimization(t)
	})
}

// testBasicDockerBuild 测试基本Docker Build功能
func testBasicDockerBuild(t *testing.T) {
	workDir := createTempBuildDir(t)
	defer os.RemoveAll(workDir)

	// 测试简单的单阶段构建
	t.Run("简单单阶段构建", func(t *testing.T) {
		dockerfile := `FROM ubuntu:20.04

# 设置非交互模式
ENV DEBIAN_FRONTEND=noninteractive

# 安装基本工具
RUN apt-get update && \
    apt-get install -y \
        curl \
        wget \
        vim \
        git \
        build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 创建测试文件
RUN echo "Hello from Sysbox build test" > /app/test.txt

# 设置入口点
CMD ["cat", "/app/test.txt"]`

		dockerfilePath := filepath.Join(workDir, "Dockerfile.simple")
		err := ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
		require.NoError(t, err)

		// 在sysbox容器内执行构建
		result := buildImageInSysbox(t, "test-simple-build", dockerfilePath, workDir)
		
		assert.True(t, result.Success, "简单构建应该成功")
		assert.NotEmpty(t, result.ImageID, "应该生成镜像ID")
		assert.Greater(t, result.ImageSize, int64(0), "镜像大小应该大于0")
		
		t.Logf("构建时间: %v, 镜像大小: %d bytes", result.BuildTime, result.ImageSize)
		
		// 测试构建的镜像
		testBuiltImage(t, result.ImageID, "Hello from Sysbox build test")
	})

	// 测试带有复杂依赖的构建
	t.Run("复杂依赖构建", func(t *testing.T) {
		dockerfile := `FROM node:16-alpine

WORKDIR /app

# 创建package.json
RUN echo '{ \
  "name": "sysbox-test-app", \
  "version": "1.0.0", \
  "main": "app.js", \
  "dependencies": { \
    "express": "^4.18.0", \
    "lodash": "^4.17.21" \
  } \
}' > package.json

# 安装依赖
RUN npm install

# 创建应用文件
RUN echo 'const express = require("express"); \
const _ = require("lodash"); \
const app = express(); \
app.get("/", (req, res) => { \
  res.json({message: "Hello from Sysbox Node.js app", data: _.range(1, 6)}); \
}); \
app.listen(3000, () => console.log("Server running on port 3000"));' > app.js

EXPOSE 3000
CMD ["node", "app.js"]`

		dockerfilePath := filepath.Join(workDir, "Dockerfile.nodejs")
		err := ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
		require.NoError(t, err)

		result := buildImageInSysbox(t, "test-nodejs-build", dockerfilePath, workDir)
		
		assert.True(t, result.Success, "Node.js构建应该成功")
		t.Logf("Node.js应用构建时间: %v", result.BuildTime)
		
		// 测试运行Node.js应用
		if result.Success {
			testNodeJSApp(t, result.ImageID)
		}
	})

	// 测试构建参数传递
	t.Run("构建参数传递", func(t *testing.T) {
		dockerfile := `FROM alpine:latest

ARG BUILD_VERSION=1.0
ARG BUILD_USER=sysbox

ENV APP_VERSION=${BUILD_VERSION}
ENV APP_USER=${BUILD_USER}

RUN echo "Building version: ${BUILD_VERSION}" > /build_info.txt && \
    echo "Built by: ${BUILD_USER}" >> /build_info.txt && \
    echo "Build timestamp: $(date)" >> /build_info.txt

CMD ["cat", "/build_info.txt"]`

		dockerfilePath := filepath.Join(workDir, "Dockerfile.args")
		err := ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
		require.NoError(t, err)

		// 测试带参数的构建
		buildArgs := map[string]string{
			"BUILD_VERSION": "2.0.0",
			"BUILD_USER":    "test-user",
		}
		
		result := buildImageWithArgs(t, "test-args-build", dockerfilePath, workDir, buildArgs)
		
		assert.True(t, result.Success, "带参数的构建应该成功")
		
		// 验证构建参数是否正确传递
		if result.Success {
			output := runImageAndGetOutput(t, result.ImageID)
			assert.Contains(t, output, "Building version: 2.0.0", "构建版本参数应该正确传递")
			assert.Contains(t, output, "Built by: test-user", "构建用户参数应该正确传递")
		}
	})
}

// testMultiStageBuild 测试多阶段构建
func testMultiStageBuild(t *testing.T) {
	workDir := createTempBuildDir(t)
	defer os.RemoveAll(workDir)

	// 测试Go应用的多阶段构建
	t.Run("Go应用多阶段构建", func(t *testing.T) {
		// 创建Go源码
		goCode := `package main

import (
	"fmt"
	"net/http"
	"log"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello from Sysbox Go app! Path: %s", r.URL.Path)
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}`

		goModContent := `module sysbox-go-app

go 1.19`

		err := ioutil.WriteFile(filepath.Join(workDir, "main.go"), []byte(goCode), 0644)
		require.NoError(t, err)
		
		err = ioutil.WriteFile(filepath.Join(workDir, "go.mod"), []byte(goModContent), 0644)
		require.NoError(t, err)

		dockerfile := `# 构建阶段
FROM golang:1.19-alpine AS builder

WORKDIR /app

# 复制Go模块文件
COPY go.mod go.sum* ./

# 下载依赖
RUN go mod download

# 复制源码
COPY . .

# 构建应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# 运行阶段
FROM alpine:latest

# 安装ca证书
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# 从构建阶段复制二进制文件
COPY --from=builder /app/main .

# 暴露端口
EXPOSE 8080

# 运行应用
CMD ["./main"]`

		dockerfilePath := filepath.Join(workDir, "Dockerfile.multistage")
		err = ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
		require.NoError(t, err)

		result := buildImageInSysbox(t, "test-multistage-go", dockerfilePath, workDir)
		
		assert.True(t, result.Success, "Go多阶段构建应该成功")
		
		if result.Success {
			// 验证最终镜像大小是否优化了
			assert.Less(t, result.ImageSize, int64(50*1024*1024), "多阶段构建的镜像应该相对较小")
			t.Logf("多阶段构建镜像大小: %d bytes", result.ImageSize)
			
			// 测试运行Go应用
			testGoApp(t, result.ImageID)
		}
	})

	// 测试复杂的多阶段构建（包含测试阶段）
	t.Run("包含测试阶段的多阶段构建", func(t *testing.T) {
		dockerfile := `# 基础阶段
FROM node:16-alpine AS base
WORKDIR /app
COPY package*.json ./

# 开发依赖阶段
FROM base AS dev-deps
RUN npm install

# 生产依赖阶段
FROM base AS prod-deps
RUN npm install --only=production

# 测试阶段
FROM dev-deps AS test
COPY . .
RUN npm test

# 构建阶段
FROM dev-deps AS build
COPY . .
RUN npm run build

# 生产阶段
FROM node:16-alpine AS production
WORKDIR /app
COPY --from=prod-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package*.json ./

EXPOSE 3000
CMD ["npm", "start"]`

		// 创建package.json
		packageJSON := `{
  "name": "sysbox-multistage-test",
  "version": "1.0.0",
  "scripts": {
    "test": "echo 'Running tests...' && echo 'All tests passed!'",
    "build": "mkdir -p dist && echo 'console.log(\"Built app\");' > dist/app.js",
    "start": "node dist/app.js"
  },
  "dependencies": {
    "express": "^4.18.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}`

		err := ioutil.WriteFile(filepath.Join(workDir, "package.json"), []byte(packageJSON), 0644)
		require.NoError(t, err)

		dockerfilePath := filepath.Join(workDir, "Dockerfile.complex-multistage")
		err = ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
		require.NoError(t, err)

		// 构建到测试阶段
		result := buildImageToStage(t, "test-multistage-with-test", dockerfilePath, workDir, "test")
		
		if result.Success {
			t.Log("测试阶段构建成功")
			
			// 构建到生产阶段
			prodResult := buildImageToStage(t, "test-multistage-prod", dockerfilePath, workDir, "production")
			assert.True(t, prodResult.Success, "生产阶段构建应该成功")
		}
	})
}

// testDockerBuildxAdvanced 测试Docker Buildx高级功能
func testDockerBuildxAdvanced(t *testing.T) {
	// 检查buildx是否可用
	if !isBuildxAvailable() {
		t.Skip("Docker Buildx不可用，跳过测试")
	}

	workDir := createTempBuildDir(t)
	defer os.RemoveAll(workDir)

	// 测试buildx基本功能
	t.Run("Buildx基本功能", func(t *testing.T) {
		dockerfile := `FROM alpine:latest
RUN apk add --no-cache curl
RUN echo "Buildx test successful" > /test.txt
CMD ["cat", "/test.txt"]`

		dockerfilePath := filepath.Join(workDir, "Dockerfile.buildx")
		err := ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
		require.NoError(t, err)

		result := buildImageWithBuildx(t, "test-buildx-basic", dockerfilePath, workDir)
		
		assert.True(t, result.Success, "Buildx构建应该成功")
		
		if result.Success {
			output := runImageAndGetOutput(t, result.ImageID)
			assert.Contains(t, output, "Buildx test successful", "Buildx构建的镜像应该正常运行")
		}
	})

	// 测试BuildKit前端功能
	t.Run("BuildKit前端功能", func(t *testing.T) {
		dockerfile := `# syntax=docker/dockerfile:1
FROM alpine:latest

# 使用高级mount功能
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache \
        curl \
        wget \
        git

# 使用heredoc语法
RUN <<EOF
echo "Using BuildKit advanced features"
echo "Cache mount and heredoc syntax working"
date > /build_time.txt
EOF

CMD ["cat", "/build_time.txt"]`

		dockerfilePath := filepath.Join(workDir, "Dockerfile.buildkit")
		err := ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
		require.NoError(t, err)

		result := buildImageWithBuildx(t, "test-buildkit-features", dockerfilePath, workDir)
		
		assert.True(t, result.Success, "BuildKit高级功能构建应该成功")
	})

	// 测试并行构建
	t.Run("并行构建测试", func(t *testing.T) {
		dockerfile := `FROM alpine:latest AS stage1
RUN sleep 2 && echo "Stage 1 complete" > /stage1.txt

FROM alpine:latest AS stage2
RUN sleep 2 && echo "Stage 2 complete" > /stage2.txt

FROM alpine:latest
COPY --from=stage1 /stage1.txt /
COPY --from=stage2 /stage2.txt /
RUN cat /stage1.txt /stage2.txt > /result.txt
CMD ["cat", "/result.txt"]`

		dockerfilePath := filepath.Join(workDir, "Dockerfile.parallel")
		err := ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
		require.NoError(t, err)

		start := time.Now()
		result := buildImageWithBuildx(t, "test-parallel-build", dockerfilePath, workDir)
		buildTime := time.Since(start)
		
		assert.True(t, result.Success, "并行构建应该成功")
		assert.Less(t, buildTime, 6*time.Second, "并行构建应该更快")
		
		t.Logf("并行构建时间: %v", buildTime)
	})
}

// testBuildKitCacheOptimization 测试BuildKit缓存优化
func testBuildKitCacheOptimization(t *testing.T) {
	workDir := createTempBuildDir(t)
	defer os.RemoveAll(workDir)

	// 创建一个基础Dockerfile
	dockerfile := `FROM alpine:latest

# 这一层很少变化，应该被缓存
RUN apk add --no-cache curl wget

# 这一层可能经常变化
COPY . /app/
WORKDIR /app

# 应用相关的操作
RUN echo "App version: 1.0.0" > version.txt

CMD ["cat", "version.txt"]`

	dockerfilePath := filepath.Join(workDir, "Dockerfile.cache")
	err := ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
	require.NoError(t, err)

	// 创建应用文件
	err = ioutil.WriteFile(filepath.Join(workDir, "app.txt"), []byte("test app content"), 0644)
	require.NoError(t, err)

	// 第一次构建
	t.Run("首次构建（建立缓存）", func(t *testing.T) {
		start := time.Now()
		result := buildImageInSysbox(t, "test-cache-first", dockerfilePath, workDir)
		firstBuildTime := time.Since(start)
		
		assert.True(t, result.Success, "首次构建应该成功")
		t.Logf("首次构建时间: %v", firstBuildTime)
		
		// 清理镜像但保持层缓存
		exec.Command("docker", "rmi", result.ImageID).Run()
	})

	// 第二次构建（应该使用缓存）
	t.Run("重复构建（使用缓存）", func(t *testing.T) {
		start := time.Now()
		result := buildImageInSysbox(t, "test-cache-second", dockerfilePath, workDir)
		secondBuildTime := time.Since(start)
		
		assert.True(t, result.Success, "重复构建应该成功")
		t.Logf("重复构建时间: %v", secondBuildTime)
		
		// 重复构建应该明显更快
		assert.Less(t, secondBuildTime.Milliseconds(), firstBuildTime.Milliseconds()/2, 
			"重复构建应该明显更快")
	})

	// 修改文件后的增量构建
	t.Run("增量构建（部分缓存失效）", func(t *testing.T) {
		// 修改应用文件
		err = ioutil.WriteFile(filepath.Join(workDir, "app.txt"), []byte("modified app content"), 0644)
		require.NoError(t, err)

		start := time.Now()
		result := buildImageInSysbox(t, "test-cache-incremental", dockerfilePath, workDir)
		incrementalBuildTime := time.Since(start)
		
		assert.True(t, result.Success, "增量构建应该成功")
		t.Logf("增量构建时间: %v", incrementalBuildTime)
	})
}

// testCrossPlatformImageBuild 测试跨平台镜像构建
func testCrossPlatformImageBuild(t *testing.T) {
	if !isBuildxAvailable() {
		t.Skip("Docker Buildx不可用，跳过跨平台构建测试")
	}

	workDir := createTempBuildDir(t)
	defer os.RemoveAll(workDir)

	dockerfile := `FROM alpine:latest

# 添加架构信息
RUN uname -m > /arch.txt && \
    echo "Platform: $(uname -s)/$(uname -m)" >> /arch.txt

CMD ["cat", "/arch.txt"]`

	dockerfilePath := filepath.Join(workDir, "Dockerfile.multiplatform")
	err := ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
	require.NoError(t, err)

	// 测试多平台构建
	t.Run("多平台镜像构建", func(t *testing.T) {
		platforms := []string{"linux/amd64", "linux/arm64"}
		
		for _, platform := range platforms {
			t.Run(fmt.Sprintf("构建%s平台镜像", platform), func(t *testing.T) {
				result := buildImageForPlatform(t, "test-multiplatform", dockerfilePath, workDir, platform)
				
				if result.Success {
					t.Logf("平台%s构建成功，耗时: %v", platform, result.BuildTime)
				} else {
					t.Logf("平台%s构建失败: %s", platform, result.ErrorMessage)
				}
			})
		}
	})

	// 测试manifest list创建
	t.Run("多架构Manifest创建", func(t *testing.T) {
		imageName := "test-multiarch-manifest:latest"
		
		// 尝试创建多架构manifest
		result := createMultiArchManifest(t, imageName, []string{"linux/amd64", "linux/arm64"}, dockerfilePath, workDir)
		
		if result {
			t.Log("多架构manifest创建成功")
			
			// 检查manifest内容
			output, err := exec.Command("docker", "manifest", "inspect", imageName).Output()
			if err == nil {
				manifest := string(output)
				assert.Contains(t, manifest, "amd64", "manifest应该包含amd64架构")
				t.Log("Manifest内容:", manifest)
			}
		}
	})
}

// testImageSecurityScanning 测试镜像安全扫描集成
func testImageSecurityScanning(t *testing.T) {
	workDir := createTempBuildDir(t)
	defer os.RemoveAll(workDir)

	// 创建一个可能有安全问题的镜像
	dockerfile := `FROM ubuntu:18.04

# 安装旧版本软件（可能有安全漏洞）
RUN apt-get update && \
    apt-get install -y \
        openssh-server \
        curl \
        wget

# 创建不安全的配置
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config

# 设置弱密码
RUN echo 'root:password123' | chpasswd

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]`

	dockerfilePath := filepath.Join(workDir, "Dockerfile.security-test")
	err := ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
	require.NoError(t, err)

	result := buildImageInSysbox(t, "test-security-scan", dockerfilePath, workDir)
	
	if !result.Success {
		t.Skip("无法构建测试镜像，跳过安全扫描测试")
	}

	// 测试基本安全检查
	t.Run("基本安全检查", func(t *testing.T) {
		// 检查镜像配置
		config := getImageConfig(t, result.ImageID)
		
		// 检查是否暴露了敏感端口
		assert.Contains(t, config, "22", "镜像暴露了SSH端口")
		
		// 检查用户配置
		if strings.Contains(config, "User") {
			t.Log("镜像用户配置:", config)
		}
	})

	// 测试漏洞扫描（如果工具可用）
	t.Run("漏洞扫描", func(t *testing.T) {
		// 尝试使用docker scan（如果可用）
		output, err := exec.Command("docker", "scan", result.ImageID).Output()
		if err == nil {
			scanResult := string(output)
			t.Log("安全扫描结果:", scanResult)
			
			// 检查是否发现了漏洞
			if strings.Contains(strings.ToLower(scanResult), "vulnerability") {
				t.Log("发现了安全漏洞")
			}
		} else {
			t.Log("Docker scan不可用，跳过详细漏洞扫描")
		}
		
		// 使用基本的安全检查
		securityIssues := performBasicSecurityCheck(t, result.ImageID)
		t.Logf("发现%d个基本安全问题", len(securityIssues))
		
		for _, issue := range securityIssues {
			t.Logf("安全问题: %s", issue)
		}
	})
}

// testLargeApplicationBuild 测试大型应用构建
func testLargeApplicationBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过大型应用构建测试（耗时较长）")
	}

	workDir := createTempBuildDir(t)
	defer os.RemoveAll(workDir)

	// 创建一个模拟的大型Java应用
	t.Run("大型Java应用构建", func(t *testing.T) {
		dockerfile := `FROM openjdk:11-jdk-slim AS build

WORKDIR /app

# 复制Maven wrapper和pom.xml
COPY mvnw pom.xml ./
COPY .mvn .mvn

# 下载依赖（这将被缓存）
RUN ./mvnw dependency:go-offline

# 复制源码
COPY src src

# 构建应用
RUN ./mvnw package -DskipTests

# 运行时镜像
FROM openjdk:11-jre-slim

WORKDIR /app

# 复制构建的jar文件
COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]`

		// 创建Maven wrapper
		mvnwContent := `#!/bin/bash
echo "Mock Maven wrapper for testing"
mkdir -p target
echo 'public class HelloWorld { public static void main(String[] args) { System.out.println("Hello World"); } }' > HelloWorld.java
javac HelloWorld.java
jar cfe target/app.jar HelloWorld HelloWorld.class`

		err := ioutil.WriteFile(filepath.Join(workDir, "mvnw"), []byte(mvnwContent), 0755)
		require.NoError(t, err)

		// 创建简单的pom.xml
		pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.sysbox.test</groupId>
    <artifactId>large-app</artifactId>
    <version>1.0.0</version>
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
    </properties>
</project>`

		err = ioutil.WriteFile(filepath.Join(workDir, "pom.xml"), []byte(pomContent), 0644)
		require.NoError(t, err)

		// 创建.mvn目录
		err = os.MkdirAll(filepath.Join(workDir, ".mvn"), 0755)
		require.NoError(t, err)

		// 创建src目录结构
		err = os.MkdirAll(filepath.Join(workDir, "src", "main", "java"), 0755)
		require.NoError(t, err)

		dockerfilePath := filepath.Join(workDir, "Dockerfile.java")
		err = ioutil.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
		require.NoError(t, err)

		start := time.Now()
		result := buildImageInSysbox(t, "test-large-java-app", dockerfilePath, workDir)
		buildTime := time.Since(start)
		
		assert.True(t, result.Success, "大型Java应用构建应该成功")
		t.Logf("大型Java应用构建时间: %v", buildTime)
		
		if result.Success {
			// 验证最终镜像
			output := runImageAndGetOutput(t, result.ImageID)
			t.Log("Java应用输出:", output)
		}
	})
}

// testBuildPerformanceOptimization 测试构建性能优化
func testBuildPerformanceOptimization(t *testing.T) {
	workDir := createTempBuildDir(t)
	defer os.RemoveAll(workDir)

	// 测试.dockerignore的影响
	t.Run("Dockerignore性能优化", func(t *testing.T) {
		// 创建大量无关文件
		for i := 0; i < 100; i++ {
			filename := filepath.Join(workDir, fmt.Sprintf("dummy_%d.txt", i))
			content := strings.Repeat("dummy content ", 1000)
			err := ioutil.WriteFile(filename, []byte(content), 0644)
			require.NoError(t, err)
		}

		dockerfile := `FROM alpine:latest
COPY needed.txt /
CMD ["cat", "/needed.txt"]`

		err := ioutil.WriteFile(filepath.Join(workDir, "Dockerfile.ignore"), []byte(dockerfile), 0644)
		require.NoError(t, err)

		err = ioutil.WriteFile(filepath.Join(workDir, "needed.txt"), []byte("This file is needed"), 0644)
		require.NoError(t, err)

		// 不使用dockerignore的构建
		start := time.Now()
		result1 := buildImageInSysbox(t, "test-no-dockerignore", filepath.Join(workDir, "Dockerfile.ignore"), workDir)
		timeWithoutIgnore := time.Since(start)

		// 创建.dockerignore
		dockerignoreContent := `dummy_*.txt
*.log
.git
node_modules`

		err = ioutil.WriteFile(filepath.Join(workDir, ".dockerignore"), []byte(dockerignoreContent), 0644)
		require.NoError(t, err)

		// 使用dockerignore的构建
		start = time.Now()
		result2 := buildImageInSysbox(t, "test-with-dockerignore", filepath.Join(workDir, "Dockerfile.ignore"), workDir)
		timeWithIgnore := time.Since(start)

		assert.True(t, result1.Success && result2.Success, "两次构建都应该成功")
		
		t.Logf("不使用.dockerignore构建时间: %v", timeWithoutIgnore)
		t.Logf("使用.dockerignore构建时间: %v", timeWithIgnore)
		
		// dockerignore应该提升性能
		if timeWithIgnore < timeWithoutIgnore {
			t.Log(".dockerignore成功优化了构建性能")
		}
	})

	// 测试层缓存优化
	t.Run("层缓存优化策略", func(t *testing.T) {
		// 优化前的Dockerfile（经常变化的内容在前面）
		dockerfileBad := `FROM node:16-alpine
COPY . .
RUN npm install
CMD ["npm", "start"]`

		// 优化后的Dockerfile（经常变化的内容在后面）
		dockerfileGood := `FROM node:16-alpine
COPY package*.json ./
RUN npm install
COPY . .
CMD ["npm", "start"]`

		// 创建package.json
		packageJSON := `{"name": "test-app", "version": "1.0.0", "dependencies": {"express": "^4.18.0"}}`
		err := ioutil.WriteFile(filepath.Join(workDir, "package.json"), []byte(packageJSON), 0644)
		require.NoError(t, err)

		err = ioutil.WriteFile(filepath.Join(workDir, "app.js"), []byte("console.log('test');"), 0644)
		require.NoError(t, err)

		// 测试优化前的构建
		err = ioutil.WriteFile(filepath.Join(workDir, "Dockerfile.bad"), []byte(dockerfileBad), 0644)
		require.NoError(t, err)

		start := time.Now()
		result1 := buildImageInSysbox(t, "test-bad-cache", filepath.Join(workDir, "Dockerfile.bad"), workDir)
		timeBadCache := time.Since(start)

		// 修改应用文件
		err = ioutil.WriteFile(filepath.Join(workDir, "app.js"), []byte("console.log('modified');"), 0644)
		require.NoError(t, err)

		// 再次构建（应该重新安装依赖）
		start = time.Now()
		buildImageInSysbox(t, "test-bad-cache-2", filepath.Join(workDir, "Dockerfile.bad"), workDir)
		timeBadCacheRebuild := time.Since(start)

		// 测试优化后的构建
		err = ioutil.WriteFile(filepath.Join(workDir, "Dockerfile.good"), []byte(dockerfileGood), 0644)
		require.NoError(t, err)

		start = time.Now()
		result2 := buildImageInSysbox(t, "test-good-cache", filepath.Join(workDir, "Dockerfile.good"), workDir)
		timeGoodCache := time.Since(start)

		// 修改应用文件（package.json不变）
		err = ioutil.WriteFile(filepath.Join(workDir, "app.js"), []byte("console.log('modified again');"), 0644)
		require.NoError(t, err)

		// 再次构建（应该使用npm install缓存）
		start = time.Now()
		buildImageInSysbox(t, "test-good-cache-2", filepath.Join(workDir, "Dockerfile.good"), workDir)
		timeGoodCacheRebuild := time.Since(start)

		t.Logf("优化前首次构建: %v, 重建: %v", timeBadCache, timeBadCacheRebuild)
		t.Logf("优化后首次构建: %v, 重建: %v", timeGoodCache, timeGoodCacheRebuild)

		assert.True(t, result1.Success && result2.Success, "构建都应该成功")
		
		// 优化后的重建应该明显更快
		if timeGoodCacheRebuild < timeBadCacheRebuild {
			t.Log("层缓存优化策略成功减少了重建时间")
		}
	})
}

// 辅助函数

func setupImageBuildingTestEnv(t *testing.T) {
	// 确保Docker和Sysbox运行正常
	err := exec.Command("docker", "version").Run()
	if err != nil {
		t.Skip("Docker不可用，跳过镜像构建测试")
	}

	err = exec.Command("systemctl", "is-active", "sysbox").Run()
	if err != nil {
		t.Skip("Sysbox服务未运行，跳过镜像构建测试")
	}
}

func cleanupImageBuildingTestEnv(t *testing.T) {
	// 清理构建产生的镜像和容器
	exec.Command("docker", "system", "prune", "-f").Run()
}

func createTempBuildDir(t *testing.T) string {
	tempDir, err := ioutil.TempDir("", "sysbox-build-test-")
	require.NoError(t, err)
	return tempDir
}

func buildImageInSysbox(t *testing.T, imageName, dockerfilePath, contextDir string) BuildResult {
	// 在sysbox容器内执行构建
	containerName := fmt.Sprintf("build-%s", imageName)
	
	// 创建构建容器
	args := []string{"run", "-d", "--runtime=sysbox-runc", "--name", containerName,
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"-v", fmt.Sprintf("%s:/build", contextDir),
		"docker:latest", "sleep", "300"}
	
	output, err := exec.Command("docker", args...).Output()
	if err != nil {
		return BuildResult{Success: false, ErrorMessage: err.Error()}
	}
	
	containerID := strings.TrimSpace(string(output))
	defer exec.Command("docker", "rm", "-f", containerID).Run()
	
	// 等待容器启动
	time.Sleep(3 * time.Second)
	
	// 执行构建
	start := time.Now()
	buildCmd := []string{"exec", containerID, "docker", "build", "-t", imageName, "-f", "/build/" + filepath.Base(dockerfilePath), "/build"}
	
	buildOutput, err := exec.Command("docker", buildCmd...).Output()
	buildTime := time.Since(start)
	
	if err != nil {
		return BuildResult{
			Success:      false,
			BuildTime:    buildTime,
			ErrorMessage: fmt.Sprintf("构建失败: %v, 输出: %s", err, string(buildOutput)),
		}
	}
	
	// 获取镜像ID
	imageID := extractImageIDFromBuildOutput(string(buildOutput))
	
	// 获取镜像大小
	var imageSize int64
	if imageID != "" {
		sizeOutput, err := exec.Command("docker", "exec", containerID, "docker", "image", "inspect", imageID, "--format", "{{.Size}}").Output()
		if err == nil {
			if size, err := strconv.ParseInt(strings.TrimSpace(string(sizeOutput)), 10, 64); err == nil {
				imageSize = size
			}
		}
	}
	
	return BuildResult{
		ImageID:   imageID,
		BuildTime: buildTime,
		ImageSize: imageSize,
		Success:   true,
	}
}

func buildImageWithArgs(t *testing.T, imageName, dockerfilePath, contextDir string, buildArgs map[string]string) BuildResult {
	containerName := fmt.Sprintf("build-%s", imageName)
	
	args := []string{"run", "-d", "--runtime=sysbox-runc", "--name", containerName,
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"-v", fmt.Sprintf("%s:/build", contextDir),
		"docker:latest", "sleep", "300"}
	
	output, err := exec.Command("docker", args...).Output()
	if err != nil {
		return BuildResult{Success: false, ErrorMessage: err.Error()}
	}
	
	containerID := strings.TrimSpace(string(output))
	defer exec.Command("docker", "rm", "-f", containerID).Run()
	
	time.Sleep(3 * time.Second)
	
	// 构建带参数的命令
	buildCmd := []string{"exec", containerID, "docker", "build", "-t", imageName}
	
	for key, value := range buildArgs {
		buildCmd = append(buildCmd, "--build-arg", fmt.Sprintf("%s=%s", key, value))
	}
	
	buildCmd = append(buildCmd, "-f", "/build/"+filepath.Base(dockerfilePath), "/build")
	
	start := time.Now()
	buildOutput, err := exec.Command("docker", buildCmd...).Output()
	buildTime := time.Since(start)
	
	if err != nil {
		return BuildResult{
			Success:      false,
			BuildTime:    buildTime,
			ErrorMessage: fmt.Sprintf("构建失败: %v", err),
		}
	}
	
	imageID := extractImageIDFromBuildOutput(string(buildOutput))
	
	return BuildResult{
		ImageID:   imageID,
		BuildTime: buildTime,
		Success:   true,
	}
}

func buildImageToStage(t *testing.T, imageName, dockerfilePath, contextDir, stage string) BuildResult {
	containerName := fmt.Sprintf("build-%s", imageName)
	
	args := []string{"run", "-d", "--runtime=sysbox-runc", "--name", containerName,
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"-v", fmt.Sprintf("%s:/build", contextDir),
		"docker:latest", "sleep", "300"}
	
	output, err := exec.Command("docker", args...).Output()
	if err != nil {
		return BuildResult{Success: false, ErrorMessage: err.Error()}
	}
	
	containerID := strings.TrimSpace(string(output))
	defer exec.Command("docker", "rm", "-f", containerID).Run()
	
	time.Sleep(3 * time.Second)
	
	buildCmd := []string{"exec", containerID, "docker", "build", "--target", stage, "-t", imageName, 
		"-f", "/build/" + filepath.Base(dockerfilePath), "/build"}
	
	start := time.Now()
	buildOutput, err := exec.Command("docker", buildCmd...).Output()
	buildTime := time.Since(start)
	
	return BuildResult{
		Success:   err == nil,
		BuildTime: buildTime,
		ImageID:   extractImageIDFromBuildOutput(string(buildOutput)),
	}
}

func buildImageWithBuildx(t *testing.T, imageName, dockerfilePath, contextDir string) BuildResult {
	start := time.Now()
	
	buildCmd := []string{"buildx", "build", "-t", imageName, "-f", dockerfilePath, contextDir}
	buildOutput, err := exec.Command("docker", buildCmd...).Output()
	buildTime := time.Since(start)
	
	if err != nil {
		return BuildResult{
			Success:      false,
			BuildTime:    buildTime,
			ErrorMessage: fmt.Sprintf("Buildx构建失败: %v", err),
		}
	}
	
	// 获取镜像ID
	imageID := extractImageIDFromBuildOutput(string(buildOutput))
	if imageID == "" {
		// 尝试从镜像名称获取ID
		output, err := exec.Command("docker", "images", "-q", imageName).Output()
		if err == nil {
			imageID = strings.TrimSpace(string(output))
		}
	}
	
	return BuildResult{
		ImageID:   imageID,
		BuildTime: buildTime,
		Success:   true,
	}
}

func buildImageForPlatform(t *testing.T, imageName, dockerfilePath, contextDir, platform string) BuildResult {
	start := time.Now()
	
	buildCmd := []string{"buildx", "build", "--platform", platform, "-t", fmt.Sprintf("%s-%s", imageName, strings.Replace(platform, "/", "-", -1)), 
		"-f", dockerfilePath, contextDir}
	
	buildOutput, err := exec.Command("docker", buildCmd...).Output()
	buildTime := time.Since(start)
	
	return BuildResult{
		Success:      err == nil,
		BuildTime:    buildTime,
		ErrorMessage: string(buildOutput),
	}
}

func createMultiArchManifest(t *testing.T, imageName string, platforms []string, dockerfilePath, contextDir string) bool {
	// 为每个平台构建镜像
	for _, platform := range platforms {
		platformTag := fmt.Sprintf("%s-%s", imageName, strings.Replace(platform, "/", "-", -1))
		result := buildImageForPlatform(t, imageName, dockerfilePath, contextDir, platform)
		if !result.Success {
			return false
		}
	}
	
	// 创建manifest list
	manifestCmd := []string{"manifest", "create", imageName}
	for _, platform := range platforms {
		platformTag := fmt.Sprintf("%s-%s", imageName, strings.Replace(platform, "/", "-", -1))
		manifestCmd = append(manifestCmd, platformTag)
	}
	
	err := exec.Command("docker", manifestCmd...).Run()
	return err == nil
}

func testBuiltImage(t *testing.T, imageID, expectedOutput string) {
	output := runImageAndGetOutput(t, imageID)
	assert.Contains(t, output, expectedOutput, "镜像输出应该包含期望内容")
}

func testNodeJSApp(t *testing.T, imageID string) {
	// 运行Node.js应用容器
	containerName := "test-nodejs-app"
	
	args := []string{"run", "-d", "--name", containerName, "-p", "3000:3000", imageID}
	_, err := exec.Command("docker", args...).Run()
	defer exec.Command("docker", "rm", "-f", containerName).Run()
	
	if err != nil {
		t.Logf("无法运行Node.js应用: %v", err)
		return
	}
	
	// 等待应用启动
	time.Sleep(5 * time.Second)
	
	// 测试应用响应
	output, err := exec.Command("curl", "-s", "http://localhost:3000").Output()
	if err == nil {
		assert.Contains(t, string(output), "Hello from Sysbox Node.js app", "Node.js应用应该正常响应")
	}
}

func testGoApp(t *testing.T, imageID string) {
	containerName := "test-go-app"
	
	args := []string{"run", "-d", "--name", containerName, "-p", "8080:8080", imageID}
	_, err := exec.Command("docker", args...).Run()
	defer exec.Command("docker", "rm", "-f", containerName).Run()
	
	if err != nil {
		t.Logf("无法运行Go应用: %v", err)
		return
	}
	
	time.Sleep(3 * time.Second)
	
	output, err := exec.Command("curl", "-s", "http://localhost:8080/test").Output()
	if err == nil {
		assert.Contains(t, string(output), "Hello from Sysbox Go app", "Go应用应该正常响应")
	}
}

func runImageAndGetOutput(t *testing.T, imageID string) string {
	output, err := exec.Command("docker", "run", "--rm", imageID).Output()
	if err != nil {
		t.Logf("运行镜像失败: %v", err)
		return ""
	}
	return string(output)
}

func getImageConfig(t *testing.T, imageID string) string {
	output, err := exec.Command("docker", "inspect", imageID).Output()
	if err != nil {
		return ""
	}
	return string(output)
}

func performBasicSecurityCheck(t *testing.T, imageID string) []string {
	var issues []string
	
	// 检查镜像配置
	configJSON := getImageConfig(t, imageID)
	
	// 解析JSON配置
	var configs []map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &configs); err == nil && len(configs) > 0 {
		config := configs[0]
		
		// 检查用户配置
		if configData, ok := config["Config"].(map[string]interface{}); ok {
			if user, exists := configData["User"].(string); !exists || user == "" || user == "root" {
				issues = append(issues, "镜像以root用户运行")
			}
			
			// 检查暴露的端口
			if exposedPorts, exists := configData["ExposedPorts"].(map[string]interface{}); exists {
				for port := range exposedPorts {
					if strings.Contains(port, "22/") {
						issues = append(issues, "镜像暴露SSH端口(22)")
					}
				}
			}
		}
	}
	
	return issues
}

func extractImageIDFromBuildOutput(output string) string {
	// 尝试提取镜像ID
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Successfully built") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[2]
			}
		}
		if match := regexp.MustCompile(`sha256:([a-f0-9]+)`).FindStringSubmatch(line); len(match) > 1 {
			return match[1]
		}
	}
	return ""
}

func isBuildxAvailable() bool {
	err := exec.Command("docker", "buildx", "version").Run()
	return err == nil
}