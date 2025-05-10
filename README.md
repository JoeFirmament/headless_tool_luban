# Board_Check_Toolkit

基于 FTXUI 库开发的终端用户界面工具包，用于检查开发板的串口通信、摄像头控制和系统信息显示。

## 开发环境信息

- 操作系统：Linux (已在 Ubuntu 20.04 LTS 和 Debian 11 上测试)
- CPU 架构：支持 x86_64 和 ARM64
- 编译器要求：GCC 9.0+ 或 Clang 10.0+
- CMake 版本：3.11+

## 系统依赖

### 必需的系统包

```bash
# Debian/Ubuntu 系统
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libv4l-dev \
    v4l-utils \
    libudev-dev \
    libusb-1.0-0-dev \
    timg \
    net-tools \
    iw
```

### 命令行工具说明

本程序使用了以下命令行工具：

1. **v4l2-ctl** (来自 v4l-utils 包)
   - 用途：用于控制视频设备、列出设备信息、设置视频格式和捕获图像
   - 主要功能：
     - 列出可用视频设备：`v4l2-ctl --list-devices`
     - 查询设备支持的格式：`v4l2-ctl --device /dev/videoX --list-formats-ext`
     - 捕获图像：`v4l2-ctl --device /dev/videoX --set-fmt-video=width=W,height=H --stream-mmap --stream-count=1 --stream-to=output.jpg`

2. **timg**
   - 用途：在终端中显示图像
   - 安装：`sudo apt-get install timg`
   - 使用方法：`timg image.jpg`

3. **系统信息工具**
   - `hostname`：获取主机名
   - `uptime`：获取系统运行时间
   - `free`：显示内存使用情况
   - `lscpu`：显示CPU信息
   - `ip`：显示网络接口信息
   - `iwgetid`：获取当前WiFi SSID

### 串口访问权限设置



### 摄像头访问权限设置



## 编译安装

1. 克隆项目代码：

```bash
git clone https://github.com/your-username/Luban_tui_toolkit.git
cd Luban_tui_toolkit
```

2. 初始化并更新子模块：

```bash
git submodule update --init --recursive
```

3. 编译项目：

```bash
# 使用提供的编译脚本
./compile.sh
```

或者手动编译：

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

## 运行程序

```bash
# 需要 root 权限运行以访问硬件设备
sudo ./luban_toolkit_tui
```

## 功能特性

- 串口通信
  - 自动检测可用串口设备
  - 支持连接/断开操作
  - 实时数据显示
  - 波特率已配置为115200

- 摄像头控制
  - USB 摄像头自动检测出USB 摄像头
  - 支持查看设备信息
  - 支持拍照功能
  - 图片预览（使用 timg）

- 系统信息显示
  - CPU 使用率
  - 内存使用情况
  - 磁盘使用情况等

## 故障排除

1. 串口访问权限问题：
   - 确保用户以root身份运行程序


2. 摄像头访问问题：
   - 检查摄像头设备：`ls -l /dev/video*`
   - 使用 `v4l2-ctl --list-devices` 查看可用设备
   - 检查 v4l2-ctl 是否正确安装：`which v4l2-ctl`
   - 测试摄像头功能：`v4l2-ctl --device /dev/videoX --set-fmt-video=width=640,height=480 --stream-mmap --stream-count=1 --stream-to=test.jpg`

3. 图像显示问题：
   - 确保 timg 已正确安装：`which timg`
   - 如果 timg 无法显示图像，可以尝试使用其他工具：`display test.jpg` (需要安装 ImageMagick)
   - 检查图像文件是否有效：`file test.jpg`

4. 系统信息获取问题：
   - 检查网络工具是否安装：`which ip iwgetid`
   - 如果某些系统信息无法获取，可能需要安装额外的工具：`sudo apt-get install net-tools iw`

5. 编译错误：
   - 确保已安装所有必需的开发包
   - 检查 CMake 版本是否满足要求：`cmake --version`
   - 查看编译日志获取详细错误信息

## 日志文件

- `debug.log`: 程序运行时的调试信息
- `development.log`: 开发过程中的更新记录

## 命令执行机制

本程序使用了安全的命令执行机制，具有以下特点：

1. **超时控制**：所有外部命令执行都有超时限制，防止程序因命令执行卡住
2. **非阻塞读取**：使用非阻塞 I/O 和 poll 机制读取命令输出
3. **错误处理**：捕获并记录命令执行过程中的错误
4. **权限检查**：在执行需要特权的命令前检查 root 权限

主要命令执行函数 `exec_command` 支持以下参数：
- 命令字符串
- 超时时间（毫秒）
- 是否忽略非零退出码

