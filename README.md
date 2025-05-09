# Luban TUI Toolkit

基于 FTXUI 库开发的终端用户界面工具包，用于串口通信、摄像头控制和系统信息显示。

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
    timg
```

### 串口访问权限设置

```bash
# 将当前用户添加到 dialout 组以访问串口设备
sudo usermod -a -G dialout $USER
# 重新登录以使更改生效
```

### 摄像头访问权限设置

```bash
# 将当前用户添加到 video 组以访问摄像头设备
sudo usermod -a -G video $USER
# 重新登录以使更改生效
```

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
  - 波特率可配置

- 摄像头控制
  - USB 摄像头自动检测
  - 支持查看设备信息
  - 支持拍照功能
  - 图片预览（使用 timg）

- 系统信息显示
  - CPU 使用率
  - 内存使用情况
  - 磁盘使用情况

## 故障排除

1. 串口访问权限问题：
   - 确保用户在 dialout 组中
   - 检查串口设备权限：`ls -l /dev/ttyUSB*`

2. 摄像头访问问题：
   - 确保用户在 video 组中
   - 检查摄像头设备：`ls -l /dev/video*`
   - 使用 `v4l2-ctl --list-devices` 查看可用设备

3. 编译错误：
   - 确保已安装所有必需的开发包
   - 检查 CMake 版本是否满足要求
   - 查看编译日志获取详细错误信息

## 日志文件

- `debug.log`: 程序运行时的调试信息
- `development.log`: 开发过程中的更新记录

## 许可证

[待添加许可证信息]

## 贡献指南

[待添加贡献指南] 