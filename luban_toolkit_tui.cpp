#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

// 标准库头文件
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <regex>
#include <set>
#include <sstream>
#include <csignal>
#include <iostream>
#include <array>
#include <sys/wait.h>
#include <poll.h>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <fstream>
#include <iomanip> // For std::put_time
#include <algorithm> // For std::min
#include <cctype> // For std::isspace

using namespace ftxui;

// --- 全局变量和信号处理 ---
ftxui::ScreenInteractive* global_screen_ptr = nullptr;
std::atomic<bool> sigterm_received(false);

// 全局日志向量和互斥锁，用于线程安全访问
std::vector<std::string> logs;
std::mutex logs_mutex;

// 用于保护终端输出的互斥锁
std::mutex cout_mutex;

// 用于保护共享状态变量（设备列表、系统信息等）的互斥锁
std::mutex state_mutex;

// 文件日志互斥锁
std::mutex file_log_mutex;

// 写入调试日志到文件
void write_debug_log(const std::string& message) {
    std::lock_guard<std::mutex> lock(file_log_mutex);
    std::ofstream log_file("debug.log", std::ios::app);
    if (!log_file.is_open()) {
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cerr << "错误: 无法打开 debug.log 文件进行写入!" << std::endl;
        return;
    }
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buffer;
    // 使用 localtime_r 是线程安全的版本
    if (localtime_r(&now_c, &tm_buffer)) {
        log_file << std::put_time(&tm_buffer, "%Y-%m-%d %H:%M:%S") << " " << message << std::endl;
    } else {
        log_file << "时间获取失败: " << message << std::endl;
    }
    log_file.close();
}

// 清空调试日志文件
void clear_debug_log() {
    std::lock_guard<std::mutex> lock(file_log_mutex);
    std::ofstream log_file("debug.log", std::ios::trunc);
    if (!log_file.is_open()) {
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cerr << "错误: 无法打开 debug.log 文件进行清空!" << std::endl;
        return;
    }
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
     std::tm tm_buffer;
    if (localtime_r(&now_c, &tm_buffer)) {
        log_file << std::put_time(&tm_buffer, "%Y-%m-%d %H:%M:%S") << " === 新会话开始 ===" << std::endl;
    } else {
         log_file << "时间获取失败: === 新会话开始 ===" << std::endl;
    }
    log_file.close();
}

// 信号处理函数
void handle_terminate_signal(int /*signal*/) {
    sigterm_received = true;
    // 如果全局屏幕指针有效，发送一个事件唤醒主循环
    if (global_screen_ptr) {
        global_screen_ptr->PostEvent(ftxui::Event::Custom); // 使用自定义事件类型
    }
}

// --- 工具函数 ---

// 检查是否具有 root 权限
bool has_root_privileges() {
    return geteuid() == 0;
}

// 执行系统命令并返回结果，同时记录日志和终端调试信息
// 改进：使用非阻塞读取和 poll 实现超时，并可选择忽略非零退出码
std::string exec_command(const std::string& cmd, int timeout_ms = 5000, bool ignore_nonzero_exit = false) {
    write_debug_log("开始执行命令: " + cmd + " (超时: " + std::to_string(timeout_ms) + "ms, 忽略非零退出码: " + (ignore_nonzero_exit ? "true" : "false") + ")");

    std::array<char, 128> buffer;
    std::string result;

    // 将标准错误重定向到标准输出，以便一起捕获
    std::string full_cmd = cmd + " 2>&1";

    write_debug_log("执行完整命令: " + full_cmd);
    FILE* pipe = popen(full_cmd.c_str(), "r");
    if (!pipe) {
        write_debug_log("错误: popen() 调用失败!");
        return "错误: popen() 调用失败!";
    }

    // 将管道的文件描述符设置为非阻塞模式
    int fd = fileno(pipe);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    write_debug_log("设置管道为非阻塞模式");

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;

    auto start_time = std::chrono::steady_clock::now();
    bool timed_out = false;

    while (true) {
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);
        int remaining_timeout = timeout_ms - static_cast<int>(elapsed.count());

        if (remaining_timeout <= 0) {
            timed_out = true;
            write_debug_log("命令执行超时");
            break;
        }

        // Poll with remaining timeout
        int poll_ret = poll(&pfd, 1, remaining_timeout);

        if (poll_ret > 0) {
            if (pfd.revents & POLLIN) {
                // Data is available, read all of it in non-blocking mode
                ssize_t n;
                while ((n = read(fd, buffer.data(), buffer.size() - 1)) > 0) {
                    buffer[n] = '\0';
                    result += buffer.data();
                    // 避免日志过长，只记录读取到的数据片段
                    write_debug_log("读取到数据 (片段): " + std::string(buffer.data()).substr(0, std::min((size_t)50, (size_t)n)) + "...");
                }
                if (n == 0) {
                    // End of file (pipe closed by child process)
                    write_debug_log("读取完成 (EOF)");
                    break; // Exit the main loop
                } else if (n < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    // Error other than EAGAIN/EWOULDBLOCK
                    std::string error_msg = "错误: 从管道读取数据失败: " + std::string(strerror(errno));
                    write_debug_log(error_msg);
                    pclose(pipe);
                    return error_msg;
                }
                // If n < 0 and EAGAIN/EWOULDBLOCK, no data currently available, continue polling
            } else if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                write_debug_log("管道错误或关闭 (POLLERR/POLLHUP/POLLNVAL)");
                 // Attempt to read any remaining data before breaking
                 ssize_t n;
                 while ((n = read(fd, buffer.data(), buffer.size() - 1)) > 0) {
                     buffer[n] = '\0';
                     result += buffer.data();
                     write_debug_log("读取到剩余数据 (片段): " + std::string(buffer.data()).substr(0, std::min((size_t)50, (size_t)n)) + "...");
                 }
                 if (n < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                     std::string error_msg = "错误: 从管道读取剩余数据失败: " + std::string(strerror(errno));
                     write_debug_log(error_msg);
                     pclose(pipe);
                     return error_msg;
                 }
                break; // Exit the main loop
            }
        } else if (poll_ret == 0) {
            // Timeout occurred
            timed_out = true;
            write_debug_log("poll() 超时");
            break; // Exit the main loop on timeout
        } else if (errno != EINTR) {
            // poll returned an error other than EINTR
            std::string error_msg = "错误: poll() 调用失败: " + std::string(strerror(errno));
            write_debug_log(error_msg);
            pclose(pipe);
            return error_msg;
        }
        // If poll_ret < 0 and errno == EINTR, continue loop
    }

    // Even if timed out or pipe error, need to call pclose to clean up resources
    int rc = pclose(pipe);
    int exit_status = -1;
    if (WIFEXITED(rc)) {
        exit_status = WEXITSTATUS(rc);
        write_debug_log("命令退出状态码: " + std::to_string(exit_status));
    } else {
         write_debug_log("命令未正常退出");
    }


    if (timed_out) {
         write_debug_log("命令执行结果: 超时");
         // If timed out, return timeout error regardless of partial output
         return "错误: 命令执行超时";
    }

    // Check pclose return value unless ignoring nonzero exit
    if (rc != 0 && !ignore_nonzero_exit) {
        std::string error;
        if (WIFEXITED(rc)) {
            error = "错误: 命令退出状态码 " + std::to_string(WEXITSTATUS(rc)) + ": " + result;
        } else {
            error = "错误: 命令执行失败: " + result;
        }
        write_debug_log("命令执行结果 (错误): " + error);
        return error;
    }

    // Remove trailing newline if present
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }

    write_debug_log("命令执行完成，结果长度: " + std::to_string(result.length()) + " 字节");
    return result;
}

// --- 设备查找函数 ---

struct VideoDeviceInfo {
    std::string path;
    std::vector<std::string> resolutions;
};

// 查找 USB 视频设备
std::vector<VideoDeviceInfo> find_video_devices() {
    write_debug_log("开始查找 USB 视频设备");
    std::vector<VideoDeviceInfo> devices;

    if (!has_root_privileges()) {
        write_debug_log("错误: 没有 root 权限，无法查找 USB 视频设备");
        return devices;
    }

    write_debug_log("执行 v4l2-ctl --list-devices 命令");
    std::string list_devices_cmd = "v4l2-ctl --list-devices 2>/dev/null";
    // 对 list-devices 命令忽略非零退出码，因为它可能因个别设备问题而返回非零
    std::string list_devices_result = exec_command(list_devices_cmd, 5000, true);

    // 即使忽略了非零退出码，如果 exec_command 返回的是表示超时的错误字符串，也需要处理
    if (list_devices_result.substr(0, 5) == "错误:") {
         write_debug_log("执行 v4l2-ctl --list-devices 失败 (可能超时)");
         return devices;
    }

    write_debug_log("v4l2-ctl --list-devices 输出:\n" + list_devices_result); // Log full output
    std::istringstream iss(list_devices_result);
    std::string line;

    std::vector<std::string> usb_video_paths;

    // Regex to find lines containing "(usb-"
    std::regex usb_device_desc_regex(".*\\(usb-.*\\):");

    // Regex to find /dev/videoX paths on indented lines
    std::regex indented_device_path_regex("^\\s*(\\/dev\\/video\\d+)$");
    std::smatch indented_device_path_match;

    bool processing_usb_device_group = false;

    // Iterate through lines to find USB devices and their video nodes
    iss.clear(); // Clear any previous state
    iss.seekg(0); // Rewind to the beginning of the stream

    while (std::getline(iss, line)) {
        // Check if this line is a device description line containing "(usb-"
        if (std::regex_search(line, usb_device_desc_regex)) {
            processing_usb_device_group = true;
            write_debug_log("进入潜在 USB 设备组: " + line);
        } else if (processing_usb_device_group) {
            // If we are processing a potential USB device group, check for indented /dev/videoX lines
            if (std::regex_match(line, indented_device_path_match, indented_device_path_regex) && indented_device_path_match.size() > 1) {
                 std::string device_path = indented_device_path_match[1].str();
                 usb_video_paths.push_back(device_path);
                 write_debug_log("找到 USB 视频设备路径: " + device_path + " (在 USB 设备组下)");
            } else if (!line.empty() && !std::isspace(static_cast<unsigned char>(line[0]))) {
                 // Encountered a non-indented, non-empty line, indicates end of the current device group
                 // Use static_cast to avoid issues with negative char values and isspace
                 processing_usb_device_group = false;
                 write_debug_log("结束处理当前 USB 设备组 (遇到非缩进行): " + line);
            } else if (line.empty()) {
                 // Encountered an empty line, also indicates end of the current device group
                 processing_usb_device_group = false;
                 write_debug_log("结束处理当前 USB 设备组 (遇到空行)");
            }
        }
    }

    // Remove duplicates just in case
    std::sort(usb_video_paths.begin(), usb_video_paths.end());
    usb_video_paths.erase(std::unique(usb_video_paths.begin(), usb_video_paths.end()), usb_video_paths.end());

    write_debug_log("找到 " + std::to_string(usb_video_paths.size()) + " 个 USB 视频设备路径 (去重后)");

    // For each found USB video device, query its resolutions
    for (const auto& device_path : usb_video_paths) {
        write_debug_log("查询 USB 设备分辨率: " + device_path);
        // Do NOT ignore nonzero exit code for list-formats-ext command
        std::string check_cmd = "timeout 2 v4l2-ctl --device " + device_path + " --list-formats-ext 2>/dev/null";
        std::string check_result = exec_command(check_cmd, 3000, false); // Do NOT ignore nonzero exit code

        // Add debug log for the result of list-formats-ext
        write_debug_log("v4l2-ctl --device " + device_path + " --list-formats-ext output:\n" + check_result);

        // --- Debugging check_result ---
        write_debug_log("Debugging check_result for " + device_path);
        write_debug_log("check_result length: " + std::to_string(check_result.length()));
        write_debug_log("check_result starts with: '" + check_result.substr(0, std::min((size_t)50, check_result.length())) + "'");

        // Use regex to find "Size: (Discrete|Stepwise) (\d+x\d+)" to confirm format support
        std::regex resolution_line_regex("Size: (Discrete|Stepwise) (\\d+x\\d+)");
        bool resolution_found_by_regex = std::regex_search(check_result, resolution_line_regex);

        write_debug_log("Regex search for \"Size: (Discrete|Stepwise) (\\d+x\\d+)\" returned: " + std::string(resolution_found_by_regex ? "true" : "false"));

        // Also print raw bytes of the relevant part of the string for debugging
        size_t debug_len = std::min((size_t)200, check_result.length()); // Print up to 200 bytes
        std::stringstream hex_dump;
        hex_dump << "Raw bytes (first " << debug_len << "): ";
        for (size_t i = 0; i < debug_len; ++i) {
            hex_dump << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(check_result[i])) << " ";
        }
        write_debug_log(hex_dump.str());
        // --- End Debugging ---


        // Check if the command executed successfully and at least one resolution was found
        bool command_successful_and_resolution_found = (check_result.substr(0, 5) != "错误:" && resolution_found_by_regex);
        write_debug_log("检查结果: command_successful_and_resolution_found = " + std::string(command_successful_and_resolution_found ? "true" : "false"));


        if (command_successful_and_resolution_found) {
            write_debug_log("设备 " + device_path + " 支持视频格式 (找到分辨率)");
            VideoDeviceInfo info;
            info.path = device_path;

            std::istringstream format_stream(check_result);
            std::string format_line;
            // Modified regex to match resolutions after Discrete or Stepwise
            std::regex res_regex("Size: (Discrete|Stepwise) (\\d+x\\d+)");
            std::smatch res_match;

            while (std::getline(format_stream, format_line)) {
                // Add debug log for each line being checked for resolution
                // write_debug_log("Checking line for resolution: " + format_line);
                if (std::regex_search(format_line, res_match, res_regex) && res_match.size() > 2) {
                    info.resolutions.push_back(res_match[2].str());
                    write_debug_log("找到分辨率: " + res_match[2].str() + " (匹配行: " + format_line + ")");
                }
            }

            write_debug_log("设备 " + device_path + " 找到分辨率数量: " + std::to_string(info.resolutions.size()));

            if (!info.resolutions.empty()) {
                devices.push_back(info);
                write_debug_log("添加设备 " + device_path + " 到列表，支持 " +
                              std::to_string(info.resolutions.size()) + " 种分辨率");
            } else {
                write_debug_log("设备 " + device_path + " 未找到有效分辨率，跳过 (未提取到分辨率)");
            }
        } else {
            write_debug_log("设备 " + device_path + " 不支持视频格式或查询失败 (check_result 错误或未找到分辨率行)");
        }
    }

    write_debug_log("USB 视频设备查找完成，共找到 " + std::to_string(devices.size()) + " 个有效设备");
    return devices;
}

// 查找串口设备
std::vector<std::string> find_serial_devices() {
    write_debug_log("开始查找串口设备");
    std::vector<std::string> devices;

    if (!has_root_privileges()) {
        write_debug_log("错误: 没有 root 权限，无法查找串口设备");
        return devices;
    }

    write_debug_log("执行 ls /dev/ttyACM* /dev/ttyUSB* 命令");
    // 对 ls 命令忽略非零退出码，因为可能没有设备而返回非零
    std::string result = exec_command("ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null || echo ''", 1000, true);
     if (result.substr(0, 5) == "错误:") {
         write_debug_log("执行 ls /dev/ttyACM* /dev/ttyUSB* 失败 (可能超时)");
         return devices;
     }


    if (result.empty()) { // Check if result is empty because nonzero exit code is ignored
        write_debug_log("未找到 /dev/ttyACM* 或 /dev/ttyUSB* 设备");
        return devices;
    }


    write_debug_log("找到以下串口设备: " + result);
    std::istringstream iss(result);
    std::string device;
    while (std::getline(iss, device)) {
        if (!device.empty()) {
            devices.push_back(device);
            write_debug_log("找到串口设备: " + device);
        }
    }
    write_debug_log("串口设备查找完成，找到 " + std::to_string(devices.size()) + " 个设备。");
    return devices;
}

// --- 系统信息获取函数 ---
struct SystemInfo {
    std::string uptime;
    std::string memory;
    std::string os_version;
    std::string cpu_info;
    std::string network_info;

    // 刷新系统信息并记录日志和终端调试信息
    void refresh() {
        write_debug_log("刷新系统信息...");
        uptime = exec_command("uptime -p");
        memory = exec_command("free -m | grep Mem | awk '{print $3\"MB used / \"$2\"MB total\"}'");
        os_version = exec_command("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2");
        cpu_info = exec_command("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2");

        auto ip = exec_command("ip route get 1 | awk '{print $7}' | head -1");
        auto iface = exec_command("ip route get 1 | awk '{print $5}' | head -1");
        network_info = iface + " - " + ip;
        write_debug_log("系统信息刷新完成。");
    }
};

// --- 串口通信类 ---
class SerialPort {
public:
    SerialPort() : fd_(-1) {}
    ~SerialPort() { close(); }

    // 打开串口
    bool open(const std::string& port) {
        write_debug_log("尝试打开串口: " + port);

        fd_ = ::open(port.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK); // Open in non-blocking mode
        if (fd_ < 0) {
            write_debug_log("打开串口失败: " + port + ", 错误: " + std::string(strerror(errno)));
            return false;
        }

        termios tty;
        if (tcgetattr(fd_, &tty) != 0) {
            write_debug_log("获取串口属性失败: " + port + ", 错误: " + std::string(strerror(errno)));
            ::close(fd_);
            fd_ = -1;
            return false;
        }

        cfsetospeed(&tty, B115200);
        cfsetispeed(&tty, B115200);
        tty.c_cflag |= (CLOCAL | CREAD);
        tty.c_cflag &= ~CSIZE;
        tty.c_cflag |= CS8;
        tty.c_cflag &= ~PARENB;
        tty.c_cflag &= ~CSTOPB;
        tty.c_cflag &= ~CRTSCTS;

        if (tcsetattr(fd_, TCSANOW, &tty) != 0) {
            write_debug_log("设置串口属性失败: " + port + ", 错误: " + std::string(strerror(errno)));
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        write_debug_log("串口打开成功: " + port);
        return true;
    }

    // 关闭串口
    void close() {
        if (fd_ >= 0) {
            write_debug_log("关闭串口。");
            ::close(fd_);
            fd_ = -1;
        }
    }

    // 检查串口是否打开
    bool is_open() const { return fd_ >= 0; }

    // 读取串口数据 (非阻塞)
    std::string read_data() {
        if (fd_ < 0) return "";

        char buffer[256];
        std::string data;
        ssize_t n;

        // Non-blocking read
        while ((n = ::read(fd_, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[n] = '\0'; // Null-terminate the buffer
            data.append(buffer);
        }

        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
             // Error other than no data available
             write_debug_log("串口读取错误: " + std::string(strerror(errno)));
        }

        return data;
    }

private:
    int fd_;
};

int main() {
    // 清空并初始化调试日志
    clear_debug_log();
    write_debug_log("程序启动");

    // 设置信号处理
    std::signal(SIGTERM, handle_terminate_signal);
    std::signal(SIGINT, handle_terminate_signal);

    write_debug_log("初始化 ScreenInteractive");
    // 修复编译错误：将返回的临时对象存储到值类型变量中
    auto screen = ScreenInteractive::Fullscreen();
    global_screen_ptr = &screen;

    // --- 状态变量 ---
    write_debug_log("初始化状态变量");
    SystemInfo sys_info;

    // 使用原子变量标记初始加载状态
    std::atomic<bool> initial_load_complete(false);

    // 将状态变量声明在 main 函数中
    std::vector<VideoDeviceInfo> video_devices;
    std::vector<std::string> serial_devices;
    int selected_video = 0;
    int selected_serial = 0;
    bool serial_connected = false;
    std::unique_ptr<SerialPort> serial_port;

    // 在新线程中执行初始加载操作
    std::thread initial_load_thread([&] {
        write_debug_log("初始加载线程开始");
        {
            std::lock_guard<std::mutex> lock(state_mutex);
            sys_info.refresh();
            video_devices = find_video_devices(); // 现在只查找 USB 视频设备
            serial_devices = find_serial_devices();
        }

        initial_load_complete = true;
        write_debug_log("初始加载完成，发送 UI 更新事件");
        screen.PostEvent(ftxui::Event::Custom);
    });
    initial_load_thread.detach();

    // --- 组件定义 ---
    int tab_selected = 0;
    std::vector<std::string> tab_titles = {"串口", "摄像头", "系统", "日志"};

    // 串口组件
    // 捕获 serial_connected
    auto serial_status = Renderer([&] {
        std::string status = serial_connected ? "已连接" : "未连接";
        return hbox(Elements{
            text("状态: ") | dim,
            text(status) | color(Color::RGB(serial_connected ? 0 : 255, serial_connected ? 255 : 0, 0))
        });
    });

    auto serial_list_container = Container::Vertical({});
    // 初始时不在此处填充，将在加载完成后填充

    // 捕获 serial_connected, serial_port, serial_devices, selected_serial, logs_mutex, screen, state_mutex
    auto connect_button = Button(serial_connected ? "断开" : "连接", [&] {
        // 锁定日志进行写入
        std::lock_guard<std::mutex> log_lock(logs_mutex);
        logs.push_back("点击连接/断开串口按钮...");
        write_debug_log("点击连接/断开串口按钮");

        // 锁定状态变量进行读写
        std::lock_guard<std::mutex> state_lock(state_mutex);

        if (serial_connected) {
            serial_port.reset();
            serial_connected = false;
            logs.push_back("串口已断开。");
            write_debug_log("串口已断开");
        } else if (!serial_devices.empty()) {
            serial_port = std::make_unique<SerialPort>();
            // 安全地转换 selected_serial 并检查边界
            if (selected_serial >= 0 && static_cast<size_t>(selected_serial) < serial_devices.size()) {
                 if (serial_port->open(serial_devices[static_cast<size_t>(selected_serial)])) {
                    serial_connected = true;
                    logs.push_back("串口已连接: " + serial_devices[static_cast<size_t>(selected_serial)]);
                    write_debug_log("串口已连接: " + serial_devices[static_cast<size_t>(selected_serial)]);
                 } else {
                     logs.push_back("连接串口失败: " + serial_devices[static_cast<size_t>(selected_serial)]);
                     write_debug_log("连接串口失败: " + serial_devices[static_cast<size_t>(selected_serial)]);
                 }
            } else {
                 // 如果 selected_serial 越界，记录日志
                 logs.push_back("错误: 选定的串口设备索引越界，无法尝试连接。");
                 write_debug_log("错误: 选定的串口设备索引越界");
            }
        } else {
             // 如果没有找到串口设备，记录日志
             logs.push_back("错误: 没有可用的串口设备进行连接。");
             write_debug_log("错误: 没有可用的串口设备进行连接");
        }
    });

    // 摄像头组件 - 条件渲染
    // 捕获 initial_load_complete, video_devices, serial_devices, serial_list_container, selected_video, selected_serial, logs_mutex, screen, state_mutex
    auto video_tab_content = Renderer([&] {
        // 锁定状态变量进行读取
        std::lock_guard<std::mutex> state_lock(state_mutex);

        if (!initial_load_complete) {
             return vbox(Elements{text("正在加载设备信息...") | hcenter | flex});
        }

        if (video_devices.empty()) {
            // 没有设备时，返回包含文本和渲染后的按钮的 vbox (Elements)
            return vbox(Elements{
                text("未找到支持的 USB 摄像头设备。") | hcenter | flex, // 修改提示文本
                // 渲染按钮以获取 Element
                Button("刷新设备列表", [&] { // 捕获 logs_mutex, video_devices, serial_devices, serial_list_container, selected_video, selected_serial, screen, state_mutex
                    write_debug_log("点击刷新设备列表按钮");
                    // 在新线程中执行刷新操作
                    std::thread refresh_thread([&] { // 捕获 logs_mutex, video_devices, serial_devices, screen, state_mutex
                        write_debug_log("刷新设备列表线程开始");
                        auto new_video_devices = find_video_devices(); // 现在只查找 USB 视频设备
                        auto new_serial_devices = find_serial_devices();

                        // 锁定状态变量进行更新
                        std::lock_guard<std::mutex> lock(state_mutex); // 确保在更新共享状态前锁定
                        video_devices = new_video_devices;
                        serial_devices = new_serial_devices;

                        // 重新填充 serial_list_container (通过事件通知主线程)
                        write_debug_log("设备列表刷新完成，发送 UI 更新事件");
                        screen.PostEvent(ftxui::Event::Custom); // 发送自定义事件通知 UI 更新
                    });
                    refresh_thread.detach(); // 分离线程，让其独立运行

                    // 锁定日志进行写入
                    std::lock_guard<std::mutex> log_lock_button(logs_mutex);
                    logs.push_back("已触发设备列表刷新。");

                })->Render() | hcenter
            }) | flex;
        } else {
            // 有设备时，动态创建视频设备列表容器 (Container::Vertical)
            // 这个容器包含 Components (Button 和嵌套的 Renderer)
            auto current_video_list = Container::Vertical({});
             for (size_t i = 0; i < video_devices.size(); ++i) {
                std::string name = video_devices[i].path.substr(video_devices[i].path.rfind('/') + 1);
                auto resolutions = video_devices[i].resolutions;

                // 这个内部的 Container::Vertical 包含 Components (Button 和 Renderer Component)
                current_video_list->Add(Container::Vertical(Components{
                    Button(name, [&, i] {
                        std::lock_guard<std::mutex> state_lock(state_mutex); // 锁定状态变量
                        selected_video = static_cast<int>(i);
                        std::lock_guard<std::mutex> log_lock(logs_mutex);
                        logs.push_back("选中视频设备: " + video_devices[selected_video].path);
                        write_debug_log("选中视频设备: " + video_devices[selected_video].path);
                    }),
                    Renderer([resolutions] {
                        Elements res_elements;
                        for (const auto& res : resolutions) {
                            res_elements.push_back(text("  " + res) | dim);
                        }
                        return vbox(res_elements);
                    })
                }));
            }
            // 有设备时，返回包含渲染后的列表容器和渲染后的按钮的 vbox (Elements)
            return vbox(Elements{
                current_video_list->Render() | flex,
                 Button("刷新设备列表", [&] { // 捕获 logs_mutex, video_devices, serial_devices, serial_list_container, selected_video, selected_serial, screen, state_mutex
                    write_debug_log("点击刷新设备列表按钮 (有设备时)");
                    // 在新线程中执行刷新操作
                    std::thread refresh_thread([&] { // 捕获 logs_mutex, video_devices, serial_devices, screen, state_mutex
                         write_debug_log("刷新设备列表线程开始 (有设备时)");
                        auto new_video_devices = find_video_devices(); // 现在只查找 USB 视频设备
                        auto new_serial_devices = find_serial_devices();

                        // 锁定状态变量进行更新
                        std::lock_guard<std::mutex> lock(state_mutex); // 确保在更新共享状态前锁定
                        video_devices = new_video_devices;
                        serial_devices = new_serial_devices;

                        // 重新填充 serial_list_container (通过事件通知主线程)
                        write_debug_log("设备列表刷新完成，发送 UI 更新事件 (有设备时)");
                        screen.PostEvent(ftxui::Event::Custom); // 发送自定义事件通知 UI 更新
                    });
                    refresh_thread.detach(); // 分离线程，让其独立运行

                    // 锁定日志进行写入
                    std::lock_guard<std::mutex> log_lock_button(logs_mutex);
                    logs.push_back("已触发设备列表刷新。");

                })->Render() | hcenter
            }) | flex;
        }
    });


    // 系统信息组件
    auto system_info = Renderer([&] {
         if (!initial_load_complete) {
             return vbox(Elements{text("正在加载设备信息...") | hcenter | flex});
         }
        // 锁定状态变量进行读取
        std::lock_guard<std::mutex> state_lock(state_mutex);
        return vbox(Elements{
            hbox(Elements{text("系统: ") | dim, text(sys_info.os_version)}),
            hbox(Elements{text("CPU: ") | dim, text(sys_info.cpu_info)}),
            hbox(Elements{text("内存: ") | dim, text(sys_info.memory)}),
            hbox(Elements{text("运行时间: ") | dim, text(sys_info.uptime)}),
            hbox(Elements{text("网络: ") | dim, text(sys_info.network_info)})
        });
    });

    // 捕获 logs_mutex, sys_info, video_devices, serial_devices, serial_list_container, selected_video, selected_serial, screen, state_mutex
    auto refresh_all_button = Button("刷新所有信息", [&] {
        write_debug_log("点击刷新所有信息按钮");
        // 在新线程中执行刷新操作
        std::thread refresh_thread([&] { // 捕获 logs_mutex, sys_info, video_devices, serial_devices, screen, state_mutex
            write_debug_log("刷新所有信息线程开始");

            // 锁定状态变量进行更新
            std::lock_guard<std::mutex> lock(state_mutex); // 确保在更新共享状态前锁定

            sys_info.refresh(); // 刷新系统信息并记录日志
            auto new_video_devices = find_video_devices(); // 现在只查找 USB 视频设备
            auto new_serial_devices = find_serial_devices(); // 刷新串口设备并记录日志

            video_devices = new_video_devices;
            serial_devices = new_serial_devices;

            // 重新填充 serial_list_container (通过事件通知主线程)
            write_debug_log("所有信息刷新完成，发送 UI 更新事件");
            screen.PostEvent(ftxui::Event::Custom); // 发送自定义事件通知 UI 更新
        });
        refresh_thread.detach(); // 分离线程，让其独立运行

        // 锁定日志进行写入
        std::lock_guard<std::mutex> log_lock_button(logs_mutex);
        logs.push_back("已触发所有信息刷新。");
    });

    // 日志标签页内容
    auto log_tab_content = Renderer([&] {
        Elements log_lines;
        {
            std::lock_guard<std::mutex> lock(logs_mutex);
            for (const auto& log : logs) {
                log_lines.push_back(text(log));
            }
        }
        return vbox(log_lines) | yframe | flex;
    });

    // 捕获 logs, logs_mutex
    auto clear_log_button = Button("清除日志", [&] {
         std::lock_guard<std::mutex> lock(logs_mutex); // 锁定日志进行清除
         logs.clear();
         logs.push_back("日志已清除。");
         write_debug_log("日志已清除");
    });


    // Tab 容器 - 显式创建 Components 向量
    auto tab_container = Container::Tab(Components{
        // 串口标签页
        Container::Vertical(Components{
            serial_status,
            serial_list_container, // 使用容器
            connect_button
        }),
        // 摄像头标签页 - 使用条件渲染 Component
        Container::Vertical(Components{
            video_tab_content // video_tab_content 是一个 Renderer Component
        }),
        // 系统标签页
        Container::Vertical(Components{
            system_info,
            refresh_all_button
        }),
        // 日志标签页
        Container::Vertical(Components{
            log_tab_content, // log_tab_content 是一个 Renderer Component
            clear_log_button
        })
    }, &tab_selected);

    // tab_select 是一个 Container::Horizontal，接受 Components
    auto tab_select = Container::Horizontal(Components{});
    for (size_t i = 0; i < tab_titles.size(); ++i) {
        tab_select->Add(Button(tab_titles[i], [&, i] { // 捕获 tab_selected, tab_titles, logs_mutex, i
            // 锁定日志进行写入
            std::lock_guard<std::mutex> log_lock(logs_mutex);
            logs.push_back("切换到标签页: " + tab_titles[i]);
            write_debug_log("切换到标签页: " + tab_titles[i]);
            tab_selected = static_cast<int>(i);
        }));
    }

    auto quit_button = Button("退出", screen.ExitLoopClosure());

    // 主容器 - 显式创建 Components 向量
    auto main_container = Container::Vertical(Components{
        tab_select,
        tab_container,
        quit_button
    });

    // 捕获 main_container
    auto main_renderer = Renderer(main_container, [&] {
        // 显式创建 Elements 向量
        // 在 vbox 初始化列表之外创建元素以确保安全
        auto title_element = text("Luban Toolkit") | bold | hcenter;
        auto tab_select_element = tab_select->Render();
        auto tab_container_element = tab_container->Render() | flex;
        auto quit_button_element = quit_button->Render();

        return vbox(Elements{
            title_element,
            separator(),
            tab_select_element,
            separator(),
            tab_container_element,
            separator(),
            quit_button_element
        });
    });

    write_debug_log("进入事件处理循环");
    // 事件处理循环
    auto event_handler = CatchEvent(main_renderer, [&](Event event) {
        if (sigterm_received) {
            write_debug_log("接收到终止信号，退出程序");
            screen.Exit();
            return true;
        }

        if (event == Event::Tab) {
            tab_selected = (tab_selected + 1) % static_cast<int>(tab_titles.size());
            write_debug_log("Tab 键按下，切换到标签页: " + tab_titles[tab_selected]);
            return true;
        }

        if (event.is_character()) {
            if (event.character() == "q") {
                write_debug_log("按下 'q' 键，退出程序");
                screen.Exit();
                return true;
            }
        }

        // 处理自定义事件，用于 UI 更新
        if (event == ftxui::Event::Custom) {
            write_debug_log("接收到自定义事件，更新 UI");
            // 当接收到自定义事件时，重新填充 serial_list_container
            serial_list_container->DetachAllChildren(); // 清空现有按钮
            {
                std::lock_guard<std::mutex> state_lock(state_mutex);
                for (size_t i = 0; i < serial_devices.size(); ++i) {
                    serial_list_container->Add(Button(serial_devices[i], [&, i] {
                        std::lock_guard<std::mutex> state_lock_button(state_mutex);
                        selected_serial = static_cast<int>(i);
                        std::lock_guard<std::mutex> log_lock(logs_mutex);
                        logs.push_back("选中串口设备: " + serial_devices[selected_serial]);
                        write_debug_log("选中串口设备: " + serial_devices[selected_serial]);
                    }));
                }
            }
            // 不再在这里记录 "UI 已更新（响应自定义事件）"，避免重复且不准确的日志
            return true;
        }

        // 将未处理的事件传递给子组件
        return main_container->OnEvent(event);
    });

    screen.Loop(event_handler);

    write_debug_log("退出事件处理循环");

    // 确保串口在程序退出时关闭
    // serial_port 在 main 作用域，可以直接访问
    if (serial_port && serial_port->is_open()) {
        serial_port->close();
    }

    // 锁定日志进行写入
    std::lock_guard<std::mutex> main_exit_log_lock(logs_mutex);
    logs.push_back("程序退出。");
    write_debug_log("程序退出");

    return 0;
}
