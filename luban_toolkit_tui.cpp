#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp> // Corrected include path
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
#include <map> // For std::map
#include <numeric> // For std::accumulate

using namespace ftxui;

// --- 全局变量和信号处理 ---
ftxui::ScreenInteractive* global_screen_ptr = nullptr;
std::atomic<bool> sigterm_received(false);

// Removed global logs vector and mutex
// std::vector<std::string> logs;
// std::mutex logs_mutex;

// 用于保护终端输出的互斥锁
std::mutex cout_mutex;

// 用于保护共享状态变量（设备列表、系统信息等）的互斥锁
std::mutex state_mutex;

// Re-added file log mutex and functions for debugging
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

// 执行系统命令并返回结果
std::string exec_command(const std::string& cmd, int timeout_ms = 5000, bool ignore_nonzero_exit = false) {
    write_debug_log("开始执行命令: " + cmd + " (超时: " + std::to_string(timeout_ms) + "ms, 忽略非零退出码: " + (ignore_nonzero_exit ? "true" : "false") + ")"); // Added debug log
    std::array<char, 128> buffer;
    std::string result;

    // 将标准错误重定向到标准输出，以便一起捕获
    std::string full_cmd = cmd + " 2>&1";

    write_debug_log("执行完整命令: " + full_cmd); // Added debug log
    FILE* pipe = popen(full_cmd.c_str(), "r");
    if (!pipe) {
        write_debug_log("错误: popen() 调用失败!"); // Added debug log
        return "错误: popen() 调用失败!";
    }

    // 将管道的文件描述符设置为非阻塞模式
    int fd = fileno(pipe);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    write_debug_log("设置管道为非阻塞模式"); // Added debug log

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
            write_debug_log("命令执行超时"); // Added debug log
            break;
        }

        // Poll with remaining timeout
        int poll_ret = poll(&pfd, 1, remaining_timeout);

        if (poll_ret > 0) {
            if (pfd.revents & POLLIN) {
                // Data is available, read all of it in non-blocking mode
                ssize_t n;
                while ((n = read(fd, buffer.data(), buffer.size() - 1)) > 0) {
                    buffer[n] = '\0'; // Null-terminate the buffer
                    result.append(buffer.data()); // Use append for string concatenation
                    write_debug_log("读取到数据 (片段): " + std::string(buffer.data()).substr(0, std::min((size_t)50, (size_t)n)) + "..."); // Added debug log
                }
                if (n == 0) {
                    // End of file (pipe closed by child process)
                    write_debug_log("读取完成 (EOF)"); // Added debug log
                    break; // Exit the main loop
                } else if (n < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    // Error other than EAGAIN/EWOULDBLOCK
                    std::string error_msg = "错误: 从管道读取数据失败: " + std::string(strerror(errno));
                    write_debug_log(error_msg); // Added debug log
                    pclose(pipe);
                    return error_msg;
                }
                // If n < 0 and EAGAIN/EWOULDBLOCK, no data currently available, continue polling
            } else if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                write_debug_log("管道错误或关闭 (POLLERR/POLLHUP/POLLNVAL)"); // Added debug log
                 // Attempt to read any remaining data before breaking
                 ssize_t n;
                 while ((n = read(fd, buffer.data(), buffer.size() - 1)) > 0) {
                     buffer[n] = '\0';
                     result.append(buffer.data()); // Use append
                     write_debug_log("读取到剩余数据 (片段): " + std::string(buffer.data()).substr(0, std::min((size_t)50, (size_t)n)) + "..."); // Added debug log
                 }
                 if (n < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                     std::string error_msg = "错误: 从管道读取剩余数据失败: " + std::string(strerror(errno));
                     write_debug_log(error_msg); // Added debug log
                     pclose(pipe);
                     return error_msg;
                 }
                break; // Exit the main loop
            }
        } else if (poll_ret == 0) {
            // Timeout occurred
            timed_out = true;
            write_debug_log("命令执行超时"); // Added debug log
            break; // Exit the main loop on timeout
        } else if (errno != EINTR) {
            // poll returned an error other than EINTR
            std::string error_msg = "错误: poll() 调用失败: " + std::string(strerror(errno));
            write_debug_log(error_msg); // Added debug log
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
        write_debug_log("命令退出状态码: " + std::to_string(exit_status)); // Added debug log
    } else {
         write_debug_log("命令未正常退出"); // Added debug log
    }


    if (timed_out) {
         write_debug_log("命令执行结果: 超时"); // Added debug log
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
        write_debug_log("命令执行结果 (错误): " + error); // Added debug log
        return error;
    }

    // Remove trailing newline if present
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }

    write_debug_log("命令执行完成，结果长度: " + std::to_string(result.length()) + " 字节"); // Added debug log
    return result;
}

// --- 设备查找函数 ---

struct VideoDeviceInfo {
    std::string path;
    // Use a map to store resolutions per format
    std::map<std::string, std::vector<std::string>> resolutions_by_format;
};

// 查找 USB 视频设备
std::vector<VideoDeviceInfo> find_video_devices() {
    write_debug_log("开始查找 USB 视频设备"); // Added debug log
    std::vector<VideoDeviceInfo> devices;

    if (!has_root_privileges()) {
        write_debug_log("错误: 没有 root 权限，无法查找 USB 视频设备"); // Added debug log
        return devices;
    }

    write_debug_log("执行 v4l2-ctl --list-devices 命令"); // Added debug log
    std::string list_devices_cmd = "v4l2-ctl --list-devices 2>/dev/null";
    // 对 list-devices 命令忽略非零退出码，因为它可能因个别设备问题而返回非零
    std::string list_devices_result = exec_command(list_devices_cmd, 5000, true);

    // 即使忽略了非零退出码，如果 exec_command 返回的是表示超时的错误字符串，也需要处理
    if (list_devices_result.substr(0, 5) == "错误:") {
         write_debug_log("执行 v4l2-ctl --list-devices 失败 (可能超时)"); // Added debug log
         return devices;
    }

    write_debug_log("v4l2-ctl --list-devices 输出:\n" + list_devices_result); // Log full output - Added debug log
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
            write_debug_log("进入潜在 USB 设备组: " + line); // Added debug log
        } else if (processing_usb_device_group) {
            // If we are processing a potential USB device group, check for indented /dev/videoX lines
            if (std::regex_match(line, indented_device_path_match, indented_device_path_regex) && indented_device_path_match.size() > 1) {
                 std::string device_path = indented_device_path_match[1].str();
                 usb_video_paths.push_back(device_path);
                 write_debug_log("找到 USB 视频设备路径: " + device_path + " (在 USB 设备组下)"); // Added debug log
            } else if (!line.empty() && !std::isspace(static_cast<unsigned char>(line[0]))) {
                 // Encountered a non-indented, non-empty line, indicates end of the current device group
                 // Use static_cast to avoid issues with negative char values and isspace
                 processing_usb_device_group = false;
                 write_debug_log("结束处理当前 USB 设备组 (遇到非缩进行): " + line); // Added debug log
            } else if (line.empty()) {
                 // Encountered an empty line, also indicates end of the current device group
                 processing_usb_device_group = false;
                 write_debug_log("结束处理当前 USB 设备组 (遇到空行)"); // Added debug log
            }
        }
    }

    // Remove duplicates just in case
    std::sort(usb_video_paths.begin(), usb_video_paths.end());
    usb_video_paths.erase(std::unique(usb_video_paths.begin(), usb_video_paths.end()), usb_video_paths.end());

    write_debug_log("找到 " + std::to_string(usb_video_paths.size()) + " 个 USB 视频设备路径 (去重后)"); // Added debug log

    // For each found USB video device, query its resolutions
    for (const auto& device_path : usb_video_paths) {
        write_debug_log("查询 USB 设备分辨率和格式: " + device_path); // Added debug log
        // Do NOT ignore nonzero exit code for list-formats-ext command
        std::string check_cmd = "timeout 2 v4l2-ctl --device " + device_path + " --list-formats-ext 2>/dev/null";
        std::string check_result = exec_command(check_cmd, 3000, false); // Do NOT ignore nonzero exit code

        // Add debug log for the result of list-formats-ext
        write_debug_log("v4l2-ctl --device " + device_path + " --list-formats-ext output:\n" + check_result); // Added debug log

        // --- Debugging check_result ---
        write_debug_log("Debugging check_result for " + device_path); // Added debug log
        write_debug_log("check_result length: " + std::to_string(check_result.length())); // Added debug log
        write_debug_log("check_result starts with: '" + check_result.substr(0, std::min((size_t)50, check_result.length())) + "'"); // Added debug log

        // Use regex to find "Size: (Discrete|Stepwise) (\d+x\d+)" to confirm format support
        std::regex resolution_line_regex("Size: (Discrete|Stepwise) (\\d+x\\d+)");
        bool resolution_found_by_regex = std::regex_search(check_result, resolution_line_regex);

        write_debug_log("Regex search for \"Size: (Discrete|Stepwise) (\\d+x\\d+)\" returned: " + std::string(resolution_found_by_regex ? "true" : "false")); // Added debug log

        // Also print raw bytes of the relevant part of the string for debugging
        size_t debug_len = std::min((size_t)200, check_result.length()); // Print up to 200 bytes
        std::stringstream hex_dump;
        hex_dump << "Raw bytes (first " << debug_len << "): ";
        for (size_t i = 0; i < debug_len; ++i) {
            hex_dump << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(check_result[i])) << " ";
        }
        write_debug_log(hex_dump.str()); // Added debug log
        // --- End Debugging ---


        // Check if the command executed successfully and at least one resolution was found
        // The device is considered supported if the command output is not an error AND at least one resolution regex match is found
        bool command_successful_and_resolution_found = (check_result.substr(0, 5) != "错误:" && resolution_found_by_regex);
        write_debug_log("检查结果: command_successful_and_resolution_found = " + std::string(command_successful_and_resolution_found ? "true" : "false")); // Added debug log


        if (command_successful_and_resolution_found) {
            write_debug_log("设备 " + device_path + " 支持视频格式 (找到分辨率行)"); // Updated log message - Added debug log
            VideoDeviceInfo info;
            info.path = device_path;

            std::istringstream format_stream(check_result);
            std::string format_line;
            std::string current_format = "未知格式"; // Default format
            std::regex format_name_regex("\\[\\d+\\]: '(.*?)'"); // Regex to capture format name like 'MJPG' or 'YUYV'
            std::smatch format_name_match;

            std::regex res_regex("Size: (Discrete|Stepwise) (\\d+x\\d+)"); // Regex to match resolutions
            std::smatch res_match;


            while (std::getline(format_stream, format_line)) {
                // Check if this line contains a format name
                if (std::regex_search(format_line, format_name_match, format_name_regex) && format_name_match.size() > 1) {
                    current_format = format_name_match[1].str();
                    write_debug_log("切换到格式: " + current_format); // Added debug log
                }
                // Check if this line contains a resolution
                else if (std::regex_search(format_line, res_match, res_regex) && res_match.size() > 2) {
                    info.resolutions_by_format[current_format].push_back(res_match[2].str());
                    write_debug_log("为格式 " + current_format + " 找到分辨率: " + res_match[2].str()); // Added debug log
                }
            }

            // Check if any resolutions were successfully added to the map
            bool resolutions_extracted = false;
            for(const auto& pair : info.resolutions_by_format) {
                if (!pair.second.empty()) {
                    resolutions_extracted = true;
                    break;
                }
            }

            write_debug_log("设备 " + device_path + " 找到的格式数量: " + std::to_string(info.resolutions_by_format.size())); // Added debug log
            if (resolutions_extracted) {
                 devices.push_back(info);
                 write_debug_log("添加设备 " + device_path + " 到列表，找到分辨率"); // Added debug log
            } else {
                 // If "Format:" was found but no resolutions were extracted, log this specific case
                 write_debug_log("设备 " + device_path + " 支持格式但未提取到任何分辨率，跳过"); // Added debug log
            }

        } else {
            write_debug_log("设备 " + device_path + " 不支持视频格式或查询失败 (check_result 错误或未找到分辨率行)"); // Updated log message - Added debug log
        }
    }

    write_debug_log("USB 视频设备查找完成，共找到 " + std::to_string(devices.size()) + " 个有效设备"); // Added debug log
    return devices;
}

// 查找串口设备
std::vector<std::string> find_serial_devices() {
    write_debug_log("开始查找串口设备"); // Added debug log
    std::vector<std::string> devices;

    if (!has_root_privileges()) {
        write_debug_log("错误: 没有 root 权限，无法查找串口设备"); // Added debug log
        return devices;
    }

    write_debug_log("执行 ls /dev/ttyACM* /dev/ttyUSB* 命令"); // Added debug log
    // 对 ls 命令忽略非零退出码，因为可能没有设备而返回非零
    std::string result = exec_command("ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null || echo ''", 1000, true);
     if (result.substr(0, 5) == "错误:") {
         write_debug_log("执行 ls /dev/ttyACM* /dev/ttyUSB* 失败 (可能超时)"); // Added debug log
         return devices;
     }


    if (result.empty()) { // Check if result is empty because nonzero exit code is ignored
        write_debug_log("未找到 /dev/ttyACM* 或 /dev/ttyUSB* 设备"); // Added debug log
        return devices;
    }


    write_debug_log("找到以下串口设备: " + result); // Added debug log
    std::istringstream iss(result);
    std::string device;
    while (std::getline(iss, device)) {
        if (!device.empty()) {
            devices.push_back(device);
            write_debug_log("找到串口设备: " + device); // Added debug log
        }
    }
    write_debug_log("串口设备查找完成，找到 " + std::to_string(devices.size()) + " 个设备。"); // Added debug log
    return devices;
}

// --- 系统信息获取函数 ---
struct SystemInfo {
    std::string hostname; // Add hostname member
    std::string uptime;
    std::string memory;
    std::string os_version;
    std::string cpu_info; // Store CPU model name
    std::string network_info;
    std::string cpu_temperature_avg; // Store average temperature
    // Removed cpu_serial as per user request
    std::vector<std::string> ip_addresses; // Add IP addresses member
    bool has_root = false; // Add member to store root privilege status

    // 刷新系统信息并记录日志和终端调试信息
    void refresh() {
        write_debug_log("刷新系统信息..."); // Added debug log
        has_root = has_root_privileges(); // Check root privileges

        // Get hostname
        hostname = exec_command("hostname", 1000);

        uptime = exec_command("uptime -p");
        memory = exec_command("free -m | grep Mem | awk '{print $3\"MB used / \"$2\"MB total\"}'");
        os_version = exec_command("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2");
        // Modified command to get CPU info (model name) using lscpu
        cpu_info = exec_command("lscpu | grep 'Model name:' | cut -d':' -f2 | xargs", 1000); // Use xargs to trim whitespace

        // Get network info including SSID for wlan0 and all IP addresses
        auto ip_a_result = exec_command("ip a", 1000, true); // Ignore nonzero exit for ip a
        ip_addresses.clear(); // Clear previous IP addresses
        std::string current_iface;
        std::istringstream ip_a_iss(ip_a_result);
        std::string ip_a_line;

        // Regex to capture interface name and state (e.g., "3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP>...")
        std::regex iface_line_regex("^\\d+:\\s*([^:]+):.*state (UP|UNKNOWN)");
        std::smatch iface_line_match;

        // Regex to capture IPv4 address (e.g., "    inet 192.168.1.100/24 brd 192.168.1.255 scope global wlan0")
        std::regex ip_v4_regex("\\s*inet (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})");
        std::smatch ip_v4_match;

        std::stringstream ip_line_ss; // Use the declared stringstream


        while(std::getline(ip_a_iss, ip_a_line)) {
             // Check if this line is an interface line
             if (std::regex_search(ip_a_line, iface_line_match, iface_line_regex) && iface_line_match.size() > 1) {
                 current_iface = iface_line_match[1].str(); // Capture interface name
                 write_debug_log("处理接口行: " + ip_a_line + " -> 当前接口: " + current_iface); // Added debug log
             }
             // Check if this line contains an IPv4 address and we have a current interface
             else if (!current_iface.empty() && std::regex_search(ip_a_line, ip_v4_match, ip_v4_regex) && ip_v4_match.size() > 1) {
                 ip_addresses.push_back(current_iface + ": " + ip_v4_match[1].str()); // Associate IP with current interface
                 write_debug_log("为接口 " + current_iface + " 找到 IPv4 地址: " + ip_v4_match[1].str()); // Added debug log
             }
        }

        std::string ssid;
        // Try to get SSID for wlan0 specifically
        auto ssid_cmd = "iwgetid wlan0 -r 2>/dev/null";
        ssid = exec_command(ssid_cmd, 1000, true); // Ignore nonzero exit if not connected or wlan0 doesn't exist
        if (ssid.substr(0, 5) == "错误:" || ssid.empty()) {
            ssid = "获取失败"; // Handle error or no SSID found
        }


        std::stringstream network_info_ss;
        if (!ip_addresses.empty()) {
            network_info_ss << "活跃接口: ";
            for(size_t i = 0; i < ip_addresses.size(); ++i) {
                network_info_ss << ip_addresses[i];
                if (i < ip_addresses.size() - 1) {
                    network_info_ss << ", ";
                }
            }
            if (ssid != "获取失败") {
                network_info_ss << " | WiFi: " << ssid;
            }
        } else {
            // 尝试更详细地检测网络接口状态
            std::string iface_check = exec_command("ip link show | grep 'state UP'", 1000, true);
            if (iface_check.empty()) {
                network_info_ss << "网络: 未连接";
            } else {
                // Check if any interface is UP but has no IP address
                bool interface_up_no_ip = false;
                std::istringstream iface_check_iss(iface_check);
                std::string up_line;
                while(std::getline(iface_check_iss, up_line)) {
                    // Check if the UP interface is present in the ip_addresses list
                    bool found_ip_for_up_iface = false;
                    std::smatch up_iface_match;
                    if (std::regex_search(up_line, up_iface_match, iface_line_regex) && up_iface_match.size() > 1) {
                        std::string up_iface_name = up_iface_match[1].str();
                        for (const auto& ip_entry : ip_addresses) {
                            if (ip_entry.rfind(up_iface_name + ":", 0) == 0) {
                                found_ip_for_up_iface = true;
                                break;
                            }
                        }
                        if (!found_ip_for_up_iface) {
                            interface_up_no_ip = true;
                            break; // Found an UP interface without an IP
                        }
                    }
                }

                if (interface_up_no_ip) {
                     network_info_ss << "网络: 接口已启用但未获取IP";
                } else {
                     network_info_ss << "网络: 未获取到IP地址"; // Default if no UP interfaces or all UP interfaces have IPs (which shouldn't happen if ip_addresses is empty)
                }
            }

            if (ssid != "获取失败") {
                network_info_ss << " | WiFi: " << ssid;
            }
        }
        network_info = network_info_ss.str();


        // Get CPU temperature
        std::string temp_result = exec_command("cat /sys/class/thermal/thermal_zone*/temp", 1000, true); // Ignore nonzero exit
        std::vector<double> temperatures_milli;
        if (temp_result.substr(0, 5) != "错误:") {
            std::istringstream temp_iss(temp_result);
            std::string temp_line;
            while(std::getline(temp_iss, temp_line)) {
                if (!temp_line.empty()) {
                    try {
                        temperatures_milli.push_back(std::stod(temp_line));
                    } catch (const std::invalid_argument& ia) {
                        write_debug_log("错误: 转换温度字符串失败: " + temp_line); // Added debug log
                    } catch (const std::out_of_range& oor) {
                         write_debug_log("错误: 温度值超出范围: " + temp_line); // Added debug log
                    }
                }
            }
        } else {
             write_debug_log("错误: 获取CPU温度失败"); // Added debug log
        }

        // Calculate and store average temperature
        if (!temperatures_milli.empty()) {
            double sum = std::accumulate(temperatures_milli.begin(), temperatures_milli.end(), 0.0);
            double average_celsius = (sum / temperatures_milli.size()) / 1000.0;
            std::stringstream ss;
            ss << std::fixed << std::setprecision(1) << average_celsius << "°C";
            cpu_temperature_avg = ss.str();
        } else {
            cpu_temperature_avg = "获取失败";
        }


        // Removed CPU serial number logic as per user request
        // std::string serial_result = exec_command("cat /proc/cpuinfo | grep 'Serial' | cut -d':' -f2 | xargs", 1000, true); // Ignore nonzero exit
        // if (serial_result.substr(0, 5) != "错误:") {
        //     cpu_serial = serial_result;
        // } else {
        //      write_debug_log("错误: 获取CPU序列号失败"); // Added debug log
        //      cpu_serial = "获取失败";
        // }
        write_debug_log("系统信息刷新完成。"); // Added debug log
    }
};

// --- 串口通信类 ---
class SerialPort {
public:
    SerialPort() : fd_(-1) {}
    ~SerialPort() { close(); }

    // 打开串口
    bool open(const std::string& port) {
        write_debug_log("尝试打开串口: " + port); // Added debug log
        if (fd_ < 0) {
            fd_ = ::open(port.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK); // Open in non-blocking mode
            if (fd_ < 0) {
                write_debug_log("打开串口失败: " + port + ", 错误: " + std::string(strerror(errno))); // Added debug log
                return false;
            }

            termios tty;
            if (tcgetattr(fd_, &tty) != 0) {
                write_debug_log("获取串口属性失败: " + port + ", 错误: " + std::string(strerror(errno))); // Added debug log
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
                write_debug_log("设置串口属性失败: " + port + ", 错误: " + std::string(strerror(errno))); // Added debug log
                ::close(fd_);
                fd_ = -1;
                return false;
            }
        }
        write_debug_log("串口打开成功: " + port); // Added debug log
        return true;
    }

    // 关闭串口
    void close() {
        if (fd_ >= 0) {
            write_debug_log("关闭串口。"); // Added debug log
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
             write_debug_log("串口读取错误: " + std::string(strerror(errno))); // Added debug log
        }

        return data;
    }

private:
    int fd_;
};

int main() {
    clear_debug_log(); // Re-added for debugging
    write_debug_log("程序启动"); // Re-added for debugging

    // 设置信号处理
    std::signal(SIGTERM, handle_terminate_signal);
    std::signal(SIGINT, handle_terminate_signal);

    write_debug_log("初始化 ScreenInteractive"); // Re-added for debugging
    // 修复编译错误：将返回的临时对象存储到值类型变量中
    auto screen = ScreenInteractive::Fullscreen();
    global_screen_ptr = &screen;

    // --- 状态变量 ---
    write_debug_log("初始化状态变量"); // Re-added for debugging
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

    // 摄像头采集状态变量
    std::atomic<bool> is_capturing(false);
    std::string camera_status_message = ""; // Removed initial message

    // 在新线程中执行初始加载操作
    std::thread initial_load_thread([&] {
        write_debug_log("初始加载线程开始"); // Re-added for debugging
        {
            std::lock_guard<std::mutex> lock(state_mutex);
            sys_info.refresh();
            video_devices = find_video_devices(); // 现在只查找 USB 视频设备
            serial_devices = find_serial_devices();
        }

        initial_load_complete = true;
        write_debug_log("初始加载完成，发送 UI 更新事件"); // Re-added for debugging
        screen.PostEvent(ftxui::Event::Custom);
    });
    initial_load_thread.detach();

    // --- 组件定义 ---
    int tab_selected = 0;
    std::vector<std::string> tab_titles = {"串口", "摄像头", "系统"}; // Removed "日志"

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

    // 捕获 serial_connected, serial_port, serial_devices, selected_serial, screen, state_mutex
    auto connect_button = Button(serial_connected ? "断开" : "连接", [&] {
        write_debug_log("点击连接/断开串口按钮..."); // Added debug log

        // 锁定状态变量进行读写
        std::lock_guard<std::mutex> state_lock(state_mutex);

        if (serial_connected) {
            serial_port.reset();
            serial_connected = false;
            write_debug_log("串口已断开。"); // Added debug log
        } else if (!serial_devices.empty()) {
            serial_port = std::make_unique<SerialPort>();
            // 安全地转换 selected_serial 并检查边界
            if (selected_serial >= 0 && static_cast<size_t>(selected_serial) < serial_devices.size()) {
                 if (serial_port->open(serial_devices[static_cast<size_t>(selected_serial)])) {
                    serial_connected = true;
                    write_debug_log("串口已连接: " + serial_devices[static_cast<size_t>(selected_serial)]); // Added debug log
                 } else {
                     write_debug_log("连接串口失败: " + serial_devices[static_cast<size_t>(selected_serial)]); // Added debug log
                 }
            } else {
                 // 如果 selected_serial 越界，记录日志
                 write_debug_log("错误: 选定的串口设备索引越界，无法尝试连接。"); // Added debug log
            }
        } else {
             // 如果没有找到串口设备，记录日志
             write_debug_log("错误: 没有可用的串口设备进行连接。"); // Added debug log
        }
    });

    // 摄像头采集状态文本组件
    // 捕获 camera_status_message
    auto camera_status_renderer = Renderer([&] {
        return text(camera_status_message) | flex;
    });

    // 获取图片按钮组件
    // 捕获 video_devices, selected_video, is_capturing, camera_status_message, screen, state_mutex
    auto capture_button_component = Button(is_capturing ? "采集中..." : "获取图片", [&] {
        write_debug_log("点击获取图片按钮"); // Added debug log
        // 锁定状态变量进行读取
        std::lock_guard<std::mutex> state_lock(state_mutex);

        if (is_capturing) {
            // 如果正在采集，忽略点击
            write_debug_log("正在采集图片，忽略新的点击"); // Added debug log
            return;
        }

        if (video_devices.empty() || selected_video < 0 || static_cast<size_t>(selected_video) >= video_devices.size()) {
            // 没有选中设备或设备列表为空
            write_debug_log("错误: 没有选中的摄像头设备。"); // Added debug log
            camera_status_message = "错误: 没有选中的摄像头设备。";
            screen.PostEvent(ftxui::Event::Custom); // 更新 UI 显示错误信息
            return;
        }

        is_capturing = true;
        // Include device path in the capturing message
        camera_status_message = "正在采集图片 (" + video_devices[static_cast<size_t>(selected_video)].path + ")...";
        write_debug_log("开始图片采集过程 (使用 v4l2-ctl)..."); // Updated log - Added debug log
        screen.PostEvent(ftxui::Event::Custom); // 更新 UI 显示“采集中...”

        std::string device_path = video_devices[static_cast<size_t>(selected_video)].path;

        // Extract device number from path (e.g., "/dev/video0" -> "0")
        std::string device_number = "unknown";
        size_t video_pos = device_path.rfind("video");
        if (video_pos != std::string::npos) {
            device_number = device_path.substr(video_pos + 5); // "video" has 5 characters
        }


        // Get current time for filename
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buffer;
        std::stringstream time_ss;
        if (localtime_r(&now_c, &tm_buffer)) {
            time_ss << std::put_time(&tm_buffer, "%Y%m%d_%H%M%S");
        } else {
            time_ss << "timestamp_error";
        }

        // Get resolution (hardcoded for now as per command, but could be dynamic)
        std::string resolution = "640x480"; // Matches the --set-fmt-video

        // Construct output filename in the current directory with device number
        std::string output_file = "./video" + device_number + "_" + time_ss.str() + "_" + resolution + ".jpg";


        // 使用 v4l2-ctl 命令采集图片到 JPG 文件
        // v4l2-ctl --stream-to 可以根据设备和驱动支持，直接输出为 JPG
        // 添加 --set-fmt-video 设置分辨率，尝试 640x480
        std::string capture_cmd = "v4l2-ctl --device " + device_path + " --set-fmt-video=width=640,height=480 --stream-mmap --stream-count=1 --stream-to " + output_file + " 2>&1";


        // 在新线程中执行采集命令
        std::thread capture_thread([&, capture_cmd, output_file, device_path] { // Capture device_path
            write_debug_log("采集线程开始执行命令: " + capture_cmd); // Added debug log
            std::string capture_result = exec_command(capture_cmd, 10000); // 10秒超时

            // 锁定状态变量进行更新
            std::lock_guard<std::mutex> state_lock_thread(state_mutex);

            is_capturing = false; // 采集完成

            if (capture_result.rfind("错误:", 0) == 0) {
                // 命令执行失败
                // Include device path in the failure message
                camera_status_message = "采集失败 (" + device_path + "): " + capture_result; // Updated message
                write_debug_log("图片采集失败 (" + device_path + "): " + capture_result); // Added debug log
            } else {
                // 命令执行成功，检查文件是否存在
                std::ifstream file_check(output_file);
                if (file_check.good()) {
                    // Include device path in the success message
                    camera_status_message = "图片采集成功 (" + device_path + "): " + output_file; // Updated message
                    write_debug_log("图片采集成功 (" + device_path + "): " + output_file); // Added debug log
                } else {
                    // Include device path in the file not found message
                    camera_status_message = "采集完成但未找到输出文件 (" + device_path + "): " + output_file; // Updated message
                    write_debug_log("采集完成但未找到输出文件 (" + device_path + "): " + output_file); // Added debug log
                }
            }
            screen.PostEvent(ftxui::Event::Custom); // 更新 UI 显示结果
        });
        capture_thread.detach(); // 分离线程
    });


    // 摄像头设备列表容器
    auto video_list_container = Container::Vertical({});
    // 初始时不在此处填充，将在加载完成后填充

    // 获取图片和刷新设备列表按钮以及状态文本的水平容器
    auto camera_buttons_status_container = Container::Horizontal(Components{
        capture_button_component,
        camera_status_renderer,
        Button("刷新设备列表", [&] { // Capture video_devices, serial_devices, video_list_container, selected_video, selected_serial, screen, state_mutex
            write_debug_log("点击刷新设备列表按钮"); // Added debug log
            // Execute refresh operation in a new thread
            std::thread refresh_thread([&] { // Capture video_devices, serial_devices, screen, state_mutex
                 write_debug_log("刷新设备列表线程开始"); // Added debug log
                auto new_video_devices = find_video_devices(); // Now only finds USB video devices
                auto new_serial_devices = find_serial_devices();

                // Lock state variables for update
                std::lock_guard<std::mutex> lock(state_mutex); // Ensure locking before updating shared state
                video_devices = new_video_devices;
                serial_devices = new_serial_devices;

                // Repopulate video_list_container (notify main thread via event)
                write_debug_log("设备列表刷新完成，发送 UI 更新事件"); // Added debug log
                screen.PostEvent(ftxui::Event::Custom); // Send custom event to notify UI update
            });
            refresh_thread.detach(); // Detach thread to run independently
        })
    });


    // 摄像头标签页内容容器 (包含设备列表和按钮/状态行)
    // 捕获 initial_load_complete, sys_info, video_devices, video_list_container, camera_buttons_status_container, screen, state_mutex
    auto camera_tab_content_container = Container::Vertical(Components{
        Renderer([&] { // This renderer displays conditional content (loading, no root, no devices)
             std::lock_guard<std::mutex> state_lock(state_mutex);
             if (!initial_load_complete) {
                 return vbox(Elements{text("正在加载设备信息...") | hcenter | flex});
             }
             if (!sys_info.has_root) {
                  return vbox(Elements{text("查找摄像头需要 root 权限。") | hcenter | flex});
             }
             if (video_devices.empty()) {
                 return vbox(Elements{text("未找到支持的 USB 摄像头设备。") | hcenter | flex});
             }
             return emptyElement(); // Return empty if devices are found, allowing the rest of the container to render
        }),
        video_list_container, // Device list container
        camera_buttons_status_container // Add the horizontal container with buttons and status
    });


    // 系统信息组件
    auto system_info = Renderer([&] {
         if (!initial_load_complete) {
             return vbox(Elements{text("正在加载设备信息...") | hcenter | flex});
         }
        // 锁定状态变量进行读取
        std::lock_guard<std::mutex> state_lock(state_mutex);

        Elements ip_elements;
        ip_elements.push_back(text("IP 地址: ") | dim);
        if (sys_info.ip_addresses.empty()) {
            ip_elements.push_back(text("获取失败或未连接"));
        } else {
            std::stringstream ip_line_ss; // Use the declared stringstream
            for(size_t i = 0; i < sys_info.ip_addresses.size(); ++i) {
                ip_line_ss << sys_info.ip_addresses[i];
                if (i < sys_info.ip_addresses.size() - 1) {
                    ip_line_ss << ", ";
                }
            }
            ip_elements.push_back(text(ip_line_ss.str())); // Use the stringstream's content
        }


        return vbox(Elements{
            hbox(Elements{text("主机名: ") | dim, text(sys_info.hostname)}), // Display hostname
            hbox(Elements{text("系统: ") | dim, text(sys_info.os_version)}),
            hbox(Elements{text("内存: ") | dim, text(sys_info.memory)}),
            hbox(Elements{text("运行时间: ") | dim, text(sys_info.uptime)}),
            hbox(Elements{text("网络: ") | dim, text(sys_info.network_info)}), // Display network info with SSID
            hbox(Elements{text("CPU 温度 (平均): ") | dim, text(sys_info.cpu_temperature_avg)}), // Display average CPU temperature
            // Removed CPU serial number display
            // hbox(Elements{text("CPU 序列号: ") | dim, text(sys_info.cpu_serial)}) // Display CPU serial
            hbox(ip_elements) // Display IP addresses
        });
    });

    // 捕获 sys_info, video_devices, serial_devices, serial_list_container, selected_video, selected_serial, screen, state_mutex
    auto refresh_all_button = Button("刷新所有信息", [&] {
        write_debug_log("点击刷新所有信息按钮"); // Added debug log
        // 在新线程中执行刷新操作
        std::thread refresh_thread([&] { // 捕获 sys_info, video_devices, serial_devices, screen, state_mutex
            write_debug_log("刷新所有信息线程开始"); // Added debug log

            // Lock state variables for update
            std::lock_guard<std::mutex> lock(state_mutex);

            sys_info.refresh(); // Refresh system info and log
            auto new_video_devices = find_video_devices(); // Find USB video devices and log
            auto new_serial_devices = find_serial_devices(); // Find serial devices and log

            video_devices = new_video_devices;
            serial_devices = new_serial_devices;

            // Repopulate serial_list_container (notify main thread via event)
            write_debug_log("所有信息刷新完成，发送 UI 更新事件"); // Added debug log
            screen.PostEvent(ftxui::Event::Custom); // Send custom event to notify UI update
        });
        refresh_thread.detach(); // Detach thread to run independently
    });

    // Removed log_tab_content and clear_log_button

    // Tab 容器 - 显式创建 Components 向量
    auto tab_container = Container::Tab(Components{
        // 串口标签页
        Container::Vertical(Components{
            serial_status,
            serial_list_container, // 使用容器
            connect_button
        }),
        // 摄像头标签页 - 使用条件渲染 Component
        camera_tab_content_container, // Use the new container for camera tab
        // 系统标签页
        Container::Vertical(Components{
            system_info,
            refresh_all_button
        })
        // Removed Log tab component
    }, &tab_selected);

    // tab_select 是一个 Container::Horizontal，接受 Components
    auto tab_select = Container::Horizontal(Components{});
    for (size_t i = 0; i < tab_titles.size(); ++i) {
        tab_select->Add(Button(tab_titles[i], [&, i] { // 捕获 tab_selected, tab_titles, i
            write_debug_log("切换到标签页: " + tab_titles[i]); // Added debug log
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

    write_debug_log("进入事件处理循环"); // Re-added for debugging
    // 事件处理循环
    auto event_handler = CatchEvent(main_renderer, [&](Event event) {
        // Added debug logging for received events (without ToString)
        if (event.is_mouse()) {
             write_debug_log("接收到鼠标事件");
        } else if (event.is_character()) {
             write_debug_log("接收到键盘事件");
        } else if (event == ftxui::Event::Custom) {
             write_debug_log("接收到自定义事件");
        } else {
             write_debug_log("接收到其他事件");
        }


        if (sigterm_received) {
            write_debug_log("接收到终止信号，退出程序"); // Added debug log
            screen.Exit();
            return true;
        }

        if (event == Event::Tab) {
            tab_selected = (tab_selected + 1) % static_cast<int>(tab_titles.size());
            write_debug_log("Tab 键按下，切换到标签页: " + tab_titles[tab_selected]); // Added debug log
            return true;
        }

        if (event.is_character()) {
            if (event.character() == "q") {
                write_debug_log("按下 'q' 键，退出程序"); // Added debug log
                screen.Exit();
                return true;
            }
        }

        // 处理自定义事件，用于 UI 更新
        if (event == ftxui::Event::Custom) {
            write_debug_log("接收到自定义事件，更新 UI"); // Added debug log
            // 当接收到自定义事件时，重新填充 serial_list_container 和 video_list_container
            {
                std::lock_guard<std::mutex> state_lock(state_mutex);
                // Update serial list
                serial_list_container->DetachAllChildren(); // 清空现有按钮
                for (size_t i = 0; i < serial_devices.size(); ++i) {
                    serial_list_container->Add(Button(serial_devices[i], [&, i] {
                        std::lock_guard<std::mutex> state_lock_button(state_mutex);
                        selected_serial = static_cast<int>(i);
                        write_debug_log("选中串口设备: " + serial_devices[selected_serial]); // Added debug log
                    }));
                }

                // Update video list
                video_list_container->DetachAllChildren(); // Clear existing children
                 for (size_t i = 0; i < video_devices.size(); ++i) {
                    std::string name = video_devices[i].path.substr(video_devices[i].path.rfind('/') + 1);
                    auto resolutions_by_format = video_devices[i].resolutions_by_format;

                    video_list_container->Add(Container::Vertical(Components{
                        Button(name, [&, i] {
                            write_debug_log("点击视频设备按钮: " + video_devices[i].path); // Added debug log for device button click
                            std::lock_guard<std::mutex> state_lock_button(state_mutex);
                            selected_video = static_cast<int>(i);
                            write_debug_log("选中视频设备: " + video_devices[selected_video].path); // Added debug log
                        }),
                        Renderer([resolutions_by_format] { // Capture map by value
                            Elements format_elements;
                            for (const auto& pair : resolutions_by_format) {
                                std::string format_name = pair.first;
                                const auto& resolutions = pair.second;

                                Elements res_elements_horizontal;
                                res_elements_horizontal.push_back(text("  " + format_name + ": ") | dim);

                                std::stringstream res_line;
                                for(size_t j = 0; j < resolutions.size(); ++j) {
                                    res_line << resolutions[j];
                                    if (j < resolutions.size() - 1) {
                                        res_line << " ";
                                    }
                                }
                                res_elements_horizontal.push_back(text(res_line.str()));
                                format_elements.push_back(hbox(res_elements_horizontal));
                            }
                            return vbox(format_elements);
                        })
                    }));
                }
            }
            return true;
        }

        // 将未处理的事件传递给子组件
        return main_container->OnEvent(event);
    });

    screen.Loop(event_handler);

    write_debug_log("退出事件处理循环"); // Re-added for debugging

    // 确保串口在程序退出时关闭
    // serial_port 在 main 作用域，可以直接访问
    if (serial_port && serial_port->is_open()) {
        serial_port->close();
    }

    write_debug_log("程序退出"); // Re-added for debugging

    return 0;
}
