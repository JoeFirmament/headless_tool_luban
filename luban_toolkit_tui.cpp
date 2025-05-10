#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp> // Corrected include path
#include <ftxui/dom/elements.hpp>

// 标准库头文件
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <thread> // Required for std::this_thread
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
#include <chrono> // Required for std::chrono
#include <fstream>
#include <iomanip> // For std::put_time
#include <algorithm> // For std::min
#include <cctype> // For std::isspace
#include <map> // For std::map
#include <numeric> // For std::accumulate
#include <limits> // Required for std::numeric_limits

using namespace ftxui;

// --- 全局变量和信号处理 ---
ftxui::ScreenInteractive* global_screen_ptr = nullptr;
std::atomic<bool> sigterm_received(false);

// 用于保护终端输出的互斥锁
std::mutex cout_mutex; // 用于保护 std::cout, std::cin

// 用于保护共享状态变量（设备列表、系统信息等）的互斥锁
std::mutex state_mutex;

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
    if (global_screen_ptr) {
        global_screen_ptr->PostEvent(ftxui::Event::Custom);
    }
}

// --- 工具函数 ---
bool has_root_privileges() {
    return geteuid() == 0;
}

// 等待固定时间，确保图片显示足够长的时间
void wait_for_display() {
    write_debug_log("显示图片，等待3秒...");

    // 显示提示信息
    std::cout << std::endl << "========== 图片查看模式 ==========" << std::endl;
    std::cout << "请查看上方显示的图片" << std::endl;
    std::cout << "图片将显示 3 秒后自动返回..." << std::endl;
    std::cout << "=================================" << std::endl;

    // 刷新标准输出，确保提示信息立即显示
    std::cout.flush();

    // 等待3秒，确保图片显示足够长的时间
    for (int i = 0; i < 3; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "." << std::flush;  // 显示进度点
    }

    std::cout << std::endl << "显示时间结束，返回主界面..." << std::endl;
    write_debug_log("等待结束，继续执行...");

    // 再等待1秒，确保用户看到返回提示
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

std::string exec_command(const std::string& cmd, int timeout_ms = 5000, bool ignore_nonzero_exit = false) {
    write_debug_log("开始执行命令: " + cmd + " (超时: " + std::to_string(timeout_ms) + "ms, 忽略非零退出码: " + (ignore_nonzero_exit ? "true" : "false") + ")");
    std::array<char, 256> buffer;
    std::string result;
    std::string full_cmd = cmd + " 2>&1";
    write_debug_log("执行完整命令: " + full_cmd);
    FILE* pipe = popen(full_cmd.c_str(), "r");
    if (!pipe) {
        write_debug_log("错误: popen() 调用失败! errno: " + std::string(strerror(errno)));
        return "错误: popen() 调用失败!";
    }
    int fd = fileno(pipe);
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        write_debug_log("错误: fcntl(F_GETFL) 调用失败! errno: " + std::string(strerror(errno)));
        pclose(pipe);
        return "错误: fcntl(F_GETFL) 调用失败!";
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        write_debug_log("错误: fcntl(F_SETFL, O_NONBLOCK) 调用失败! errno: " + std::string(strerror(errno)));
        pclose(pipe);
        return "错误: fcntl(F_SETFL, O_NONBLOCK) 调用失败!";
    }
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

        int poll_ret = poll(&pfd, 1, remaining_timeout);

        if (poll_ret > 0) {
            if (pfd.revents & POLLIN) {
                ssize_t n;
                while ((n = read(fd, buffer.data(), buffer.size() - 1)) > 0) {
                    buffer[n] = '\0';
                    result.append(buffer.data());
                }
                if (n == 0) {
                    write_debug_log("读取完成 (EOF)");
                    break;
                } else if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        continue;
                    } else {
                        std::string error_msg = "错误: 从管道读取数据失败: " + std::string(strerror(errno));
                        write_debug_log(error_msg);
                        result = error_msg;
                        goto close_pipe;
                    }
                }
            } else if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                write_debug_log("管道错误或关闭 (POLLERR/POLLHUP/POLLNVAL)");
                 ssize_t n;
                 while ((n = read(fd, buffer.data(), buffer.size() - 1)) > 0) {
                     buffer[n] = '\0';
                     result.append(buffer.data());
                 }
                goto close_pipe;
            }
        } else if (poll_ret == 0) {
            timed_out = true;
            write_debug_log("poll() 超时");
            break;
        } else {
            if (errno == EINTR) {
                continue;
            }
            std::string error_msg = "错误: poll() 调用失败: " + std::string(strerror(errno));
            write_debug_log(error_msg);
            result = error_msg;
            goto close_pipe;
        }
    }

close_pipe:
    int status = pclose(pipe);
    if (timed_out) {
         write_debug_log("命令执行结果: 超时 (部分结果可能已读取)");
         if (result.rfind("错误:", 0) != 0) {
            result += (result.empty() ? "" : "\n") + std::string("错误: 命令执行超时");
         } else if (result.find("超时") == std::string::npos) {
            result += " (且命令执行超时)";
         }
         return result;
    }

    if (status == -1) {
        write_debug_log("错误: pclose() 调用失败! errno: " + std::string(strerror(errno)));
        if (result.rfind("错误:", 0) != 0) {
            return "错误: pclose() 调用失败!";
        }
    } else if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        write_debug_log("命令退出状态码: " + std::to_string(exit_code));
        if (exit_code != 0 && !ignore_nonzero_exit) {
            std::string error_msg = "错误: 命令退出状态码 " + std::to_string(exit_code) + (result.empty() ? "" : (": " + result));
             write_debug_log("命令执行结果 (错误): " + error_msg);
            return error_msg;
        }
    } else if (WIFSIGNALED(status)) {
        write_debug_log("命令被信号终止: " + std::to_string(WTERMSIG(status)));
        if (!ignore_nonzero_exit) {
            std::string error_msg = "错误: 命令被信号 " + std::to_string(WTERMSIG(status)) + " 终止" + (result.empty() ? "" : (": " + result));
            write_debug_log("命令执行结果 (错误): " + error_msg);
            return error_msg;
        }
    } else {
        write_debug_log("命令未正常退出 (未知状态)。");
         if (!ignore_nonzero_exit) {
            std::string error_msg = "错误: 命令未正常退出" + (result.empty() ? "" : (": " + result));
            write_debug_log("命令执行结果 (错误): " + error_msg);
            return error_msg;
        }
    }

    if (result.rfind("错误:", 0) != 0 && !result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    write_debug_log("命令执行完成，结果长度: " + std::to_string(result.length()) + " 字节");
    return result;
}

// --- 设备查找函数 ---
struct VideoDeviceInfo {
    std::string path;
    std::map<std::string, std::vector<std::string>> resolutions_by_format;
};

std::vector<VideoDeviceInfo> find_video_devices() {
    write_debug_log("开始查找 USB 视频设备");
    std::vector<VideoDeviceInfo> devices;

    if (!has_root_privileges()) {
        write_debug_log("错误: 没有 root 权限，无法查找 USB 视频设备");
        return devices;
    }

    std::string list_devices_cmd = "v4l2-ctl --list-devices";
    std::string list_devices_result = exec_command(list_devices_cmd, 5000, true);

    if (list_devices_result.rfind("错误:", 0) == 0 && list_devices_result.find("超时") != std::string::npos) {
         write_debug_log("执行 v4l2-ctl --list-devices 超时");
         return devices;
    }
    if (list_devices_result.rfind("错误:", 0) == 0) {
        write_debug_log("执行 v4l2-ctl --list-devices 失败: " + list_devices_result);
        return devices;
    }

    write_debug_log("v4l2-ctl --list-devices 输出:\n" + list_devices_result);
    std::istringstream iss(list_devices_result);
    std::string line;
    std::vector<std::string> usb_video_paths;
    std::regex usb_device_desc_regex(".*\\(usb-.*\\):");
    std::regex indented_device_path_regex("^\\s*(\\/dev\\/video\\d+)$");
    std::smatch indented_device_path_match;
    bool processing_usb_device_group = false;

    iss.clear();
    iss.seekg(0);

    while (std::getline(iss, line)) {
        if (std::regex_search(line, usb_device_desc_regex)) {
            processing_usb_device_group = true;
        } else if (processing_usb_device_group) {
            if (std::regex_match(line, indented_device_path_match, indented_device_path_regex) && indented_device_path_match.size() > 1) {
                 std::string device_path = indented_device_path_match[1].str();
                 usb_video_paths.push_back(device_path);
            } else if (!line.empty() && !std::isspace(static_cast<unsigned char>(line[0]))) {
                 processing_usb_device_group = false;
            } else if (line.empty()) {
                 processing_usb_device_group = false;
            }
        }
    }

    std::sort(usb_video_paths.begin(), usb_video_paths.end());
    usb_video_paths.erase(std::unique(usb_video_paths.begin(), usb_video_paths.end()), usb_video_paths.end());

    for (const auto& device_path : usb_video_paths) {
        std::string check_cmd = "v4l2-ctl --device " + device_path + " --list-formats-ext";
        std::string check_result = exec_command(check_cmd, 3000, false);

        write_debug_log("v4l2-ctl --device " + device_path + " --list-formats-ext 输出:\n" + check_result);

        std::regex resolution_line_regex("Size: (Discrete|Stepwise) (\\d+x\\d+)");
        bool resolution_found_by_regex = std::regex_search(check_result, resolution_line_regex);
        bool command_successful_and_resolution_found = (check_result.rfind("错误:", 0) != 0 && resolution_found_by_regex);

        if (command_successful_and_resolution_found) {
            VideoDeviceInfo info;
            info.path = device_path;
            std::istringstream format_stream(check_result);
            std::string format_line;
            std::string current_format = "未知格式";
            std::regex format_name_regex("\\[\\d+\\]:\\s*'(.*?)'");
            std::smatch format_name_match;
            std::regex res_regex("Size: (Discrete|Stepwise)\\s*(\\d+x\\d+)");
            std::smatch res_match;

            while (std::getline(format_stream, format_line)) {
                if (std::regex_search(format_line, format_name_match, format_name_regex) && format_name_match.size() > 1) {
                    current_format = format_name_match[1].str();
                }
                else if (std::regex_search(format_line, res_match, res_regex) && res_match.size() > 2) {
                    info.resolutions_by_format[current_format].push_back(res_match[2].str());
                }
            }
            bool resolutions_extracted = false;
            for(const auto& pair : info.resolutions_by_format) {
                if (!pair.second.empty()) {
                    resolutions_extracted = true;
                    break;
                }
            }
            if (resolutions_extracted) {
                 devices.push_back(info);
            } else {
                write_debug_log("设备 " + device_path + " 支持格式但未提取到任何分辨率，跳过");
            }
        } else {
             write_debug_log("设备 " + device_path + " 不支持视频格式或查询失败。检查结果: " + check_result.substr(0,100) + "...");
        }
    }
    return devices;
}

std::vector<std::string> find_serial_devices() {
    write_debug_log("开始查找串口设备");
    std::vector<std::string> devices_found;
    if (!has_root_privileges()) {
        write_debug_log("错误: 没有 root 权限，无法查找串口设备");
        return devices_found;
    }
    std::string result = exec_command("ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null || echo ''", 1000, true);
     if (result.rfind("错误:", 0) == 0 || result.empty()) {
         write_debug_log("查找串口设备失败或未找到设备: " + result);
         return devices_found;
     }
    std::istringstream iss(result);
    std::string device_path;
    while (iss >> device_path) {
        if (!device_path.empty()) {
            devices_found.push_back(device_path);
        }
    }
    return devices_found;
}

// --- 系统信息获取函数 ---
struct SystemInfo {
    std::string hostname;
    std::string uptime;
    std::string memory;
    std::string os_version;
    std::string cpu_info;
    std::string network_info;
    std::string cpu_temperature_avg;
    std::vector<std::string> ip_addresses;
    bool has_root = false;

    void refresh() {
        has_root = has_root_privileges();
        hostname = exec_command("hostname", 1000);
        uptime = exec_command("uptime -p", 1000);
        memory = exec_command("free -m | grep Mem | awk '{print $3\"MB used / \"$2\"MB total\"}'", 1000);
        os_version = exec_command("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2", 1000);
        cpu_info = exec_command("lscpu | grep 'Model name:' | sed -r 's/Model name:\\s*//g'", 1000);

        auto ip_a_result = exec_command("ip -4 a show scope global", 2000, true);
        ip_addresses.clear();
        if (ip_a_result.rfind("错误:", 0) != 0) {
            std::istringstream ip_a_iss(ip_a_result);
            std::string ip_a_line;
            std::regex ip_iface_regex("inet (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})/\\d+\\s.*\\s(\\S+)$");
            std::smatch ip_match;
            while(std::getline(ip_a_iss, ip_a_line)) {
                 if (std::regex_search(ip_a_line, ip_match, ip_iface_regex) && ip_match.size() > 2) {
                     ip_addresses.push_back(ip_match[2].str() + ": " + ip_match[1].str());
                 }
            }
        } else {
            write_debug_log("获取IP地址失败: " + ip_a_result);
        }

        std::string ssid = exec_command("iwgetid -r", 1000, true);
        if (ssid.rfind("错误:", 0) == 0 || ssid.empty()) {
            ssid = "获取失败";
        }

        std::stringstream network_info_ss;
        if (!ip_addresses.empty()) {
            network_info_ss << "活跃接口: ";
            for(size_t i = 0; i < ip_addresses.size(); ++i) {
                network_info_ss << ip_addresses[i];
                if (i < ip_addresses.size() - 1) network_info_ss << ", ";
            }
            if (ssid != "获取失败") network_info_ss << " | WiFi: " << ssid;
        } else {
            network_info_ss << "网络: 未连接或无IP";
            if (ssid != "获取失败") network_info_ss << " | WiFi: " << ssid;
        }
        network_info = network_info_ss.str();

        std::string temp_result = exec_command("cat /sys/class/thermal/thermal_zone*/temp", 1000, true);
        std::vector<double> temperatures_milli;
        if (temp_result.rfind("错误:", 0) != 0) {
            std::istringstream temp_iss(temp_result);
            std::string temp_line;
            while(std::getline(temp_iss, temp_line)) {
                if (!temp_line.empty()) {
                    try { temperatures_milli.push_back(std::stod(temp_line)); }
                    catch (const std::invalid_argument& ia) { write_debug_log("无效温度值: " + temp_line + " Error: " + ia.what()); }
                    catch (const std::out_of_range& oor) { write_debug_log("温度值超出范围: " + temp_line + " Error: " + oor.what()); }
                }
            }
        }
        if (!temperatures_milli.empty()) {
            double sum_temp = std::accumulate(temperatures_milli.begin(), temperatures_milli.end(), 0.0);
            double average_celsius = (sum_temp / temperatures_milli.size()) / 1000.0;
            std::stringstream temp_ss;
            temp_ss << std::fixed << std::setprecision(1) << average_celsius << "°C";
            cpu_temperature_avg = temp_ss.str();
        } else {
            cpu_temperature_avg = "获取失败";
        }
    }
};

// --- 串口通信类 ---
class SerialPort {
public:
    SerialPort() : fd_(-1) {}
    ~SerialPort() { close(); }
    bool open(const std::string& port) {
        if (fd_ >= 0) close();
        fd_ = ::open(port.c_str(), O_RDWR | O_NOCTTY | O_NDELAY);
        if (fd_ < 0) {
            write_debug_log("打开串口失败: " + port + " - " + strerror(errno));
            return false;
        }
        fcntl(fd_, F_SETFL, 0);

        termios tty;
        if (tcgetattr(fd_, &tty) != 0) {
            write_debug_log("tcgetattr 失败: " + port + " - " + strerror(errno));
            close(); return false;
        }
        cfsetospeed(&tty, B115200); cfsetispeed(&tty, B115200);
        tty.c_cflag |= (CLOCAL | CREAD);
        tty.c_cflag &= ~CSIZE; tty.c_cflag |= CS8;
        tty.c_cflag &= ~PARENB; tty.c_cflag &= ~CSTOPB;
        tty.c_cflag &= ~CRTSCTS;

        tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXOFF|IXANY);
        tty.c_lflag = 0;
        tty.c_oflag = 0;

        tty.c_cc[VMIN] = 0;
        tty.c_cc[VTIME] = 5;

        if (tcsetattr(fd_, TCSANOW, &tty) != 0) {
            write_debug_log("tcsetattr 失败: " + port + " - " + strerror(errno));
            close(); return false;
        }
        int current_flags = fcntl(fd_, F_GETFL, 0);
        fcntl(fd_, F_SETFL, current_flags | O_NONBLOCK);

        write_debug_log("串口打开成功: " + port);
        return true;
    }
    void close() { if (fd_ >= 0) ::close(fd_); fd_ = -1; write_debug_log("串口已关闭");}
    bool is_open() const { return fd_ >= 0; }
    std::string read_data() {
        if (fd_ < 0) return "";
        char buffer[256]; std::string data; ssize_t n;
        n = ::read(fd_, buffer, sizeof(buffer) - 1);
        if (n > 0) {
            buffer[n] = '\0';
            data.append(buffer);
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            write_debug_log("串口读取错误: " + std::string(strerror(errno)));
        }
        return data;
    }
private:
    int fd_;
};


int main() {
    clear_debug_log();
    write_debug_log("程序启动");

    std::signal(SIGTERM, handle_terminate_signal);
    std::signal(SIGINT, handle_terminate_signal);

    auto screen = ScreenInteractive::Fullscreen();
    global_screen_ptr = &screen;

    SystemInfo sys_info;
    std::atomic<bool> initial_load_complete(false);
    std::vector<VideoDeviceInfo> video_devices;
    std::vector<std::string> serial_devices_list;
    int selected_video = 0;
    int selected_serial = 0;
    std::atomic<bool> serial_connected(false);
    std::unique_ptr<SerialPort> serial_port;
    std::atomic<bool> is_capturing(false);
    std::string camera_status_message = "";
    std::string last_captured_image_path = "";

    std::string connect_button_label_str = "连接";
    std::string capture_button_label_str = "获取图片";

    std::thread initial_load_thread([&] {
        write_debug_log("初始加载线程开始");
        {
            std::lock_guard<std::mutex> lock(state_mutex);
            sys_info.refresh();
            video_devices = find_video_devices();
            serial_devices_list = find_serial_devices();
            connect_button_label_str = serial_connected.load() ? "断开" : "连接";
            capture_button_label_str = is_capturing.load() ? "采集中..." : "获取图片";
        }
        initial_load_complete = true;
        write_debug_log("初始加载完成，发送 UI 更新事件");
        screen.PostEvent(ftxui::Event::Custom);
    });
    initial_load_thread.detach();

    int tab_selected = 0;
    std::vector<std::string> tab_titles = {"串口", "摄像头", "系统"};

    auto serial_status = Renderer([&] {
        std::string status_str = serial_connected.load() ? "已连接" : "未连接";
        Color status_color = serial_connected.load() ? Color::Green : Color::RedLight;

        // 创建一个带有框线的状态显示，但保持简约风格
        return window(
            text(" 串口状态 "),
            hbox({
                text("状态: ") | dim,
                text(status_str) | color(status_color)
            })
        ) | border;
    });

    auto serial_list_container = Container::Vertical({});

    ButtonOption connect_button_options;
    connect_button_options.label = &connect_button_label_str;
    connect_button_options.on_click = [&] {
        write_debug_log("点击连接/断开串口按钮...");
        std::lock_guard<std::mutex> state_lock(state_mutex);
        if (serial_connected.load()) {
            if(serial_port) serial_port->close();
            serial_port.reset();
            serial_connected = false;
            connect_button_label_str = "连接";
            write_debug_log("串口已断开。");
        } else if (!serial_devices_list.empty()) {
            serial_port = std::make_unique<SerialPort>();
            if (selected_serial >= 0 && static_cast<size_t>(selected_serial) < serial_devices_list.size()) {
                 if (serial_port->open(serial_devices_list[static_cast<size_t>(selected_serial)])) {
                    serial_connected = true;
                    connect_button_label_str = "断开";
                    write_debug_log("串口已连接: " + serial_devices_list[static_cast<size_t>(selected_serial)]);
                 } else {
                     serial_connected = false;
                     connect_button_label_str = "连接";
                     write_debug_log("连接串口失败: " + serial_devices_list[static_cast<size_t>(selected_serial)]);
                     serial_port.reset();
                 }
            } else {
                 serial_connected = false;
                 connect_button_label_str = "连接";
                 write_debug_log("错误: 选定的串口设备索引越界，无法尝试连接。");
                 serial_port.reset();
            }
        } else {
             serial_connected = false;
             connect_button_label_str = "连接";
             write_debug_log("错误: 没有可用的串口设备进行连接。");
        }
        screen.PostEvent(ftxui::Event::Custom);
    };
    // 创建一个简化的按钮，减少边框线条
    auto connect_button = Renderer([&] {
        return text(serial_connected.load() ? "断开" : "连接") | center;
    });

    // 添加点击事件
    connect_button = CatchEvent(connect_button, [&](Event event) {
        if (event == Event::Return || event.mouse().button == Mouse::Left) {
            if (serial_connected.load()) {
                write_debug_log("点击断开按钮");
                std::thread disconnect_thread([&] {
                    // 使用原来的断开逻辑
                    if(serial_port) serial_port->close();
                    serial_port.reset();
                    serial_connected = false;

                    std::lock_guard<std::mutex> lock(state_mutex);
                    connect_button_label_str = "连接";
                    write_debug_log("串口已断开。");
                    screen.PostEvent(ftxui::Event::Custom);
                });
                disconnect_thread.detach();
            } else {
                write_debug_log("点击连接按钮");
                std::thread connect_thread([&] {
                    // 使用原来的连接逻辑
                    if (!serial_devices_list.empty()) {
                        serial_port = std::make_unique<SerialPort>();
                        if (selected_serial >= 0 && static_cast<size_t>(selected_serial) < serial_devices_list.size()) {
                            if (serial_port->open(serial_devices_list[static_cast<size_t>(selected_serial)])) {
                                serial_connected = true;

                                std::lock_guard<std::mutex> lock(state_mutex);
                                connect_button_label_str = "断开";
                                write_debug_log("串口已连接: " + serial_devices_list[static_cast<size_t>(selected_serial)]);
                                screen.PostEvent(ftxui::Event::Custom);
                            } else {
                                serial_connected = false;

                                std::lock_guard<std::mutex> lock(state_mutex);
                                connect_button_label_str = "连接";
                                write_debug_log("连接串口失败: " + serial_devices_list[static_cast<size_t>(selected_serial)]);
                                serial_port.reset();
                                screen.PostEvent(ftxui::Event::Custom);
                            }
                        } else {
                            serial_connected = false;

                            std::lock_guard<std::mutex> lock(state_mutex);
                            connect_button_label_str = "连接";
                            write_debug_log("错误: 选定的串口设备索引越界，无法尝试连接。");
                            serial_port.reset();
                            screen.PostEvent(ftxui::Event::Custom);
                        }
                    } else {
                        serial_connected = false;

                        std::lock_guard<std::mutex> lock(state_mutex);
                        connect_button_label_str = "连接";
                        write_debug_log("错误: 没有可用的串口设备进行连接。");
                        screen.PostEvent(ftxui::Event::Custom);
                    }
                });
                connect_thread.detach();
            }
            return true;
        }
        return false;
    });

    auto camera_status_renderer = Renderer([&] {
        std::lock_guard<std::mutex> lock(state_mutex);
        if (camera_status_message.empty()) {
            return emptyElement();
        }

        // 错误时使用浅红色，但添加框线
        Element message_element;
        if (camera_status_message.find("错误") != std::string::npos ||
            camera_status_message.find("失败") != std::string::npos) {
            // 使用 Color::RedLight 代替 Color::Red，颜色更柔和
            message_element = text(camera_status_message) | color(Color::RedLight);
        } else {
            message_element = text(camera_status_message);
        }

        return window(
            text(" 摄像头状态 "),
            message_element
        ) | border | flex;
    });

    ButtonOption capture_button_options;
    capture_button_options.label = &capture_button_label_str;
    capture_button_options.on_click = [&] {
        write_debug_log("点击获取图片按钮");
        std::string device_path_copy;
        std::string output_file_copy;
        {
            std::lock_guard<std::mutex> state_lock(state_mutex);
            if (is_capturing.load()) {
                write_debug_log("正在采集图片，忽略新的点击（在锁内检查）");
                return;
            }
            if (video_devices.empty() || selected_video < 0 || static_cast<size_t>(selected_video) >= video_devices.size()) {
                camera_status_message = "错误: 没有选中的摄像头设备。";
                write_debug_log(camera_status_message);
                screen.PostEvent(ftxui::Event::Custom);
                return;
            }
            is_capturing = true;
            capture_button_label_str = "采集中...";
            device_path_copy = video_devices[static_cast<size_t>(selected_video)].path;
            camera_status_message = "正在采集图片 (" + device_path_copy + ")...";
            write_debug_log("开始图片采集过程 (使用 v4l2-ctl)...");
            std::string device_number = "unknown";
            size_t video_pos = device_path_copy.rfind("video");
            if (video_pos != std::string::npos) {
                device_number = device_path_copy.substr(video_pos + 5);
            }
            auto now_ts = std::chrono::system_clock::now();
            auto now_c_ts = std::chrono::system_clock::to_time_t(now_ts);
            std::tm tm_buffer_ts;
            std::stringstream time_ss;
            if (localtime_r(&now_c_ts, &tm_buffer_ts)) {
                time_ss << std::put_time(&tm_buffer_ts, "%Y%m%d_%H%M%S");
            } else {
                time_ss << "timestamp_error";
            }
            std::string resolution = "640x480";
            output_file_copy = "./video" + device_number + "_" + time_ss.str() + "_" + resolution + ".jpg";
        }
        screen.PostEvent(ftxui::Event::Custom);
        std::string capture_cmd = "v4l2-ctl --device " + device_path_copy + " --set-fmt-video=width=640,height=480 --stream-mmap --stream-count=1 --stream-to=" + output_file_copy;
        std::thread capture_thread([&, capture_cmd, output_file = output_file_copy, device_path = device_path_copy] {
            write_debug_log("采集线程开始执行命令: " + capture_cmd);
            std::string capture_result = exec_command(capture_cmd, 10000, false);
            std::lock_guard<std::mutex> thread_state_lock(state_mutex);
            is_capturing = false;
            capture_button_label_str = "获取图片";
            if (capture_result.rfind("错误:", 0) == 0) {
                camera_status_message = "采集失败 (" + device_path + "): " + capture_result;
            } else {
                std::ifstream file_check(output_file, std::ios::binary | std::ios::ate);
                if (file_check.good() && file_check.tellg() > 0) {
                    camera_status_message = "图片采集成功 (" + device_path + "): " + output_file;
                    last_captured_image_path = output_file;
                } else {
                    camera_status_message = "采集命令执行，但输出文件无效或为空 (" + device_path + "): " + output_file + ". v4l2-ctl 输出: " + capture_result.substr(0, 200) + "...";
                }
            }
             write_debug_log(camera_status_message);
            screen.PostEvent(ftxui::Event::Custom);
        });
        capture_thread.detach();
    };
    auto capture_button_component = Button(capture_button_options);
    // 极简风格 - 不添加背景色
    capture_button_component = Renderer(capture_button_component, [&] {
        Element button_renderer = capture_button_component->Render();
        return button_renderer;
    });

    // 创建显示图片按钮
    ButtonOption show_image_button_options;
    show_image_button_options.label = "显示图片";
    show_image_button_options.on_click = [&] {
        write_debug_log("点击显示图片按钮");
        std::string local_last_captured_image_path_copy;
        {
            std::lock_guard<std::mutex> lock(state_mutex);
            local_last_captured_image_path_copy = last_captured_image_path;
            if (local_last_captured_image_path_copy.empty()) {
                camera_status_message = "错误: 没有捕获的图片可显示。";
                write_debug_log(camera_status_message);
                screen.PostEvent(ftxui::Event::Custom);
                return;
            }
            camera_status_message = "尝试使用 timg 显示: " + local_last_captured_image_path_copy;
        }
        screen.PostEvent(ftxui::Event::Custom);

        // 直接在主线程中显示图片，确保图片能够正常显示
        write_debug_log("准备显示图片: " + local_last_captured_image_path_copy);

        // 先退出 FTXUI 界面，这样可以完全控制终端
        screen.Exit();

        // 清屏
        std::system("clear");

        // 显示图片 - 使用更可靠的方式
        std::string timg_cmd = "timg -g $(tput cols)x$(tput lines) \"" + local_last_captured_image_path_copy + "\"";
        write_debug_log("执行 timg 命令: " + timg_cmd);

        // 确保命令输出被立即显示
        std::cout << "正在加载图片..." << std::endl;
        std::cout.flush();

        // 执行命令并捕获返回值
        int timg_ret = std::system(timg_cmd.c_str());

        // 确保图片显示后有一点延迟，防止一闪而过
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // 显示提示并等待固定时间
        if (timg_ret == 0) {
            std::cout << "图片 '" << local_last_captured_image_path_copy << "' 已显示。" << std::endl;
        } else {
            std::cout << "timg 命令执行可能存在问题 (返回码: " << timg_ret << ")。" << std::endl;
            if (WIFEXITED(timg_ret) && WEXITSTATUS(timg_ret) == 127) {
                std::cout << "提示: timg 命令可能未找到或无法执行。" << std::endl;
            }
        }

        // 等待固定时间
        wait_for_display();

        // 清屏，准备重新进入 FTXUI 界面
        std::system("clear");
        std::cout << "正在返回主界面..." << std::endl;

        // 更新状态信息
        {
            std::lock_guard<std::mutex> lock(state_mutex);
            if (timg_ret == 0) {
                camera_status_message = "图片查看结束。";
            } else {
                bool command_not_found = false;
                if (WIFEXITED(timg_ret)) {
                    if (WEXITSTATUS(timg_ret) == 127) {
                        command_not_found = true;
                    }
                } else if (timg_ret == -1) {
                    command_not_found = true;
                }
                if (command_not_found) {
                    camera_status_message = "错误: timg 命令未找到或执行失败。";
                } else {
                    camera_status_message = "timg 显示图片时返回错误 (代码: " + std::to_string(WEXITSTATUS(timg_ret)) + ")";
                }
            }
            write_debug_log(camera_status_message);
        }
    };

    auto video_list_container = Container::Vertical({});

    // 创建显示图片按钮
    auto show_image_button = Button(show_image_button_options);

    // 极简风格 - 不添加背景色
    show_image_button = Renderer(show_image_button, [show_image_button] {
        Element button_renderer = show_image_button->Render();
        return button_renderer;
    });

    // 创建刷新设备列表按钮
    ButtonOption refresh_button_options;
    refresh_button_options.label = "刷新设备列表";
    refresh_button_options.on_click = [&] {
        write_debug_log("点击刷新设备列表按钮");
        std::thread refresh_thread([&] {
            auto new_video_devices = find_video_devices();
            std::lock_guard<std::mutex> lock(state_mutex);
            video_devices = new_video_devices;
            screen.PostEvent(ftxui::Event::Custom);
        });
        refresh_thread.detach();
    };

    // 创建刷新设备列表按钮
    auto refresh_button = Button(refresh_button_options);

    // 极简风格 - 不添加背景色
    refresh_button = Renderer(refresh_button, [refresh_button] {
        Element button_renderer = refresh_button->Render();
        return button_renderer;
    });

    std::vector<Component> camera_action_buttons;
    camera_action_buttons.push_back(capture_button_component);
    camera_action_buttons.push_back(show_image_button);
    camera_action_buttons.push_back(refresh_button);
    auto camera_action_buttons_container = Container::Horizontal(camera_action_buttons);
    std::vector<Component> camera_tab_components;
    camera_tab_components.push_back(Renderer([&] {
         std::lock_guard<std::mutex> state_lock(state_mutex);
         if (!initial_load_complete.load()) {
             std::vector<Element> elements;
             elements.push_back(text("正在加载设备信息...") | hcenter | flex);
             return vbox(elements);
         }
         if (!sys_info.has_root) {
             std::vector<Element> elements;
             elements.push_back(text("查找摄像头需要 root 权限。") | hcenter | flex);
             return vbox(elements);
         }
         if (video_devices.empty()) {
             std::vector<Element> elements;
             elements.push_back(text("未找到支持的 USB 摄像头设备。") | hcenter | flex);
             return vbox(elements);
         }
         return emptyElement();
    }));
    camera_tab_components.push_back(video_list_container);
    camera_tab_components.push_back(camera_action_buttons_container);
    camera_tab_components.push_back(camera_status_renderer);
    auto camera_tab_content_container = Container::Vertical(camera_tab_components);

    auto system_info_renderer = Renderer([&] {
         if (!initial_load_complete.load()) {
             std::vector<Element> elements;
             elements.push_back(text("正在加载设备信息...") | hcenter | flex);
             return vbox(elements);
         }
        std::lock_guard<std::mutex> state_lock(state_mutex);
        Elements ip_elements_list;
        ip_elements_list.push_back(text("IP 地址: ") | dim);
        if (sys_info.ip_addresses.empty()) {
            ip_elements_list.push_back(text("获取失败或未连接"));
        } else {
            std::stringstream ip_line_ss_render;
            for(size_t i = 0; i < sys_info.ip_addresses.size(); ++i) {
                ip_line_ss_render << sys_info.ip_addresses[i];
                if (i < sys_info.ip_addresses.size() - 1) ip_line_ss_render << ", ";
            }
            ip_elements_list.push_back(text(ip_line_ss_render.str()));
        }

        // 创建系统信息项目 - 极简风格
        std::vector<Element> info_items;
        info_items.push_back(hbox({text("主机名: ") | dim, text(sys_info.hostname)}));
        info_items.push_back(hbox({text("系统: ") | dim, text(sys_info.os_version)}));
        info_items.push_back(hbox({text("内存: ") | dim, text(sys_info.memory)}));
        info_items.push_back(hbox({text("运行时间: ") | dim, text(sys_info.uptime)}));
        info_items.push_back(hbox({text("网络: ") | dim, text(sys_info.network_info)}));

        // CPU 温度显示 - 只保留必要的颜色
        Element temp_element;
        if (sys_info.cpu_temperature_avg == "获取失败") {
            temp_element = text(sys_info.cpu_temperature_avg);
        } else {
            // 尝试提取温度数值
            std::string temp_str = sys_info.cpu_temperature_avg;
            size_t pos = temp_str.find("°C");
            if (pos != std::string::npos) {
                temp_str = temp_str.substr(0, pos);
            }

            try {
                double temp = std::stod(temp_str);
                if (temp > 70.0) {
                    // 高温时使用浅红色警示，更加柔和
                    temp_element = text(sys_info.cpu_temperature_avg) | color(Color::RedLight);
                } else {
                    temp_element = text(sys_info.cpu_temperature_avg);
                }
            } catch (...) {
                temp_element = text(sys_info.cpu_temperature_avg);
            }
        }

        info_items.push_back(hbox({text("CPU 温度 (平均): ") | dim, temp_element}));
        info_items.push_back(hbox(ip_elements_list));

        // 创建一个带有框线的信息框，但保持简约风格
        auto info_box = window(
            text(" 系统信息 "),
            vbox(info_items)
        ) | border;

        std::vector<Element> container;
        container.push_back(info_box);
        return vbox(container);
    });

    // 创建刷新所有信息按钮
    ButtonOption refresh_all_button_options;
    refresh_all_button_options.label = "刷新所有信息";
    refresh_all_button_options.on_click = [&] {
        write_debug_log("点击刷新所有信息按钮");
        std::thread refresh_thread([&] {
            std::unique_lock<std::mutex> lock(state_mutex);
            sys_info.refresh();
            auto new_video_devices = find_video_devices();
            auto new_serial_devices = find_serial_devices();
            video_devices = new_video_devices;
            serial_devices_list = new_serial_devices;
            connect_button_label_str = serial_connected.load() ? "断开" : "连接";
            capture_button_label_str = is_capturing.load() ? "采集中..." : "获取图片";
            lock.unlock();
            screen.PostEvent(ftxui::Event::Custom);
        });
        refresh_thread.detach();
    };

    // 创建刷新所有信息按钮
    auto refresh_all_button = Button(refresh_all_button_options);

    // 极简风格 - 不添加背景色
    refresh_all_button = Renderer(refresh_all_button, [refresh_all_button] {
        Element button_renderer = refresh_all_button->Render();
        return button_renderer;
    });

    // 创建标签页内容
    std::vector<Component> tab_components;

    // 串口标签页
    std::vector<Component> serial_tab_components;
    serial_tab_components.push_back(serial_status);
    serial_tab_components.push_back(serial_list_container);
    serial_tab_components.push_back(connect_button);
    tab_components.push_back(Container::Vertical(serial_tab_components));

    // 摄像头标签页
    tab_components.push_back(camera_tab_content_container);

    // 系统标签页
    std::vector<Component> system_tab_components;
    system_tab_components.push_back(system_info_renderer);
    system_tab_components.push_back(refresh_all_button);
    tab_components.push_back(Container::Vertical(system_tab_components));

    auto tab_container = Container::Tab(tab_components, &tab_selected);

    std::vector<Component> tab_buttons;
    for (size_t i = 0; i < tab_titles.size(); ++i) {
        size_t index = i; // 捕获当前索引的副本

        ButtonOption tab_button_option;
        tab_button_option.label = tab_titles[i];
        tab_button_option.on_click = [&, index] {
            tab_selected = static_cast<int>(index);
        };

        auto tab_button = Button(tab_button_option);

        // 极简风格 - 使用淡淡的背景色标记选中的标签，而不是下划线
        tab_button = Renderer(tab_button, [tab_button, index, &tab_selected] {
            Element button_renderer = tab_button->Render();
            if (static_cast<int>(index) == tab_selected) {
                return button_renderer | bgcolor(Color::GrayDark);
            } else {
                return button_renderer;
            }
        });

        tab_buttons.push_back(tab_button);
    }
    auto tab_select = Container::Horizontal(tab_buttons);

    // 创建退出按钮
    bool should_exit_flag = false; // 用于标记是否应该退出程序

    ButtonOption quit_button_options;
    quit_button_options.label = "退出";
    quit_button_options.on_click = [&] {
        write_debug_log("点击退出按钮");
        should_exit_flag = true;
        screen.Exit();
    };

    // 使用标准按钮组件，确保可以正常点击
    auto quit_button_component = Button(quit_button_options);

    // 添加简单的样式
    auto quit_button = Renderer(quit_button_component, [&quit_button_component] {
        return quit_button_component->Render() | bold | center;
    });
    std::vector<Component> main_components;
    main_components.push_back(tab_select);
    main_components.push_back(tab_container);
    main_components.push_back(quit_button);
    auto main_container = Container::Vertical(main_components);

    auto main_renderer = Renderer(main_container, [&] {
        std::vector<Element> elements;
        elements.push_back(text("Luban Toolkit") | bold | hcenter);
        // 恢复分隔线，但使用细线
        elements.push_back(separator());
        elements.push_back(tab_select->Render());
        // 恢复分隔线
        elements.push_back(separator());
        elements.push_back(tab_container->Render() | flex);
        // 恢复分隔线
        elements.push_back(separator());
        elements.push_back(quit_button->Render());

        // 添加一个简单的单线边框
        return vbox(elements) | border;
    });

    write_debug_log("进入事件处理循环");

    // 主循环，允许重新启动 FTXUI 界面
    while (!should_exit_flag) {
        auto event_handler = CatchEvent(main_renderer, [&](Event event) {
            if (sigterm_received.load()) {
                write_debug_log("接收到终止信号，退出程序");
                should_exit_flag = true;
                screen.Exit();
                return true;
            }
            if (event == Event::Tab) {
                tab_selected = (tab_selected + 1) % static_cast<int>(tab_titles.size());
                write_debug_log("Tab 键按下，切换到标签页: " + tab_titles[tab_selected]);
                return true;
            }
            if (event.is_character() && event.character() == "q") {
                write_debug_log("按下 'q' 键，退出程序");
                should_exit_flag = true;
                screen.Exit();
                return true;
            }
            if (event == Event::Custom) {
                write_debug_log("处理自定义事件，更新 UI");
                std::lock_guard<std::mutex> state_lock(state_mutex);
            serial_list_container->DetachAllChildren();
            if (!serial_devices_list.empty()) {
                // 添加一个带有框线的标题
                serial_list_container->Add(Renderer([] {
                    return window(
                        text(" 串口设备 "),
                        text("请选择一个设备:")
                    ) | border;
                }));

                for (size_t i = 0; i < serial_devices_list.size(); ++i) {
                    size_t index = i; // 捕获当前索引的副本

                    ButtonOption serial_btn_option;
                    serial_btn_option.label = serial_devices_list[i];
                    serial_btn_option.on_click = [&, index] {
                        std::lock_guard<std::mutex> btn_lock(state_mutex);
                        selected_serial = static_cast<int>(index);
                        write_debug_log("选中串口设备: " + serial_devices_list[selected_serial]);
                    };

                    auto serial_btn = Button(serial_btn_option);

                    // 极简风格 - 使用淡淡的背景色标记选中的设备，而不是下划线
                    serial_btn = Renderer(serial_btn, [serial_btn, index, &selected_serial] {
                        Element button_renderer = serial_btn->Render();
                        if (static_cast<int>(index) == selected_serial) {
                            return button_renderer | bgcolor(Color::GrayDark);
                        } else {
                            return button_renderer;
                        }
                    });

                    serial_list_container->Add(serial_btn);
                }
            } else {
                serial_list_container->Add(Renderer([] {
                    return window(
                        text(" 串口设备 "),
                        text("未找到可用的串口设备")
                    ) | border;
                }));
            }
            video_list_container->DetachAllChildren();
            if (!video_devices.empty()) {
                // 添加一个带有框线的标题
                video_list_container->Add(Renderer([] {
                    return window(
                        text(" 摄像头设备 "),
                        text("请选择一个设备:")
                    ) | border;
                }));

                for (size_t i = 0; i < video_devices.size(); ++i) {
                    std::string name = video_devices[i].path.substr(video_devices[i].path.rfind('/') + 1);
                    auto res_by_fmt = video_devices[i].resolutions_by_format;
                    size_t index = i; // 捕获当前索引的副本

                    ButtonOption video_btn_option;
                    video_btn_option.label = name;
                    video_btn_option.on_click = [&, index] {
                        std::lock_guard<std::mutex> btn_lock(state_mutex);
                        selected_video = static_cast<int>(index);
                        write_debug_log("选中视频设备: " + video_devices[selected_video].path);
                    };

                    auto video_btn = Button(video_btn_option);

                    // 极简风格 - 使用淡淡的背景色标记选中的设备，而不是下划线
                    video_btn = Renderer(video_btn, [video_btn, index, &selected_video] {
                        Element button_renderer = video_btn->Render();
                        if (static_cast<int>(index) == selected_video) {
                            return button_renderer | bgcolor(Color::GrayDark);
                        } else {
                            return button_renderer;
                        }
                    });

                    auto format_renderer = Renderer([res_by_fmt_copy = res_by_fmt] {
                        std::vector<Element> format_elements_list;
                        for (const auto& pair : res_by_fmt_copy) {
                            std::vector<Element> res_elements_horizontal;
                            res_elements_horizontal.push_back(text("  " + pair.first + ": ") | dim);
                            std::stringstream res_line_ss;
                            for(size_t j = 0; j < pair.second.size(); ++j) {
                                res_line_ss << pair.second[j];
                                if (j < pair.second.size() - 1) res_line_ss << " ";
                            }
                            res_elements_horizontal.push_back(text(res_line_ss.str()));
                            format_elements_list.push_back(hbox(res_elements_horizontal));
                        }
                        // 极简风格 - 不使用窗口和边框
                        return vbox(format_elements_list);
                    });

                    std::vector<Component> device_components;
                    device_components.push_back(video_btn);
                    device_components.push_back(format_renderer);
                    video_list_container->Add(Container::Vertical(device_components));
                }
            } else {
                video_list_container->Add(Renderer([] {
                    return window(
                        text(" 摄像头设备 "),
                        text("未找到可用的摄像头设备")
                    ) | border;
                }));
            }
            return true;
        }
        return main_container->OnEvent(event);
    });

        // 运行 FTXUI 界面循环
        screen.Loop(event_handler);

        // 如果是因为显示图片而退出循环，但不是真正要退出程序，则继续循环
        if (!should_exit_flag) {
            write_debug_log("FTXUI 界面循环退出，但程序继续运行");
        }
    }

    write_debug_log("退出事件处理循环");

    if (serial_port && serial_port->is_open()) {
         serial_port->close();
    }
    write_debug_log("程序退出");
    return 0;
}
