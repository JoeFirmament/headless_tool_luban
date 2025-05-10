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
        Color status_color = serial_connected.load() ? Color::Green : Color::Red;
        return hbox({text("状态: ") | dim, text(status_str) | color(status_color)});
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
    auto connect_button = Button(connect_button_options);

    auto camera_status_renderer = Renderer([&] {
        std::lock_guard<std::mutex> lock(state_mutex); 
        return text(camera_status_message) | flex;
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

    auto show_image_button = Button("显示图片", [&] {
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

        std::string timg_cmd = "timg \"" + local_last_captured_image_path_copy + "\"";
        write_debug_log("准备执行 timg 命令: " + timg_cmd);
        
        {
            std::lock_guard<std::mutex> io_lock(cout_mutex);
            for(int i=0; i<5; ++i) std::cout << std::endl; 
        }

        int timg_ret = std::system(timg_cmd.c_str()); 

        // ---- 修改开始：使用固定时长的休眠替代 std::cin.get() ----
        {
            std::lock_guard<std::mutex> io_lock(cout_mutex);
            std::cout << std::endl << "--- Luban Toolkit 图片查看 ---" << std::endl;
            if (timg_ret == 0) {
                std::cout << "图片 '" << local_last_captured_image_path_copy << "' 已尝试通过 timg 显示。" << std::endl;
            } else {
                std::cout << "timg 命令执行可能存在问题 (返回码: " << timg_ret << ")。" << std::endl;
                 if (WIFEXITED(timg_ret) && WEXITSTATUS(timg_ret) == 127) {
                     std::cout << "提示: timg 命令可能未找到或无法执行。" << std::endl;
                 }
            }
            std::cout << "程序将在此暂停10秒钟，请查看图片..." << std::endl;
        }

        std::this_thread::sleep_for(std::chrono::seconds(3)); // 休眠3秒

        {
            std::lock_guard<std::mutex> io_lock(cout_mutex);
            // 尝试清除之前的输出或打印更多空行
            for(int i=0; i<10; ++i) std::cout << std::endl; 
            std::cout << "暂停结束，返回应用程序..." << std::endl << std::endl;
        }
        // ---- 修改结束 ----
        
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
        screen.PostEvent(ftxui::Event::Custom); 
    });

    auto video_list_container = Container::Vertical({});
    auto camera_action_buttons_container = Container::Horizontal({
        capture_button_component,
        show_image_button, 
        Button("刷新设备列表", [&] {
            write_debug_log("点击刷新设备列表按钮");
            std::thread refresh_thread([&] { 
                auto new_video_devices = find_video_devices();
                std::lock_guard<std::mutex> lock(state_mutex); 
                video_devices = new_video_devices;
                screen.PostEvent(ftxui::Event::Custom); 
            });
            refresh_thread.detach(); 
        })
    });
    auto camera_tab_content_container = Container::Vertical({
        Renderer([&] { 
             std::lock_guard<std::mutex> state_lock(state_mutex);
             if (!initial_load_complete.load()) return vbox({text("正在加载设备信息...") | hcenter | flex});
             if (!sys_info.has_root) return vbox({text("查找摄像头需要 root 权限。") | hcenter | flex});
             if (video_devices.empty()) return vbox({text("未找到支持的 USB 摄像头设备。") | hcenter | flex}); 
             return emptyElement(); 
        }),
        video_list_container, 
        camera_action_buttons_container, 
        camera_status_renderer 
    });

    auto system_info_renderer = Renderer([&] {
         if (!initial_load_complete.load()) {
             return vbox({text("正在加载设备信息...") | hcenter | flex});
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
        return vbox({ 
            hbox({text("主机名: ") | dim, text(sys_info.hostname)}),
            hbox({text("系统: ") | dim, text(sys_info.os_version)}),
            hbox({text("内存: ") | dim, text(sys_info.memory)}),
            hbox({text("运行时间: ") | dim, text(sys_info.uptime)}),
            hbox({text("网络: ") | dim, text(sys_info.network_info)}),
            hbox({text("CPU 温度 (平均): ") | dim, text(sys_info.cpu_temperature_avg)}),
            hbox(ip_elements_list)
        });
    });

    auto refresh_all_button = Button("刷新所有信息", [&] {
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
    });

    auto tab_container = Container::Tab({
        Container::Vertical({serial_status, serial_list_container, connect_button}),
        camera_tab_content_container,
        Container::Vertical({system_info_renderer, refresh_all_button})
    }, &tab_selected);

    auto tab_select = Container::Horizontal({}); 
    for (size_t i = 0; i < tab_titles.size(); ++i) {
        tab_select->Add(Button(tab_titles[i], [&, i_val = i] { 
            tab_selected = static_cast<int>(i_val);
        }));
    }

    auto quit_button = Button("退出", screen.ExitLoopClosure());
    auto main_container = Container::Vertical({ tab_select, tab_container, quit_button });

    auto main_renderer = Renderer(main_container, [&] {
        return vbox({ 
            text("Luban Toolkit") | bold | hcenter,
            separator(),
            tab_select->Render(),
            separator(),
            tab_container->Render() | flex,
            separator(),
            quit_button->Render()
        });
    });

    write_debug_log("进入事件处理循环");
    auto event_handler = CatchEvent(main_renderer, [&](Event event) {
        if (sigterm_received.load()) { 
            write_debug_log("接收到终止信号，退出程序");
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
            screen.Exit();
            return true;
        }
        if (event == Event::Custom) {
            write_debug_log("处理自定义事件，更新 UI");
            std::lock_guard<std::mutex> state_lock(state_mutex); 
            serial_list_container->DetachAllChildren();
            for (size_t i = 0; i < serial_devices_list.size(); ++i) { 
                serial_list_container->Add(Button(serial_devices_list[i], [&, i_val = i] {  
                    std::lock_guard<std::mutex> btn_lock(state_mutex); 
                    selected_serial = static_cast<int>(i_val); 
                    write_debug_log("选中串口设备: " + serial_devices_list[selected_serial]); 
                }));
            }
            video_list_container->DetachAllChildren();
            for (size_t i = 0; i < video_devices.size(); ++i) { 
                std::string name = video_devices[i].path.substr(video_devices[i].path.rfind('/') + 1);
                auto res_by_fmt = video_devices[i].resolutions_by_format; 
                video_list_container->Add(Container::Vertical({ 
                    Button(name, [&, i_val = i] { 
                        std::lock_guard<std::mutex> btn_lock(state_mutex); 
                        selected_video = static_cast<int>(i_val); 
                        write_debug_log("选中视频设备: " + video_devices[selected_video].path); 
                    }),
                    Renderer([res_by_fmt_copy = res_by_fmt] { 
                        Elements format_elements_list; 
                        for (const auto& pair : res_by_fmt_copy) { 
                            Elements res_elements_horizontal;
                            res_elements_horizontal.push_back(text("  " + pair.first + ": ") | dim);
                            std::stringstream res_line_ss; 
                            for(size_t j = 0; j < pair.second.size(); ++j) {
                                res_line_ss << pair.second[j];
                                if (j < pair.second.size() - 1) res_line_ss << " ";
                            }
                            res_elements_horizontal.push_back(text(res_line_ss.str()));
                            format_elements_list.push_back(hbox(res_elements_horizontal)); 
                        }
                        return vbox(format_elements_list); 
                    })
                }));
            }
            return true; 
        }
        return main_container->OnEvent(event);
    });

    screen.Loop(event_handler);
    write_debug_log("退出事件处理循环");

    if (serial_port && serial_port->is_open()) {
         serial_port->close();
    }
    write_debug_log("程序退出");
    return 0;
}
