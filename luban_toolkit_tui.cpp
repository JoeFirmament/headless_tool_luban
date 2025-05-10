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
#include <poll.h> // For poll

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
// 改进：使用非阻塞读取和 poll 实现超时
std::string exec_command(const std::string& cmd, int timeout_ms = 5000) { // 默认超时 5 秒
    std::array<char, 128> buffer;
    std::string result;

    { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "调试: 准备执行命令: " << cmd << std::endl;
    }

    // 将标准错误重定向到标准输出，以便一起捕获
    std::string full_cmd = cmd + " 2>&1";

    // 添加调试输出，指示 popen 调用前
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "调试: 在 popen 调用前..." << std::endl;
    }
    FILE* pipe = popen(full_cmd.c_str(), "r");
    // 添加调试输出，指示 popen 调用后
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "调试: 在 popen 调用后..." << std::endl;
    }

    // 锁定日志进行写入
    std::lock_guard<std::mutex> log_lock(logs_mutex);
    logs.push_back("执行命令: " + cmd);

    if (!pipe) {
        std::string error = "错误: popen() 调用失败!";
        logs.push_back("命令执行失败: " + cmd + "\n" + error);
        { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "调试: popen() 失败!" << std::endl;
        }
        return error;
    }

    // 将管道的文件描述符设置为非阻塞模式
    int fd = fileno(pipe);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "调试: popen() 成功，设置为非阻塞，开始读取输出..." << std::endl;
    }

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN; // 监听可读事件

    bool timed_out = false;
    while (true) {
        int poll_ret = poll(&pfd, 1, timeout_ms); // 等待数据或超时

        if (poll_ret > 0) {
            if (pfd.revents & POLLIN) {
                // 有数据可读
                ssize_t n = read(fd, buffer.data(), buffer.size() - 1);
                if (n > 0) {
                    buffer[n] = '\0'; // Null-terminate the buffer
                    result += buffer.data();
                } else if (n == 0) {
                    // End of file (pipe closed by child process)
                    break;
                } else if (n < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    // Error other than EAGAIN/EWOULDBLOCK
                    std::string error = "错误: 从管道读取数据失败: " + std::string(strerror(errno));
                    logs.push_back("命令读取失败: " + cmd + "\n" + error);
                    { // 锁定 cout 进行输出
                        std::lock_guard<std::mutex> cout_lock(cout_mutex);
                        std::cerr << "调试: 从管道读取失败: " << error << std::endl;
                    }
                    // Attempt to close pipe and return error
                    pclose(pipe);
                    return error;
                }
                // If n < 0 and EAGAIN/EWOULDBLOCK, no data currently available, continue polling
            } else if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                // Error or hangup on the pipe
                 std::string error = "错误: 管道发生错误或挂起。";
                 logs.push_back("命令管道错误: " + cmd + "\n" + error);
                  { // 锁定 cout 进行输出
                    std::lock_guard<std::mutex> cout_lock(cout_mutex);
                    std::cerr << "调试: 管道错误或挂起。" << std::endl;
                }
                 pclose(pipe);
                 return error;
            }
        } else if (poll_ret == 0) {
            // Timeout occurred
            timed_out = true;
            std::string error = "警告: 命令执行超时。已读取部分输出。";
            logs.push_back("命令超时: " + cmd + "\n" + error);
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cerr << "调试: 命令执行超时。" << std::endl;
            }
            break; // Exit the read loop on timeout
        } else {
            // poll returned an error
            if (errno != EINTR) { // Ignore interrupted system calls
                 std::string error = "错误: poll() 调用失败: " + std::string(strerror(errno));
                 logs.push_back("poll 失败: " + cmd + "\n" + error);
                  { // 锁定 cout 进行输出
                    std::lock_guard<std::mutex> cout_lock(cout_mutex);
                    std::cerr << "调试: poll() 失败。" << std::endl;
                }
                 pclose(pipe);
                 return error;
            }
        }
        // If not timed out, poll_ret > 0 with POLLIN, or poll_ret < 0 with EINTR, continue loop
    }


    { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "调试: 读取输出完成，准备 pclose()..." << std::endl;
    }

    auto rc = pclose(pipe);

    { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "调试: pclose() 完成，返回码: " << rc << std::endl;
    }

    // 检查 pclose 的返回值以判断命令是否成功执行
    // 如果超时，即使 pclose 返回 0，也可能是部分成功
    if (rc != 0 && !timed_out) {
        std::string error;
        if (WIFEXITED(rc)) {
            error = "错误: 命令退出状态码 " + std::to_string(WEXITSTATUS(rc)) + ": " + result;
        } else {
            error = "错误: 命令执行失败: " + result;
        }
        logs.push_back("命令结果 (错误): " + error);
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cerr << "调试: 命令执行失败: " << error << std::endl;
        }
        return error;
    }

    // 移除末尾的换行符（如果存在）
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }

    logs.push_back("命令结果 (成功): " + result);
    { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "调试: 命令执行成功。" << std::endl;
    }
    return result;
}

// --- 设备查找函数 ---

struct VideoDeviceInfo {
    std::string path;
    std::vector<std::string> resolutions;
};

// 查找视频设备
std::vector<VideoDeviceInfo> find_video_devices() {
    std::vector<VideoDeviceInfo> devices;

    // 锁定日志进行写入
    std::lock_guard<std::mutex> log_lock(logs_mutex);
    logs.push_back("开始查找视频设备...");
     { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cout << "调试: 开始查找视频设备..." << std::endl;
    }


    if (!has_root_privileges()) {
        logs.push_back("查找视频设备需要 root 权限。");
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cerr << "调试: 查找视频设备需要 root 权限。" << std::endl;
        }
        return devices;
    }

    // 使用正则表达式过滤设备路径
    std::string cmd = "ls /dev/video* 2>/dev/null || echo ''";
    std::string ls_result = exec_command(cmd);

    if (ls_result.empty() || ls_result.substr(0, 5) == "错误") {
        logs.push_back("未找到 /dev/video* 设备或列出设备时出错。");
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 未找到 /dev/video* 设备或列出设备时出错。" << std::endl;
        }
        return devices;
    }

    std::istringstream iss(ls_result);
    std::string device_path;
    std::regex video_regex("/dev/video([0-9]+)");

    while (std::getline(iss, device_path)) {
        if (device_path.empty()) continue;

        std::smatch match;
        if (std::regex_match(device_path, match, video_regex)) {
            // 找到匹配 /dev/video[0-9]+ 模式的设备
            logs.push_back("找到潜在视频设备: " + device_path);
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: 找到潜在视频设备: " + device_path << std::endl;
            }


            std::string check_cmd = "v4l2-ctl --device " + device_path + " --list-formats-ext 2>/dev/null";
            std::string check_result = exec_command(check_cmd);

            if (check_result.substr(0, 5) != "错误" && check_result.find("Format") != std::string::npos) {
                VideoDeviceInfo info;
                info.path = device_path;

                // 提取分辨率信息
                std::istringstream format_stream(check_result);
                std::string line;
                std::regex res_regex("Size: Discrete (\\d+x\\d+)");
                std::smatch res_match;

                while (std::getline(format_stream, line)) {
                    if (std::regex_search(line, res_match, res_regex) && res_match.size() > 1) {
                        info.resolutions.push_back(res_match[1].str());
                    }
                }

                if (!info.resolutions.empty()) {
                    devices.push_back(info);
                    logs.push_back("设备 " + device_path + " 找到分辨率，已添加到列表。");
                     { // 锁定 cout 进行输出
                        std::lock_guard<std::mutex> cout_lock(cout_mutex);
                        std::cout << "调试: 设备 " + device_path + " 找到分辨率，已添加。" << std::endl;
                    }
                } else {
                     logs.push_back("设备 " + device_path + " 未找到分辨率，跳过。");
                      { // 锁定 cout 进行输出
                        std::lock_guard<std::mutex> cout_lock(cout_mutex);
                        std::cout << "调试: 设备 " + device_path + " 未找到分辨率，跳过。" << std::endl;
                    }
                }
            } else {
                logs.push_back("v4l2-ctl 执行失败或设备 " + device_path + " 未找到格式，跳过。");
                 { // 锁定 cout 进行输出
                    std::lock_guard<std::mutex> cout_lock(cout_mutex);
                    std::cout << "调试: v4l2-ctl 失败或未找到格式，跳过设备: " + device_path << std::endl;
                }
            }
        } else {
             logs.push_back("设备路径不匹配 /dev/video[0-9]+ 模式: " + device_path + "，跳过。");
              { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: 设备路径不匹配模式，跳过: " + device_path << std::endl;
            }
        }
    }
    logs.push_back("视频设备查找完成，找到 " + std::to_string(devices.size()) + " 个设备。");
     { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cout << "调试: 视频设备查找完成，找到 " + std::to_string(devices.size()) + " 个设备。" << std::endl;
    }
    return devices;
}

// 查找串口设备
std::vector<std::string> find_serial_devices() {
    std::vector<std::string> devices;
    // 锁定日志进行写入
    std::lock_guard<std::mutex> log_lock(logs_mutex);
    logs.push_back("开始查找串口设备...");
     { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cout << "调试: 开始查找串口设备..." << std::endl;
    }


    if (!has_root_privileges()) {
        logs.push_back("查找串口设备需要 root 权限。");
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cerr << "调试: 查找串口设备需要 root 权限。" << std::endl;
        }
        return devices;
    }

    std::string result = exec_command("ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null || echo ''");
    if (result.empty() || result.substr(0, 5) == "错误") {
        logs.push_back("未找到 /dev/ttyACM* 或 /dev/ttyUSB* 设备或列出设备时出错。");
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 未找到 /dev/ttyACM* 或 /dev/ttyUSB* 设备或列出设备时出错。" << std::endl;
        }
        return devices;
    }

    std::istringstream iss(result);
    std::string device;
    while (std::getline(iss, device)) {
        if (!device.empty()) {
            devices.push_back(device);
             logs.push_back("找到串口设备: " + device);
              { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: 找到串口设备: " + device << std::endl;
            }
        }
    }
    logs.push_back("串口设备查找完成，找到 " + std::to_string(devices.size()) + " 个设备。");
     { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cout << "调试: 串口设备查找完成，找到 " + std::to_string(devices.size()) + " 个设备。" << std::endl;
    }
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
        logs.push_back("刷新系统信息...");
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 刷新系统信息..." << std::endl;
        }
        uptime = exec_command("uptime -p");
        memory = exec_command("free -m | grep Mem | awk '{print $3\"MB used / \"$2\"MB total\"}'");
        os_version = exec_command("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2");
        cpu_info = exec_command("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2");

        auto ip = exec_command("ip route get 1 | awk '{print $7}' | head -1");
        auto iface = exec_command("ip route get 1 | awk '{print $5}' | head -1");
        network_info = iface + " - " + ip;
        logs.push_back("系统信息刷新完成。");
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 系统信息刷新完成。" << std::endl;
        }
    }
};

// --- 串口通信类 ---
class SerialPort {
public:
    SerialPort() : fd_(-1) {}
    ~SerialPort() { close(); }

    // 打开串口
    bool open(const std::string& port) {
        // 锁定日志进行写入
        std::lock_guard<std::mutex> log_lock(logs_mutex);
        logs.push_back("尝试打开串口: " + port);
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 尝试打开串口: " + port << std::endl;
        }


        fd_ = ::open(port.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK); // Open in non-blocking mode
        if (fd_ < 0) {
            logs.push_back("打开串口失败: " + port);
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cerr << "调试: 打开串口失败: " + port << std::endl;
            }
            return false;
        }

        termios tty;
        if (tcgetattr(fd_, &tty) != 0) {
            logs.push_back("获取串口属性失败: " + port);
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cerr << "调试: 获取串口属性失败: " + port << std::endl;
            }
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
            logs.push_back("设置串口属性失败: " + port);
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cerr << "调试: 设置串口属性失败: " + port << std::endl;
            }
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        logs.push_back("串口打开成功: " + port);
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 串口打开成功: " + port << std::endl;
        }
        return true;
    }

    // 关闭串口
    void close() {
        if (fd_ >= 0) {
             // 锁定日志进行写入
            std::lock_guard<std::mutex> log_lock(logs_mutex);
            logs.push_back("关闭串口。");
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: 关闭串口..." << std::endl;
            }
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
             std::lock_guard<std::mutex> log_lock(logs_mutex);
             logs.push_back("串口读取错误: " + std::string(strerror(errno)));
              { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cerr << "调试: 串口读取错误: " + std::string(strerror(errno)) << std::endl;
            }
        }

        return data;
    }

private:
    int fd_;
};

int main() {
    { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << "调试: 进入 main 函数..." << std::endl;
    }

    // 锁定日志进行写入
    std::lock_guard<std::mutex> main_log_lock(logs_mutex);
    logs.push_back("程序启动...");

    // 设置信号处理
    std::signal(SIGTERM, handle_terminate_signal);
    std::signal(SIGINT, handle_terminate_signal);

    auto screen = ScreenInteractive::Fullscreen();
    global_screen_ptr = &screen;

    // --- 状态变量 ---
    SystemInfo sys_info;

    // 使用原子变量标记初始加载状态
    std::atomic<bool> initial_load_complete(false);

    // 将状态变量声明在 main 函数中，并确保 lambda 捕获它们
    std::vector<VideoDeviceInfo> video_devices;
    std::vector<std::string> serial_devices;
    int selected_video = 0;
    int selected_serial = 0;
    bool serial_connected = false;
    std::unique_ptr<SerialPort> serial_port;


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
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 点击连接/断开串口按钮。" << std::endl;
        }

        // 锁定状态变量进行读写
        std::lock_guard<std::mutex> state_lock(state_mutex);

        if (serial_connected) {
            serial_port.reset();
            serial_connected = false;
             logs.push_back("串口已断开。");
              { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: 串口已断开。" << std::endl;
            }
        } else if (!serial_devices.empty()) {
            serial_port = std::make_unique<SerialPort>();
            // 安全地转换 selected_serial 并检查边界
            if (selected_serial >= 0 && static_cast<size_t>(selected_serial) < serial_devices.size()) {
                 if (serial_port->open(serial_devices[static_cast<size_t>(selected_serial)])) {
                    serial_connected = true;
                 } else {
                     logs.push_back("连接串口失败: " + serial_devices[static_cast<size_t>(selected_serial)]);
                      { // 锁定 cout 进行输出
                        std::lock_guard<std::mutex> cout_lock(cout_mutex);
                        std::cerr << "调试: 连接串口失败: " + serial_devices[static_cast<size_t>(selected_serial)] << std::endl;
                    }
                 }
            } else {
                 // 如果 selected_serial 越界，记录日志
                 logs.push_back("错误: 选定的串口设备索引越界，无法尝试连接。");
                  { // 锁定 cout 进行输出
                    std::lock_guard<std::mutex> cout_lock(cout_mutex);
                    std::cerr << "调试: 选定的串口设备索引越界，无法尝试连接。" << std::endl;
                }
            }
        } else {
             // 如果没有找到串口设备，记录日志
             logs.push_back("错误: 没有可用的串口设备进行连接。");
              { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cerr << "调试: 没有可用的串口设备进行连接。" << std::endl;
            }
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
                text("未找到支持的摄像头设备 (/dev/video[0-9]+ 且能获取分辨率)。") | hcenter | flex,
                // 渲染按钮以获取 Element
                Button("刷新设备列表", [&] { // 捕获 logs_mutex, video_devices, serial_devices, serial_list_container, selected_video, selected_serial, screen, state_mutex
                    { // 锁定 cout 进行输出
                        std::lock_guard<std::mutex> cout_lock(cout_mutex);
                        std::cout << "调试: 点击刷新设备列表按钮。" << std::endl;
                    }
                    // 在新线程中执行刷新操作
                    std::thread refresh_thread([&] { // 捕获 logs_mutex, video_devices, serial_devices, screen, state_mutex
                        logs.push_back("在新线程中刷新设备列表...");
                         { // 锁定 cout 进行输出
                            std::lock_guard<std::mutex> cout_lock(cout_mutex);
                            std::cout << "调试: 刷新线程开始执行设备查找。" << std::endl;
                        }
                        auto new_video_devices = find_video_devices();
                        auto new_serial_devices = find_serial_devices();

                        // 锁定状态变量进行更新
                        std::lock_guard<std::mutex> lock(state_mutex); // 确保在更新共享状态前锁定
                        video_devices = new_video_devices;
                        serial_devices = new_serial_devices;

                        // 重新填充 serial_list_container (通过事件通知主线程)
                        screen.PostEvent(ftxui::Event::Custom); // 发送自定义事件通知 UI 更新
                        logs.push_back("设备列表刷新完成，发送 UI 更新事件。");
                         { // 锁定 cout 进行输出
                            std::lock_guard<std::mutex> cout_lock(cout_mutex);
                            std::cout << "调试: 刷新线程完成，发送 UI 更新事件。" << std::endl;
                        }
                    });
                    refresh_thread.detach(); // 分离线程，让其独立运行

                    // 锁定日志进行写入
                    std::lock_guard<std::mutex> log_lock_button(logs_mutex);
                    logs.push_back("已触发设备列表刷新。");
                     { // 锁定 cout 进行输出
                        std::lock_guard<std::mutex> cout_lock(cout_mutex);
                        std::cout << "调试: 已触发设备列表刷新线程。" << std::endl;
                    }

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
                        { // 锁定 cout 进行输出
                            std::lock_guard<std::mutex> cout_lock(cout_mutex);
                            std::cout << "调试: 选中视频设备: " + video_devices[selected_video].path << std::endl;
                        }
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
                    { // 锁定 cout 进行输出
                        std::lock_guard<std::mutex> cout_lock(cout_mutex);
                        std::cout << "调试: 点击刷新设备列表按钮 (有设备时)。" << std::endl;
                    }
                    // 在新线程中执行刷新操作
                    std::thread refresh_thread([&] { // 捕获 logs_mutex, video_devices, serial_devices, screen, state_mutex
                         logs.push_back("在新线程中刷新设备列表...");
                          { // 锁定 cout 进行输出
                            std::lock_guard<std::mutex> cout_lock(cout_mutex);
                            std::cout << "调试: 刷新线程开始执行设备查找 (有设备时)。" << std::endl;
                        }
                        auto new_video_devices = find_video_devices();
                        auto new_serial_devices = find_serial_devices();

                        // 锁定状态变量进行更新
                        std::lock_guard<std::mutex> lock(state_mutex); // 确保在更新共享状态前锁定
                        video_devices = new_video_devices;
                        serial_devices = new_serial_devices;

                        // 重新填充 serial_list_container (通过事件通知主线程)
                        screen.PostEvent(ftxui::Event::Custom); // 发送自定义事件通知 UI 更新
                         logs.push_back("设备列表刷新完成，发送 UI 更新事件。");
                          { // 锁定 cout 进行输出
                            std::lock_guard<std::mutex> cout_lock(cout_mutex);
                            std::cout << "调试: 刷新线程完成，发送 UI 更新事件 (有设备时)。" << std::endl;
                        }
                    });
                    refresh_thread.detach(); // 分离线程，让其独立运行

                    // 锁定日志进行写入
                    std::lock_guard<std::mutex> log_lock_button(logs_mutex);
                    logs.push_back("已触发设备列表刷新。");
                     { // 锁定 cout 进行输出
                        std::lock_guard<std::mutex> cout_lock(cout_mutex);
                        std::cout << "调试: 已触发设备列表刷新线程 (有设备时)。" << std::endl;
                    }

                })->Render() | hcenter
            }) | flex;
        }
    });


    // 系统信息组件
    // 捕获 initial_load_complete, sys_info, state_mutex
    auto system_info = Renderer([&] {
         // 锁定状态变量进行读取
         std::lock_guard<std::mutex> state_lock(state_mutex);
         if (!initial_load_complete) {
             return vbox(Elements{text("正在加载系统信息...") | hcenter | flex});
         }
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
        { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 点击刷新所有信息按钮。" << std::endl;
        }
        // 在新线程中执行刷新操作
        std::thread refresh_thread([&] { // 捕获 logs_mutex, sys_info, video_devices, serial_devices, screen, state_mutex
            logs.push_back("在新线程中刷新所有信息...");
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: 刷新线程开始执行所有信息刷新。" << std::endl;
            }

            // 锁定状态变量进行更新
            std::lock_guard<std::mutex> lock(state_mutex); // 确保在更新共享状态前锁定

            sys_info.refresh(); // 刷新系统信息并记录日志
            auto new_video_devices = find_video_devices(); // 刷新视频设备并记录日志
            auto new_serial_devices = find_serial_devices(); // 刷新串口设备并记录日志

            video_devices = new_video_devices;
            serial_devices = new_serial_devices;

            // 重新填充 serial_list_container (通过事件通知主线程)
            screen.PostEvent(ftxui::Event::Custom); // 发送自定义事件通知 UI 更新
            logs.push_back("所有信息刷新完成，发送 UI 更新事件。");
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: 所有信息刷新完成，发送 UI 更新事件。" << std::endl;
            }
        });
        refresh_thread.detach(); // 分离线程，让其独立运行

        // 锁定日志进行写入
        std::lock_guard<std::mutex> log_lock_button(logs_mutex);
        logs.push_back("已触发所有信息刷新。");
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 已触发所有信息刷新线程。" << std::endl;
        }
    });

    // 日志标签页内容
    // 捕获 logs, logs_mutex
    auto log_tab_content = Renderer([&] {
         std::lock_guard<std::mutex> lock(logs_mutex); // 锁定日志进行读取
        Elements log_lines;
        for (const auto& log : logs) {
            log_lines.push_back(text(log));
        }
        return vbox(log_lines) | yframe | flex;
    });

    // 捕获 logs, logs_mutex
    auto clear_log_button = Button("清除日志", [&] {
         std::lock_guard<std::mutex> lock(logs_mutex); // 锁定日志进行清除
         logs.clear();
         logs.push_back("日志已清除。");
          { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 日志已清除。" << std::endl;
        }
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
        // 日志标签页 - 使用日志内容 Renderer 和清除按钮
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
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: 切换到标签页: " + tab_titles[i] << std::endl;
            }
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

    // 在新线程中执行初始加载操作
    // 捕获 logs_mutex, sys_info, video_devices, serial_devices, screen, initial_load_complete, state_mutex
    std::thread initial_load_thread([&] {
        logs.push_back("在新线程中开始初始加载...");
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 初始加载线程开始执行..." << std::endl;
        }

        // 锁定状态变量进行更新
        std::lock_guard<std::mutex> lock(state_mutex);

        sys_info.refresh(); // 刷新系统信息并记录日志
        video_devices = find_video_devices(); // 查找视频设备并记录日志
        serial_devices = find_serial_devices(); // 查找串口设备并记录日志

        // 初始填充 serial_list_container (通过事件通知主线程)
        screen.PostEvent(ftxui::Event::Custom); // 发送自定义事件通知 UI 更新

        initial_load_complete = true; // 标记初始加载完成
        screen.PostEvent(ftxui::Event::Custom); // 再次发送事件以触发 UI 刷新显示加载完成的状态
        logs.push_back("初始加载完成，发送 UI 更新事件。");
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            std::cout << "调试: 初始加载线程完成，发送 UI 更新事件。" << std::endl;
        }
    });
    initial_load_thread.detach(); // 分离线程，让其独立运行

    { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cout << "调试: 进入事件处理循环..." << std::endl;
    }

    // 事件处理循环
    // 捕获 sigterm_received, screen, tab_selected, tab_titles, main_container, logs_mutex, serial_list_container, serial_devices, selected_serial, state_mutex
    auto event_handler = CatchEvent(main_renderer, [&](Event event) {
        // 锁定日志进行写入
        std::lock_guard<std::mutex> log_lock_event(logs_mutex);
        // logs.push_back("接收到事件: " + event.ToString()); // 如果需要详细调试可以开启此行
         { // 锁定 cout 进行输出
            std::lock_guard<std::mutex> cout_lock(cout_mutex);
            // 移除 event.ToString()
            std::cout << "调试: 接收到事件 (类型未知或无法打印)。" << std::endl;
        }


        if (sigterm_received) {
            logs.push_back("接收到终止信号，退出程序。");
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: 接收到终止信号，退出程序。" << std::endl;
            }
            screen.Exit();
            return true;
        }
        if (event == Event::Tab) {
            // 锁定状态变量进行读写
            std::lock_guard<std::mutex> state_lock(state_mutex);
            tab_selected = (tab_selected + 1) % static_cast<int>(tab_titles.size());
            logs.push_back("Tab 键按下，切换到标签页: " + tab_titles[tab_selected]);
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: Tab 键按下，切换到标签页: " + tab_titles[tab_selected] << std::endl;
            }
            return true;
        }
        if (event.is_character()) {
            if (event.character() == "q") {
                logs.push_back("按下 'q' 键，退出程序。");
                 { // 锁定 cout 进行输出
                    std::lock_guard<std::mutex> cout_lock(cout_mutex);
                    std::cout << "调试: 按下 'q' 键，退出程序。" << std::endl;
                }
                screen.Exit();
                return true;
            }
        }
        // 处理自定义事件，用于 UI 更新
        if (event == ftxui::Event::Custom) {
             // 当接收到自定义事件时，重新填充 serial_list_container
             // 注意：这里假设自定义事件只用于通知刷新
             { // 锁定 cout 进行输出
                std::lock_guard<std::mutex> cout_lock(cout_mutex);
                std::cout << "调试: 接收到自定义事件，更新 UI。" << std::endl;
            }
             // 锁定状态变量进行读取
             std::lock_guard<std::mutex> state_lock(state_mutex);
             serial_list_container->DetachAllChildren(); // 清空现有按钮
             for (size_t i = 0; i < serial_devices.size(); ++i) {
                 serial_list_container->Add(Button(serial_devices[i], [&, i] { // 捕获 selected_serial, logs_mutex, serial_devices, i, state_mutex
                     std::lock_guard<std::mutex> state_lock_button(state_mutex); // 锁定状态变量
                     selected_serial = static_cast<int>(i);
                     // 锁定日志进行写入
                     std::lock_guard<std::mutex> log_lock_button(logs_mutex);
                     logs.push_back("选中串口设备: " + serial_devices[selected_serial]);
                      { // 锁定 cout 进行输出
                        std::lock_guard<std::mutex> cout_lock(cout_mutex);
                        std::cout << "调试: 选中串口设备: " + serial_devices[selected_serial] << std::endl;
                    }
                 }));
             }
             logs.push_back("UI 已更新（响应自定义事件）。");

             // 返回 true 表示事件已处理，阻止进一步传播
             return true;
        }

        // 将未处理的事件传递给子组件
        return main_container->OnEvent(event);
    });

    screen.Loop(event_handler);

    { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cout << "调试: 退出事件处理循环。" << std::endl;
    }

    // 确保串口在程序退出时关闭
    // serial_port 在 main 作用域，可以直接访问
    if (serial_port && serial_port->is_open()) {
        serial_port->close();
    }

    // 锁定日志进行写入
    std::lock_guard<std::mutex> main_exit_log_lock(logs_mutex);
    logs.push_back("程序退出。");
     { // 锁定 cout 进行输出
        std::lock_guard<std::mutex> cout_lock(cout_mutex);
        std::cout << "调试: 退出 main 函数。" << std::endl;
    }

    return 0;
}
