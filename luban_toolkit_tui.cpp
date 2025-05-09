#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

// 标准库
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

using namespace ftxui;

// --- 全局变量和信号处理 ---
ftxui::ScreenInteractive* global_screen_ptr = nullptr;
std::atomic<bool> sigterm_received(false);

void handle_terminate_signal(int signal) {
    sigterm_received = true;
    if (global_screen_ptr) {
        global_screen_ptr->PostEvent(ftxui::Event());
    }
}

// --- 工具函数 ---
bool has_root_privileges() {
    return geteuid() == 0;
}

std::string exec_command(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    auto pipe = popen((cmd + " 2>&1").c_str(), "r");
    
    if (!pipe) return "ERROR: popen() failed!";
    
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    
    auto rc = pclose(pipe);
    if (rc != 0) {
        return "ERROR: " + result;
    }
    
    if (!result.empty() && result.back() == '\n') {
        result.pop_back();
    }
    return result;
}

// --- 设备查找函数 ---
std::vector<std::string> find_video_devices() {
    std::vector<std::string> devices;
    if (!has_root_privileges()) return devices;

    std::string cmd = "ls /dev/video* 2>/dev/null || echo ''";
    std::string result = exec_command(cmd);
    
    if (result.empty() || result.substr(0, 5) == "ERROR") return devices;
    
    std::istringstream iss(result);
    std::string device;
    while (std::getline(iss, device)) {
        if (device.empty()) continue;
        
        // 检查是否为有效的v4l2设备
        std::string check_cmd = "v4l2-ctl --device " + device + " --list-formats-ext 2>/dev/null";
        std::string check_result = exec_command(check_cmd);
        
        if (check_result.substr(0, 5) != "ERROR" && check_result.find("Format") != std::string::npos) {
            devices.push_back(device);
        }
    }
    return devices;
}

std::vector<std::string> find_serial_devices() {
    std::vector<std::string> devices;
    if (!has_root_privileges()) return devices;
    
    std::string result = exec_command("ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null || echo ''");
    if (result.empty() || result.substr(0, 5) == "ERROR") return devices;
    
    std::istringstream iss(result);
    std::string device;
    while (std::getline(iss, device)) {
        if (!device.empty()) {
            devices.push_back(device);
        }
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
    
    void refresh() {
        uptime = exec_command("uptime -p");
        memory = exec_command("free -m | grep Mem | awk '{print $3\"MB used / \"$2\"MB total\"}'");
        os_version = exec_command("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2");
        cpu_info = exec_command("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d: -f2");
        
        auto ip = exec_command("ip route get 1 | awk '{print $7}' | head -1");
        auto iface = exec_command("ip route get 1 | awk '{print $5}' | head -1");
        network_info = iface + " - " + ip;
    }
};

// --- 串口通信类 ---
class SerialPort {
public:
    SerialPort() : fd_(-1) {}
    ~SerialPort() { close(); }
    
    bool open(const std::string& port) {
        fd_ = ::open(port.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd_ < 0) return false;
        
        termios tty;
        if (tcgetattr(fd_, &tty) != 0) {
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
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        return true;
    }
    
    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }
    
    bool is_open() const { return fd_ >= 0; }
    
    std::string read_data() {
        if (fd_ < 0) return "";
        
        char buffer[256];
        std::string data;
        ssize_t n;
        
        while ((n = ::read(fd_, buffer, sizeof(buffer))) > 0) {
            data.append(buffer, n);
        }
        return data;
    }

private:
    int fd_;
};

int main() {
    // 设置信号处理
    std::signal(SIGTERM, handle_terminate_signal);
    std::signal(SIGINT, handle_terminate_signal);
    
    auto screen = ScreenInteractive::Fullscreen();
    global_screen_ptr = &screen;
    
    // --- 状态变量 ---
    SystemInfo sys_info;
    sys_info.refresh();
    
    std::vector<std::string> video_devices = find_video_devices();
    std::vector<std::string> serial_devices = find_serial_devices();
    
    int selected_video = 0;
    int selected_serial = 0;
    bool serial_connected = false;
    std::unique_ptr<SerialPort> serial_port;
    std::string serial_data;
    
    // --- 组件定义 ---
    int tab_selected = 0;
    std::vector<std::string> tab_titles = {"串口", "摄像头", "系统"};
    
    // 串口组件
    auto serial_status = Renderer([&] {
        std::string status = serial_connected ? "已连接" : "未连接";
        std::string color_text = serial_connected ? "green" : "red";
        return hbox({
            text("状态: ") | dim,
            text(status) | color(Color::RGB(serial_connected ? 0 : 255, serial_connected ? 255 : 0, 0))
        });
    });
    
    auto serial_list = Container::Vertical({});
    for (size_t i = 0; i < serial_devices.size(); ++i) {
        serial_list->Add(Button(serial_devices[i], [&, i] {
            selected_serial = i;
        }));
    }
    
    auto connect_button = Button(serial_connected ? "断开" : "连接", [&] {
        if (serial_connected) {
            serial_port.reset();
            serial_connected = false;
        } else if (!serial_devices.empty()) {
            serial_port = std::make_unique<SerialPort>();
            if (serial_port->open(serial_devices[selected_serial])) {
                serial_connected = true;
            }
        }
    });
    
    // 摄像头组件
    auto video_list = Container::Vertical({});
    for (size_t i = 0; i < video_devices.size(); ++i) {
        std::string name = video_devices[i].substr(video_devices[i].rfind('/') + 1);
        video_list->Add(Button(name, [&, i] {
            selected_video = i;
        }));
    }
    
    // 系统信息组件
    auto system_info = Renderer([&] {
        return vbox({
            hbox(text("系统: ") | dim, text(sys_info.os_version)),
            hbox(text("CPU: ") | dim, text(sys_info.cpu_info)),
            hbox(text("内存: ") | dim, text(sys_info.memory)),
            hbox(text("运行时间: ") | dim, text(sys_info.uptime)),
            hbox(text("网络: ") | dim, text(sys_info.network_info))
        });
    });
    
    auto refresh_button = Button("刷新", [&] {
        sys_info.refresh();
        video_devices = find_video_devices();
        serial_devices = find_serial_devices();
    });
    
    // 标签页组件
    auto tab_container = Container::Tab({
        // 串口标签页
        Container::Vertical({
            serial_status,
            serial_list,
            connect_button
        }),
        // 摄像头标签页
        Container::Vertical({
            video_list
        }),
        // 系统标签页
        Container::Vertical({
            system_info,
            refresh_button
        })
    }, &tab_selected);
    
    auto tab_select = Container::Horizontal({});
    for (size_t i = 0; i < tab_titles.size(); ++i) {
        tab_select->Add(Button(tab_titles[i], [&, i] { tab_selected = i; }));
    }
    
    auto quit_button = Button("退出", screen.ExitLoopClosure());
    
    auto main_container = Container::Vertical({
        tab_select,
        tab_container,
        quit_button
    });
    
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
    
    auto event_handler = CatchEvent(main_renderer, [&](Event event) {
        if (sigterm_received) {
            screen.Exit();
            return true;
        }
        if (event == Event::Tab) {
            tab_selected = (tab_selected + 1) % tab_titles.size();
            return true;
        }
        if (event.is_character()) {
            if (event.character() == "q") {
                screen.Exit();
                return true;
            }
        }
        return false;
    });
    
    screen.Loop(event_handler);
    return 0;
}
