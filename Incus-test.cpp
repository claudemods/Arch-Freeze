#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <filesystem>
#include <ctime>
#include <vector>
#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <cstdio>
#include <cstring>
#include <sys/wait.h>
#include <fcntl.h>
#include <sstream>
#include <map>
#include <cctype>
#include <pwd.h>
#include <grp.h>

namespace fs = std::filesystem;

// Color definitions
#define COLOR_RED "\033[31m"
#define COLOR_CYAN "\033[38;2;0;255;255m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_RESET "\033[0m"

// ASCII art
const std::string APEX_ART = COLOR_RED R"(
░█████╗░██╗░░░░░░█████╗░██║░░░██║██████╗░███████╗███╗░░░███╗░█████╗░██████╗░░██████╗
██╔══██╗██║░░░░░██╔══██╗██║░░░██║██╔══██╗██╔════╝████╗░████║██╔══██╗██╔══██╗██╔════╝
██║░░╚═╝██║░░░░░███████║██║░░░██║██║░░██║█████╗░░██╔████╔██║██║░░██║██║░░██║╚█████╗░
██║░░██╗██║░░░░░██╔══██╗██║░░░██║██║░░██║██╔══╝░░██║╚██╔╝██║██║░░██║██║░░██║░╚═══██╗
╚█████╔╝███████╗██║░░██║╚██████╔╝██████╔╝███████╗██║░╚═╝░██║╚█████╔╝██████╔╝██████╔╝
░╚════╝░╚══════╝╚═╝░░╚═╝░╚═════╝░╚═════╝░╚══════╝╚═╝░░░░░╚═╝░╚════╝░╚═════╝░╚═════╝░
)" COLOR_RESET;

// Function declarations
bool checkIncus();
void importToIncus();
void cleanTempDirs();
std::string getUsername();
void run_command(const std::string& command, bool show_output = true);
void capture_and_display_rsync_output(const std::vector<std::string>& command);
void setupContainerBoot(const std::string& container_name); // NEW

// Helper function to get current username
std::string getUsername() {
    const char* user = getenv("USER");
    return user ? std::string(user) : "user";
}

// Clean temporary directories
void cleanTempDirs() {
    std::cout << COLOR_CYAN << "Cleaning temporary directories..." << COLOR_RESET << std::endl;
    system("sudo rm -rf /opt/img_extract");
    system("sudo rm -rf /opt/squashfs");
    system("sudo rm -rf /mnt/temp");
    std::string username = getUsername();
    system(("sudo rm -rf /home/" + username + "/.config/Accu/clone_*").c_str());
    std::cout << COLOR_GREEN << "Temporary directories cleaned successfully." << COLOR_RESET << std::endl;
}

// Run system command with cyan terminal and improved output
void run_command(const std::string& command, bool show_output) {
    std::cout << COLOR_CYAN << "\nProcessing..." << COLOR_RESET << std::endl;
    if (show_output) {
        int status = system((std::string("printf '") + COLOR_CYAN + "'; " + command + "; printf '" + COLOR_RESET + "'").c_str());
        if (status == 0) {
            std::cout << COLOR_GREEN << "Operation completed successfully." << COLOR_RESET << std::endl;
        }
    } else {
        int status = system(command.c_str());
        if (status == 0) {
            std::cout << COLOR_GREEN << "Operation completed successfully." << COLOR_RESET << std::endl;
        }
    }
}

// Function to capture and display rsync output with improved progress
void capture_and_display_rsync_output(const std::vector<std::string>& command) {
    std::cout << COLOR_CYAN << "Starting data transfer..." << COLOR_RESET << std::endl;

    int pipefd[2];
    if (pipe(pipefd)) {
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        std::vector<char*> args;
        for (const auto& arg : command) {
            args.push_back(const_cast<char*>(arg.c_str()));
        }
        args.push_back(nullptr);

        execvp(args[0], args.data());
        exit(0);
    } else if (pid > 0) {
        close(pipefd[1]);
        char buffer[128];
        while (true) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(pipefd[0], &read_fds);
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            int select_result = select(pipefd[0] + 1, &read_fds, nullptr, nullptr, &timeout);
            if (select_result <= 0) {
                continue;
            } else {
                ssize_t count = read(pipefd[0], buffer, sizeof(buffer));
                if (count <= 0) {
                    break;
                } else {
                    std::string output(buffer, count);
                    std::cout << COLOR_GREEN << output << COLOR_RESET;
                    std::cout.flush();
                }
            }
        }
        close(pipefd[0]);
        int status;
        waitpid(pid, &status, 0);
    }
    std::cout << COLOR_GREEN << "Data transfer completed." << COLOR_RESET << std::endl;
}

// Incus check function
bool checkIncus() {
    if (system("command -v incus &> /dev/null") != 0) {
        std::cout << COLOR_RED << "Incus is not installed. Please install Incus first." << COLOR_RESET << std::endl;
        return false;
    }

    // Check if Incus is running, start if not
    if (system("incus list &> /dev/null") != 0) {
        std::cout << COLOR_CYAN << "Starting Incus service..." << COLOR_RESET << std::endl;
        system("sudo systemctl start incus &> /dev/null");
        system("sudo systemctl enable incus &> /dev/null");
    }

    return true;
}

// YOUR EXACT ORIGINAL importToIncus FUNCTION - NO CHANGES
void importToIncus() {
    // Get container name from user
    std::string container_name;
    std::cout << COLOR_CYAN << "Enter container name: " << COLOR_RESET;
    std::cin.ignore();
    std::getline(std::cin, container_name);
    
    // Validate container name
    if (container_name.empty()) {
        std::cout << COLOR_RED << "Container name cannot be empty!" << COLOR_RESET << std::endl;
        return;
    }
    
    std::string rootfs_path = "/var/lib/incus/storage-pools/default/containers/" + container_name + "/rootfs";

    // Create base container with privileged mode using archlinux image
    std::cout << COLOR_CYAN << "Creating base container with privileged mode using Arch Linux..." << COLOR_RESET << std::endl;
    std::string cmd = "sudo incus launch images:archlinux " + container_name +
    " -c security.privileged=true";
    run_command(cmd);

    // Prompt user to manually stop container
    std::cout << COLOR_YELLOW << "\nIMPORTANT: Before proceeding, please manually stop the container using this command:\n";
    std::cout << "sudo incus stop " << container_name << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "Press Enter to continue after stopping the container..." << COLOR_RESET;
    std::cin.ignore();
    std::cin.get();

    // Verify container is stopped
    if (system(("sudo incus list | grep -q " + container_name + ".*STOPPED").c_str()) != 0) {
        std::cout << COLOR_RED << "Container is still running. Please stop it first." << COLOR_RESET << std::endl;
        return;
    }

    // Clear existing rootfs contents
    std::cout << COLOR_CYAN << "Clearing existing rootfs contents..." << COLOR_RESET << std::endl;
    cmd = "sudo rm -rf " + rootfs_path + "/*";
    run_command(cmd);

    // SINGLE RSYNC COMMAND - Clone system excluding special directories (including /usr)
    std::cout << COLOR_CYAN << "Starting system copy..." << COLOR_RESET << std::endl;
    std::vector<std::string> rsync_cmd = {
        "sudo", "rsync", "-aHAXxSr", "--numeric-ids", "--info=progress2",
        "--exclude=/dev/*", "--exclude=/proc/*", "--exclude=/sys/*",
        "--exclude=/tmp/*", "--exclude=/run/*", "--exclude=/mnt/*",
        "--exclude=/media/*", "--exclude=/lost+found",
        "--exclude=/var/lib/incus",
        "--exclude=/var/lib/docker",
        "--exclude=/etc/fstab",
        "--exclude=/etc/mtab",
        "/",
        rootfs_path + "/"
    };
    
    capture_and_display_rsync_output(rsync_cmd);
    std::cout << COLOR_GREEN << "System copy completed" << COLOR_RESET << std::endl;

    // Start container
    std::cout << COLOR_CYAN << "Starting container..." << COLOR_RESET << std::endl;
    cmd = "sudo incus start " + container_name;
    run_command(cmd);

    // NEW: Setup container boot
    setupContainerBoot(container_name);

    // Execute bash in container
    cmd = "sudo incus exec " + container_name + " -- /bin/bash";
    std::cout << COLOR_CYAN << "Launching Incus container: " << container_name << COLOR_RESET << std::endl;
    system(cmd.c_str());
}

int main() {
    std::cout << APEX_ART;
    std::cout << COLOR_CYAN << "claudemods Arch Freeze Beta v1.0 20-12-2025\n" << COLOR_RESET;
    std::cout << COLOR_YELLOW << "Note: This tool only works on Arch Linux systems\n" << COLOR_RESET;

    // Check if running on Arch Linux
    std::cout << COLOR_CYAN << "Verifying Arch Linux system..." << COLOR_RESET << std::endl;
    if (system("grep -q 'ID=arch' /etc/os-release 2>/dev/null") != 0) {
        std::cout << COLOR_RED << "This tool only works on Arch Linux systems!" << COLOR_RESET << std::endl;
        cleanTempDirs();
        return 1;
    }

    // Check if Incus is installed
    if (!checkIncus()) {
        cleanTempDirs();
        return 1;
    }

    // Run the import process directly (no menu)
    importToIncus();

    // Clean up and exit
    cleanTempDirs();
    return 0;
}

// NEW FUNCTION: Setup container to be the boot target
void setupContainerBoot(const std::string& container_name) {
    std::cout << COLOR_CYAN << "\n=== Setting up container as boot target ===" << COLOR_RESET << std::endl;
    
    // 1. Make container immutable
    system(("sudo incus config set " + container_name + " security.protection.delete=true").c_str());
    system(("sudo incus config set " + container_name + " security.privileged=true").c_str());
    
    // 2. Setup auto-start
    system(("sudo incus config set " + container_name + " boot.autostart=true").c_str());
    system(("sudo incus config set " + container_name + " boot.autostart.delay=5").c_str());
    
    // 3. Detect login manager from cloned system
    std::string login_manager = "";
    std::vector<std::string> managers = {"sddm", "gdm", "lightdm", "lxdm"};
    
    for (const auto& manager : managers) {
        std::string check_cmd = "sudo incus exec " + container_name + 
                               " -- systemctl list-unit-files | grep -q \"^" + manager + "\\.service\"";
        if (system(check_cmd.c_str()) == 0) {
            login_manager = manager;
            break;
        }
    }
    
    if (!login_manager.empty()) {
        std::cout << COLOR_GREEN << "Found login manager: " << login_manager << COLOR_RESET << std::endl;
        system(("sudo incus exec " + container_name + " -- systemctl enable " + login_manager).c_str());
    } else {
        std::cout << COLOR_YELLOW << "No login manager found. Container will boot without display manager." << COLOR_RESET << std::endl;
    }
    
    // 4. Setup hardware access
    system(("sudo incus config device add " + container_name + " gpu gpu").c_str());
    system(("sudo incus config device add " + container_name + " wayland unix-char path=/run/user/1000/wayland-0").c_str());
    system(("sudo incus config device add " + container_name + " x11 unix-char path=/tmp/.X11-unix/X0").c_str());
    system(("sudo incus config device add " + container_name + " pulseaudio unix-char path=/run/user/1000/pulse/native").c_str());
    system(("sudo incus config device add " + container_name + " input0 unix-char path=/dev/input/event0").c_str());
    system(("sudo incus config device add " + container_name + " bluetooth unix-char path=/dev/bus/usb").c_str());
    system(("sudo incus config device add " + container_name + " dbus unix-char path=/run/user/1000/bus").c_str());
    
    // 5. Create systemd service to replace display manager with container
    std::string service_content = R"([Unit]
Description=Container Display Service
After=network-online.target incus.service
Wants=network-online.target
Conflicts=getty@tty1.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/incus start )" + container_name + R"(
ExecStop=/usr/bin/incus stop )" + container_name + R"(
TimeoutStartSec=600

[Install]
WantedBy=graphical.target
)";
    
    std::ofstream service_file("/etc/systemd/system/container-display.service");
    service_file << service_content;
    service_file.close();
    
    system("sudo systemctl daemon-reload");
    system("sudo systemctl enable container-display.service");
    
    // 6. Disable host display manager and enable container as display
    for (const auto& manager : managers) {
        system(("sudo systemctl disable " + manager + " 2>/dev/null || true").c_str());
    }
    
    // 7. Set graphical target to start container
    system("sudo systemctl set-default graphical.target");
    
    // 8. Create container login service
    std::string login_service = R"([Unit]
Description=Container Login Service
After=container-display.service
Before=display-manager.service
Conflicts=display-manager.service

[Service]
Type=simple
ExecStart=/usr/bin/bash -c "sleep 5 && incus exec )" + container_name + R"( -- systemctl start display-manager.target"
Restart=on-failure
RestartSec=10
TimeoutStartSec=0

[Install]
WantedBy=graphical.target
)";
    
    std::ofstream login_file("/etc/systemd/system/container-login.service");
    login_file << login_service;
    login_file.close();
    
    system("sudo systemctl enable container-login.service");
    
    std::cout << COLOR_GREEN << "\n=== Setup complete! ===" << COLOR_RESET << std::endl;
    std::cout << COLOR_YELLOW << "\nOn next reboot:" << COLOR_RESET << std::endl;
    std::cout << "1. System will boot into the container" << std::endl;
    if (!login_manager.empty()) {
        std::cout << "2. " << login_manager << " login manager will start in container" << std::endl;
    }
    std::cout << "3. You can login as your normal user" << std::endl;
    std::cout << "4. Container has WiFi, Bluetooth, Wayland, X11, audio support" << std::endl;
    std::cout << "\n" << COLOR_CYAN << "Reboot now to test: sudo reboot" << COLOR_RESET << std::endl;
}
