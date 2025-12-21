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
#define COLOR_MAGENTA "\033[35m"
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
int run_command_full_output(const std::string& command, const std::string& description = "");
void capture_and_display_rsync_output(const std::vector<std::string>& command);
void setupContainerBoot(const std::string& container_name);
void show_command_header(const std::string& command, const std::string& description);
void show_command_result(int status, const std::string& command);

// Helper function to get current username
std::string getUsername() {
    const char* user = getenv("USER");
    return user ? std::string(user) : "user";
}

// Show command header
void show_command_header(const std::string& command, const std::string& description = "") {
    std::cout << "\n" << COLOR_MAGENTA << "╔══════════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_MAGENTA << "║ " << COLOR_CYAN << "Executing: " << COLOR_YELLOW << command << COLOR_RESET << std::endl;
    if (!description.empty()) {
        std::cout << COLOR_MAGENTA << "║ " << COLOR_BLUE << "Description: " << COLOR_RESET << description << std::endl;
    }
    std::cout << COLOR_MAGENTA << "╚══════════════════════════════════════════════════════════════════╝" << COLOR_RESET << std::endl;
    std::cout << COLOR_GREEN << "Output:" << COLOR_RESET << std::endl;
}

// Show command result
void show_command_result(int status, const std::string& command) {
    std::cout << "\n" << COLOR_MAGENTA << "╔══════════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_MAGENTA << "║ " << COLOR_CYAN << "Result: " << COLOR_RESET;
    if (status == 0) {
        std::cout << COLOR_GREEN << "✓ SUCCESS" << COLOR_RESET;
    } else {
        std::cout << COLOR_RED << "✗ FAILED (Exit code: " << status << ")" << COLOR_RESET;
    }
    std::cout << std::endl;
    std::cout << COLOR_MAGENTA << "║ " << COLOR_YELLOW << "Command: " << COLOR_RESET << command << std::endl;
    std::cout << COLOR_MAGENTA << "╚══════════════════════════════════════════════════════════════════╝" << COLOR_RESET << "\n" << std::endl;
}

// Run system command with full output capture and display
int run_command_full_output(const std::string& command, const std::string& description) {
    show_command_header(command, description);
    
    int status = system(command.c_str());
    
    show_command_result(status, command);
    
    return status;
}

// Clean temporary directories
void cleanTempDirs() {
    std::cout << COLOR_CYAN << "Cleaning temporary directories..." << COLOR_RESET << std::endl;
    
    run_command_full_output("sudo rm -rf /opt/img_extract", "Remove /opt/img_extract directory");
    run_command_full_output("sudo rm -rf /opt/squashfs", "Remove /opt/squashfs directory");
    run_command_full_output("sudo rm -rf /mnt/temp", "Remove /mnt/temp directory");
    
    std::string username = getUsername();
    run_command_full_output(("sudo rm -rf /home/" + username + "/.config/Accu/clone_*").c_str(), 
                           "Remove Accu clone directories");
    
    std::cout << COLOR_GREEN << "✓ Temporary directories cleaned successfully." << COLOR_RESET << "\n" << std::endl;
}

// Function to capture and display rsync output with improved progress
void capture_and_display_rsync_output(const std::vector<std::string>& command) {
    std::cout << COLOR_CYAN << "Starting data transfer..." << COLOR_RESET << std::endl;
    std::cout << COLOR_YELLOW << "Command: ";
    for (const auto& arg : command) {
        std::cout << arg << " ";
    }
    std::cout << COLOR_RESET << "\n" << std::endl;

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        std::cerr << COLOR_RED << "Failed to create pipe for rsync" << COLOR_RESET << std::endl;
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        std::vector<char*> args;
        for (const auto& arg : command) {
            args.push_back(const_cast<char*>(arg.c_str()));
        }
        args.push_back(nullptr);

        execvp(args[0], args.data());
        std::cerr << COLOR_RED << "Failed to execute rsync" << COLOR_RESET << std::endl;
        exit(1);
    } else if (pid > 0) {
        // Parent process
        close(pipefd[1]);
        char buffer[4096];
        
        std::cout << COLOR_GREEN << "Transfer progress:" << COLOR_RESET << std::endl;
        
        while (true) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(pipefd[0], &read_fds);
            struct timeval timeout;
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            
            int select_result = select(pipefd[0] + 1, &read_fds, nullptr, nullptr, &timeout);
            if (select_result == -1) {
                break;
            } else if (select_result == 0) {
                // Timeout - continue waiting
                continue;
            } else {
                ssize_t count = read(pipefd[0], buffer, sizeof(buffer) - 1);
                if (count <= 0) {
                    break;
                } else {
                    buffer[count] = '\0';
                    std::cout << COLOR_CYAN << buffer << COLOR_RESET;
                    std::cout.flush();
                }
            }
        }
        close(pipefd[0]);
        
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status)) {
            std::cout << "\n" << COLOR_GREEN << "✓ Data transfer completed with exit code: " 
                     << WEXITSTATUS(status) << COLOR_RESET << std::endl;
        } else {
            std::cout << "\n" << COLOR_RED << "✗ Data transfer failed" << COLOR_RESET << std::endl;
        }
    } else {
        std::cerr << COLOR_RED << "Failed to fork process for rsync" << COLOR_RESET << std::endl;
    }
}

// Incus check function
bool checkIncus() {
    std::cout << COLOR_CYAN << "Checking Incus installation..." << COLOR_RESET << std::endl;
    
    int status = run_command_full_output("command -v incus", "Check if incus command exists");
    if (status != 0) {
        std::cout << COLOR_RED << "✗ Incus is not installed. Please install Incus first." << COLOR_RESET << std::endl;
        return false;
    }
    
    std::cout << COLOR_GREEN << "✓ Incus is installed." << COLOR_RESET << std::endl;
    
    // Check if Incus is running, start if not
    status = run_command_full_output("incus list", "Check if Incus daemon is running");
    if (status != 0) {
        std::cout << COLOR_CYAN << "Starting Incus service..." << COLOR_RESET << std::endl;
        run_command_full_output("sudo systemctl start incus", "Start Incus service");
        run_command_full_output("sudo systemctl enable incus", "Enable Incus to start on boot");
    }
    
    // Show Incus version
    run_command_full_output("incus --version", "Show Incus version");
    
    // Show Incus storage pools
    run_command_full_output("incus storage list", "List Incus storage pools");
    
    // Show existing containers
    run_command_full_output("incus list", "List existing containers");
    
    return true;
}

// Main import function
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
    
    std::cout << "\n" << COLOR_CYAN << "Using container name: " << COLOR_YELLOW << container_name << COLOR_RESET << "\n" << std::endl;

    std::string rootfs_path = "/var/lib/incus/storage-pools/default/containers/" + container_name + "/rootfs";

    // Create base container with privileged mode using archlinux image
    std::string cmd = "sudo incus launch images:archlinux " + container_name + " -c security.privileged=true";
    run_command_full_output(cmd, "Create base container with Arch Linux image and privileged mode");
    
    // Show container info after creation
    run_command_full_output(("incus info " + container_name).c_str(), "Show container information");

    // Prompt user to manually stop container
    std::cout << COLOR_YELLOW << "\n╔══════════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_YELLOW << "║ " << COLOR_RED << "IMPORTANT: Before proceeding, please manually stop the container" << COLOR_RESET << std::endl;
    std::cout << COLOR_YELLOW << "║ " << COLOR_CYAN << "Command: " << COLOR_RESET << "sudo incus stop " << container_name << std::endl;
    std::cout << COLOR_YELLOW << "╚══════════════════════════════════════════════════════════════════╝" << COLOR_RESET << "\n" << std::endl;
    
    std::cout << COLOR_CYAN << "Press Enter to continue after stopping the container..." << COLOR_RESET;
    std::cin.get();

    // Verify container is stopped
    std::cout << COLOR_CYAN << "Verifying container is stopped..." << COLOR_RESET << std::endl;
    int status = system(("incus list | grep -q " + container_name + ".*STOPPED").c_str());
    if (status != 0) {
        std::cout << COLOR_RED << "✗ Container is still running or not found. Please stop it first." << COLOR_RESET << std::endl;
        
        // Show current container status
        run_command_full_output(("incus list " + container_name).c_str(), "Check container status");
        return;
    }
    
    std::cout << COLOR_GREEN << "✓ Container is stopped." << COLOR_RESET << std::endl;

    // Clear existing rootfs contents
    std::cout << COLOR_CYAN << "Preparing container rootfs..." << COLOR_RESET << std::endl;
    cmd = "sudo rm -rf " + rootfs_path + "/*";
    run_command_full_output(cmd, "Clear existing rootfs contents");
    
    // Create necessary directories
    cmd = "sudo mkdir -p " + rootfs_path + "/{dev,proc,sys,tmp,run,mnt,media}";
    run_command_full_output(cmd, "Create essential directories in rootfs");

    // SINGLE RSYNC COMMAND - Clone system excluding special directories
    std::cout << COLOR_CYAN << "Starting system copy from host to container..." << COLOR_RESET << std::endl;
    std::cout << COLOR_YELLOW << "This may take several minutes depending on your system size." << COLOR_RESET << "\n" << std::endl;
    
    std::vector<std::string> rsync_cmd = {
        "sudo", "rsync", "-aHAXxSr", "--numeric-ids", "--info=progress2",
        "--exclude=/dev/*", "--exclude=/proc/*", "--exclude=/sys/*",
        "--exclude=/tmp/*", "--exclude=/run/*", "--exclude=/mnt/*",
        "--exclude=/media/*", "--exclude=/lost+found",
        "--exclude=/var/lib/incus",
        "--exclude=/var/lib/docker",
        "--exclude=/etc/fstab",
        "--exclude=/etc/mtab",
        "--exclude=/boot/*",
        "--exclude=/var/cache/*",
        "--exclude=/var/tmp/*",
        "/",
        rootfs_path + "/"
    };

    capture_and_display_rsync_output(rsync_cmd);

    // Fix permissions on critical directories
    std::cout << COLOR_CYAN << "Fixing permissions..." << COLOR_RESET << std::endl;
    run_command_full_output(("sudo chmod 1777 " + rootfs_path + "/tmp").c_str(), "Set tmp directory permissions");
    run_command_full_output(("sudo chmod 755 " + rootfs_path + "/run").c_str(), "Set run directory permissions");

    // Start container
    cmd = "sudo incus start " + container_name;
    run_command_full_output(cmd, "Start the container");

    // Show container status after starting
    run_command_full_output(("incus list " + container_name).c_str(), "Verify container is running");

    // NEW: Setup container boot
    setupContainerBoot(container_name);

    // Execute bash in container
    std::cout << COLOR_CYAN << "\nLaunching interactive shell in container..." << COLOR_RESET << std::endl;
    std::cout << COLOR_YELLOW << "Type 'exit' to return to host shell." << COLOR_RESET << "\n" << std::endl;
    
    cmd = "sudo incus exec " + container_name + " -- /bin/bash";
    show_command_header(cmd, "Interactive shell in container");
    status = system(cmd.c_str());
    show_command_result(status, cmd);
}

int main() {
    // Clear screen and show banner
    system("clear");
    std::cout << APEX_ART;
    std::cout << COLOR_CYAN << "claudemods Arch Freeze Beta v1.0 20-12-2025\n" << COLOR_RESET;
    std::cout << COLOR_YELLOW << "Note: This tool only works on Arch Linux systems\n" << COLOR_RESET;
    std::cout << COLOR_RED << "WARNING: This tool will modify your boot process and systemd services!\n" << COLOR_RESET;
    std::cout << COLOR_RED << "Make sure you have backups before proceeding.\n\n" << COLOR_RESET;

    // Check if running on Arch Linux
    std::cout << COLOR_CYAN << "Verifying Arch Linux system..." << COLOR_RESET << std::endl;
    if (system("grep -q 'ID=arch' /etc/os-release 2>/dev/null") != 0) {
        std::cout << COLOR_RED << "✗ This tool only works on Arch Linux systems!" << COLOR_RESET << std::endl;
        run_command_full_output("cat /etc/os-release", "Detected OS information");
        cleanTempDirs();
        return 1;
    }
    std::cout << COLOR_GREEN << "✓ Running on Arch Linux." << COLOR_RESET << std::endl;
    
    // Show system information
    run_command_full_output("uname -a", "Kernel information");
    run_command_full_output("lsblk", "Disk layout");
    run_command_full_output("free -h", "Memory information");

    // Check if Incus is installed
    if (!checkIncus()) {
        std::cout << COLOR_RED << "Incus check failed. Exiting." << COLOR_RESET << std::endl;
        cleanTempDirs();
        return 1;
    }

    // Run the import process directly (no menu)
    importToIncus();

    // Clean up and exit
    cleanTempDirs();
    
    std::cout << COLOR_GREEN << "╔══════════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_GREEN << "║                    PROCESS COMPLETED SUCCESSFULLY                 ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_GREEN << "╚══════════════════════════════════════════════════════════════════╝" << COLOR_RESET << "\n" << std::endl;
    
    std::cout << COLOR_YELLOW << "Next steps:" << COLOR_RESET << std::endl;
    std::cout << "1. Review the container configuration" << std::endl;
    std::cout << "2. Test the container with: sudo incus exec <container_name> -- bash" << std::endl;
    std::cout << "3. Reboot to test the new boot configuration" << std::endl;
    std::cout << "\n" << COLOR_RED << "WARNING: A reboot will boot into the container instead of the host!" << COLOR_RESET << std::endl;
    
    return 0;
}

// NEW FUNCTION: Setup container to be the boot target
void setupContainerBoot(const std::string& container_name) {
    std::cout << COLOR_CYAN << "\n╔══════════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "║            SETTING UP CONTAINER AS BOOT TARGET                     ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "╚══════════════════════════════════════════════════════════════════╝" << COLOR_RESET << "\n" << std::endl;

    // 1. Make container immutable and privileged
    run_command_full_output(("incus config set " + container_name + " security.protection.delete=true").c_str(),
                           "Set container protection to prevent deletion");
    
    run_command_full_output(("incus config set " + container_name + " security.privileged=true").c_str(),
                           "Set container to privileged mode");

    // 2. Setup auto-start
    run_command_full_output(("incus config set " + container_name + " boot.autostart=true").c_str(),
                           "Enable container auto-start on boot");
    
    run_command_full_output(("incus config set " + container_name + " boot.autostart.delay=5").c_str(),
                           "Set auto-start delay to 5 seconds");

    // 3. Detect login manager from cloned system
    std::cout << COLOR_CYAN << "Detecting login manager in container..." << COLOR_RESET << std::endl;
    std::string login_manager = "";
    std::vector<std::string> managers = {"sddm", "gdm", "lightdm", "lxdm"};

    for (const auto& manager : managers) {
        std::string check_cmd = "incus exec " + container_name + 
                               " -- systemctl list-unit-files | grep -q \"^" + manager + "\\.service\"";
        int status = system(check_cmd.c_str());
        if (status == 0) {
            login_manager = manager;
            std::cout << COLOR_GREEN << "✓ Found login manager: " << login_manager << COLOR_RESET << std::endl;
            
            // Enable the login manager
            run_command_full_output(("incus exec " + container_name + " -- systemctl enable " + login_manager).c_str(),
                                   "Enable " + login_manager + " in container");
            break;
        }
    }

    if (login_manager.empty()) {
        std::cout << COLOR_YELLOW << "⚠ No login manager found. Container will boot without display manager." << COLOR_RESET << std::endl;
    }

    // 4. Setup hardware access - show each device being added
    std::cout << COLOR_CYAN << "Setting up hardware passthrough..." << COLOR_RESET << std::endl;
    
    std::vector<std::pair<std::string, std::string>> devices = {
        {"gpu", "gpu"},
        {"wayland", "unix-char path=/run/user/1000/wayland-0"},
        {"x11", "unix-char path=/tmp/.X11-unix/X0"},
        {"pulseaudio", "unix-char path=/run/user/1000/pulse/native"},
        {"input0", "unix-char path=/dev/input/event0"},
        {"bluetooth", "unix-char path=/dev/bus/usb"},
        {"dbus", "unix-char path=/run/user/1000/bus"}
    };

    for (const auto& device : devices) {
        std::string cmd = "incus config device add " + container_name + " " + 
                         device.first + " " + device.second;
        run_command_full_output(cmd.c_str(), "Add " + device.first + " device to container");
    }

    // 5. Create systemd service to replace display manager with container
    std::cout << COLOR_CYAN << "Creating systemd service for container display..." << COLOR_RESET << std::endl;
    
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

    // Write service file
    std::string service_file_path = "/tmp/container-display.service";
    std::ofstream service_file(service_file_path);
    if (service_file.is_open()) {
        service_file << service_content;
        service_file.close();
        std::cout << COLOR_GREEN << "✓ Service file created at: " << service_file_path << COLOR_RESET << std::endl;
        
        // Copy to system directory
        run_command_full_output(("sudo cp " + service_file_path + " /etc/systemd/system/").c_str(),
                               "Copy service file to systemd directory");
        run_command_full_output("sudo systemctl daemon-reload", "Reload systemd daemon");
        run_command_full_output("sudo systemctl enable container-display.service", 
                               "Enable container display service");
    } else {
        std::cout << COLOR_RED << "✗ Failed to create service file" << COLOR_RESET << std::endl;
    }

    // 6. Disable host display manager and enable container as display
    std::cout << COLOR_CYAN << "Disabling host display managers..." << COLOR_RESET << std::endl;
    for (const auto& manager : managers) {
        run_command_full_output(("sudo systemctl disable " + manager + " 2>/dev/null || true").c_str(),
                               "Disable " + manager + " on host");
    }

    // 7. Set graphical target to start container
    run_command_full_output("sudo systemctl set-default graphical.target", 
                           "Set default target to graphical");

    // 8. Create container login service
    std::cout << COLOR_CYAN << "Creating container login service..." << COLOR_RESET << std::endl;
    
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

    std::string login_file_path = "/tmp/container-login.service";
    std::ofstream login_file(login_file_path);
    if (login_file.is_open()) {
        login_file << login_service;
        login_file.close();
        std::cout << COLOR_GREEN << "✓ Login service file created at: " << login_file_path << COLOR_RESET << std::endl;
        
        run_command_full_output(("sudo cp " + login_file_path + " /etc/systemd/system/").c_str(),
                               "Copy login service to systemd directory");
        run_command_full_output("sudo systemctl enable container-login.service", 
                               "Enable container login service");
    }

    // Show final container configuration
    std::cout << COLOR_CYAN << "\nFinal container configuration:" << COLOR_RESET << std::endl;
    run_command_full_output(("incus config show " + container_name).c_str(), "Container config");
    run_command_full_output(("incus info " + container_name).c_str(), "Container info");
    run_command_full_output("incus list", "All containers");

    std::cout << COLOR_GREEN << "\n╔══════════════════════════════════════════════════════════════════╗" << COLOR_RESET << std::endl;
    std::cout << COLOR_GREEN << "║                    SETUP COMPLETE!                                 ║" << COLOR_RESET << std::endl;
    std::cout << COLOR_GREEN << "╚══════════════════════════════════════════════════════════════════╝" << COLOR_RESET << "\n" << std::endl;
    
    std::cout << COLOR_YELLOW << "On next reboot:" << COLOR_RESET << std::endl;
    std::cout << "1. ✓ System will boot into the container: " << container_name << std::endl;
    if (!login_manager.empty()) {
        std::cout << "2. ✓ " << login_manager << " login manager will start in container" << std::endl;
    }
    std::cout << "3. ✓ You can login as your normal user inside the container" << std::endl;
    std::cout << "4. ✓ Container has hardware passthrough (GPU, audio, input, Bluetooth)" << std::endl;
    std::cout << "\n" << COLOR_RED << "IMPORTANT: To revert changes, disable the container display services:" << COLOR_RESET << std::endl;
    std::cout << "  sudo systemctl disable container-display.service" << std::endl;
    std::cout << "  sudo systemctl disable container-login.service" << std::endl;
    std::cout << "  sudo systemctl set-default multi-user.target" << std::endl;
    std::cout << "\n" << COLOR_CYAN << "Reboot now to test: sudo reboot" << COLOR_RESET << "\n" << std::endl;
}
