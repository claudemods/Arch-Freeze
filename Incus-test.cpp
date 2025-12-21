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
void createContainer();
void run_command(const std::string& command, bool show_output = true);
void capture_and_display_rsync_output(const std::vector<std::string>& command);
void setupContainerBoot(const std::string& container_name);

// Global variables
std::string container_name = "";
std::string container_username = "";

// Run system command
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

// OPTION 1: Name the fucking container
void nameContainer() {
    std::cout << COLOR_CYAN << "\n=== OPTION 1: Name Container ===\n" << COLOR_RESET;
    std::cout << COLOR_CYAN << "Enter container name: " << COLOR_RESET;

    // Clear input buffer
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    std::getline(std::cin, container_name);

    if (container_name.empty()) {
        std::cout << COLOR_RED << "Container name cannot be empty!" << COLOR_RESET << std::endl;
        return;
    }

    std::cout << COLOR_GREEN << "✓ Container name set to: " << container_name << COLOR_RESET << std::endl;
    
    // Also ask for username
    std::cout << COLOR_CYAN << "Enter username for container login: " << COLOR_RESET;
    std::getline(std::cin, container_username);
    
    if (container_username.empty()) {
        std::cout << COLOR_RED << "Username cannot be empty!" << COLOR_RESET << std::endl;
        container_username = "";
        return;
    }
    
    std::cout << COLOR_GREEN << "✓ Username set to: " << container_username << COLOR_RESET << std::endl;
    std::cout << COLOR_YELLOW << "Note: Now select Option 2 to create it.\n" << COLOR_RESET << std::endl;
}

// OPTION 2: Create the fucking container
void createContainer() {
    if (container_name.empty()) {
        std::cout << COLOR_RED << "Error: No container name set. Use Option 1 first!\n" << COLOR_RESET << std::endl;
        return;
    }
    
    if (container_username.empty()) {
        std::cout << COLOR_RED << "Error: No username set. Use Option 1 first!\n" << COLOR_RESET << std::endl;
        return;
    }

    std::cout << COLOR_CYAN << "\n=== OPTION 2: Creating Container '" << container_name << "' ===\n" << COLOR_RESET;

    std::string rootfs_path = "/var/lib/incus/storage-pools/default/containers/" + container_name + "/rootfs";

    // Create components profile
    std::cout << COLOR_CYAN << "1. Creating hardware profile..." << COLOR_RESET << std::endl;
    std::string cmd = "sudo incus profile create components < components.yaml";
    run_command(cmd);

    // Create base container with privileged mode using archlinux image and components profile
    std::cout << COLOR_CYAN << "2. Creating base container with username: " << container_username << "..." << COLOR_RESET << std::endl;
    cmd = "sudo incus launch images:archlinux " + container_name + " -c security.privileged=true --profile default --profile components";
    run_command(cmd);

    // Prompt user to manually stop container
    std::cout << COLOR_YELLOW << "\n3. IMPORTANT: Manually stop the container using:\n";
    std::cout << "   sudo incus stop " << container_name << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "Press Enter after stopping the container..." << COLOR_RESET;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();

    // Verify container is stopped
    if (system(("sudo incus list | grep -q " + container_name + ".*STOPPED").c_str()) != 0) {
        std::cout << COLOR_RED << "Container is still running. Please stop it first." << COLOR_RESET << std::endl;
        return;
    }

    // Clear existing rootfs contents
    std::cout << COLOR_CYAN << "4. Clearing existing rootfs..." << COLOR_RESET << std::endl;
    cmd = "sudo rm -rf " + rootfs_path + "/*";
    run_command(cmd);

    // SINGLE RSYNC COMMAND - Clone system excluding special directories
    std::cout << COLOR_CYAN << "5. Cloning system to container..." << COLOR_RESET << std::endl;
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
    std::cout << COLOR_GREEN << "✓ System cloned successfully" << COLOR_RESET << std::endl;

    // Start container
    std::cout << COLOR_CYAN << "6. Starting container..." << COLOR_RESET << std::endl;
    cmd = "sudo incus start " + container_name;
    run_command(cmd);

    // Setup container boot
    std::cout << COLOR_CYAN << "7. Setting up container boot..." << COLOR_RESET << std::endl;
    setupContainerBoot(container_name);

    // Execute bash in container with the specified username
    std::cout << COLOR_CYAN << "8. Launching container shell as user: " << container_username << "..." << COLOR_RESET << std::endl;
    cmd = "sudo incus exec " + container_name + " -- su - " + container_username;
    system(cmd.c_str());
}

// Setup container to be the boot target
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
        std::cout << COLOR_YELLOW << "No login manager found." << COLOR_RESET << std::endl;
    }

    std::cout << COLOR_GREEN << "\n✓ Container setup complete!" << COLOR_RESET << std::endl;
    std::cout << COLOR_YELLOW << "\nReboot to use container as main system: sudo reboot\n" << COLOR_RESET << std::endl;
}

// Show fucking menu
void showMenu() {
    int choice = 0;

    do {
        std::cout << COLOR_CYAN << "\n=== Arch Freeze MENU ===\n" << COLOR_RESET;
        std::cout << "Current container: " << (container_name.empty() ? std::string(COLOR_RED) + "NOT SET" + COLOR_RESET : std::string(COLOR_GREEN) + container_name + COLOR_RESET) << "\n";
        std::cout << "Username: " << (container_username.empty() ? std::string(COLOR_RED) + "NOT SET" + COLOR_RESET : std::string(COLOR_GREEN) + container_username + COLOR_RESET) << "\n";
        std::cout << COLOR_YELLOW << "1. Name Container & Set Username\n";
        std::cout << "2. Create Container (clone system)\n";
        std::cout << "3. Exit\n" << COLOR_RESET;
        std::cout << COLOR_CYAN << "Choice [1-3]: " << COLOR_RESET;

        std::cin >> choice;

        switch(choice) {
            case 1:
                nameContainer();
                break;
            case 2:
                createContainer();
                break;
            case 3:
                std::cout << COLOR_CYAN << "Exiting...\n" << COLOR_RESET;
                break;
            default:
                std::cout << COLOR_RED << "Invalid choice!\n" << COLOR_RESET;
        }

    } while (choice != 3);
}

int main() {
    std::cout << APEX_ART;
    std::cout << COLOR_CYAN << "claudemods Arch Freeze Beta v1.0\n" << COLOR_RESET;
    
    // Quick check for Incus
    if (system("command -v incus &> /dev/null") != 0) {
        std::cout << COLOR_RED << "Incus is not installed!\n" << COLOR_RESET;
        return 1;
    }

    showMenu();
    return 0;
}
