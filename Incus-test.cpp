#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <filesystem>
#include <ctime>
#include <sys/statvfs.h>
#include <sys/statfs.h>
#include <sys/utsname.h>

namespace fs = std::filesystem;

// ANSI Color Codes
#define COLOR_RED     "\033[38;2;255;0;0m"
#define COLOR_CYAN    "\033[38;2;0;255;255m"
#define COLOR_GREEN   "\033[38;2;0;255;0m"
#define COLOR_YELLOW  "\033[38;2;255;255;0m"
#define COLOR_MAGENTA "\033[38;2;255;0;255m"
#define COLOR_RESET   "\033[0m"

class Logger {
private:
    std::ofstream logfile;
    std::string timestamp() {
        time_t now = time(0);
        char buf[100];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
        return std::string(buf);
    }
public:
    Logger() {
        logfile.open("/var/log/archfreeze.log", std::ios::app);
    }

    ~Logger() {
        if (logfile.is_open()) logfile.close();
    }

    void log(const std::string& msg, bool echo = true) {
        std::string logmsg = "[" + timestamp() + "] " + msg;
        if (echo) std::cout << COLOR_CYAN << "[LOG] " << COLOR_RESET << COLOR_CYAN << msg << COLOR_RESET << std::endl;
        if (logfile.is_open()) logfile << logmsg << std::endl;
    }

    void error(const std::string& msg) {
        std::string errmsg = "ERROR: " + msg;
        std::cout << COLOR_CYAN << "[ERROR] " << COLOR_RESET << COLOR_CYAN << msg << COLOR_RESET << std::endl;
        if (logfile.is_open()) logfile << "[" << timestamp() << "] ERROR: " << msg << std::endl;
    }

    void warn(const std::string& msg) {
        std::cout << COLOR_CYAN << "[WARN] " << COLOR_RESET << COLOR_CYAN << msg << COLOR_RESET << std::endl;
        if (logfile.is_open()) logfile << "[" << timestamp() << "] WARN: " << msg << std::endl;
    }

    void info(const std::string& msg) {
        std::cout << COLOR_CYAN << "[INFO] " << COLOR_RESET << COLOR_CYAN << msg << COLOR_RESET << std::endl;
        if (logfile.is_open()) logfile << "[" << timestamp() << "] INFO: " << msg << std::endl;
    }
};

class SystemCheck {
private:
    Logger& logger;
public:
    SystemCheck(Logger& log) : logger(log) {}

    bool checkRoot() {
        if (geteuid() != 0) {
            logger.error("Must be run as root");
            return false;
        }
        return true;
    }

    bool checkArch() {
        if (!fs::exists("/etc/arch-release")) {
            logger.error("This is not Arch Linux");
            return false;
        }
        return true;
    }

    bool checkFilesystem() {
        struct statfs fs;
        if (statfs("/", &fs) == 0) {
            logger.info("Filesystem check passed");
            return true;
        }
        return false;
    }

    bool checkKernel() {
        struct utsname uts;
        if (uname(&uts) == 0) {
            logger.info("Kernel: " + std::string(uts.release));
            return true;
        }
        return false;
    }

    bool checkDiskSpace() {
        struct statvfs vfs;
        if (statvfs("/var", &vfs) == 0) {
            unsigned long long free_bytes = vfs.f_bfree * vfs.f_bsize;
            unsigned long long free_gb = free_bytes / (1024 * 1024 * 1024);

            if (free_gb < 10) {
                logger.warn("Low disk space in /var: " + std::to_string(free_gb) + "GB free");
                logger.warn("At least 10GB recommended for Incus immutable system");
                return false;
            }
            logger.info("Disk space available: " + std::to_string(free_gb) + "GB");
            return true;
        }
        return true;
    }

    bool checkIncus() {
        // Check if incus is installed and running
        int result = system("incus --version >/dev/null 2>&1");
        if (result != 0) {
            logger.warn("Incus is not installed. Installing now...");
            result = system("pacman -S --noconfirm incus incus-ui 2>/dev/null");
            if (result != 0) {
                logger.error("Failed to install Incus");
                return false;
            }
        }
        
        // Initialize Incus if not already initialized
        if (!fs::exists("/var/lib/incus")) {
            logger.info("Initializing Incus...");
            result = system("incus admin init --auto --storage-backend=dir 2>/dev/null");
            if (result != 0) {
                logger.error("Failed to initialize Incus");
                return false;
            }
        }
        
        // Check if incus service is running
        result = system("systemctl is-active incus >/dev/null 2>&1");
        if (result != 0) {
            logger.info("Starting Incus service...");
            result = system("systemctl start incus 2>/dev/null && systemctl enable incus 2>/dev/null");
            if (result != 0) {
                logger.error("Failed to start Incus service");
                return false;
            }
        }
        
        logger.info("Incus check passed");
        return true;
    }

    bool performAllChecks() {
        logger.info("=== System Check ===");
        if (!checkRoot()) return false;
        if (!checkArch()) return false;
        if (!checkFilesystem()) return false;
        if (!checkKernel()) return false;
        if (!checkIncus()) return false;
        if (!checkDiskSpace()) {
            std::cout << COLOR_CYAN << "Continue anyway? (y/N): " << COLOR_RESET;
            std::string response;
            std::cin >> response;
            if (response != "y" && response != "Y") return false;
        }
        logger.info("All system checks passed");
        return true;
    }
};

class OverlayManager {
private:
    Logger& logger;
    std::string base_dir = "/var/lib/archfreeze";
    std::string upper_dir;
    std::string work_dir;
    std::string merged_dir;
    std::string squashfs_dir;

public:
    OverlayManager(Logger& log) : logger(log) {
        upper_dir = base_dir + "/upper";
        work_dir = base_dir + "/work";
        merged_dir = base_dir + "/merged";
        squashfs_dir = base_dir + "/squashfs";
    }

    bool createDirectories() {
        try {
            std::vector<std::string> dirs = {
                base_dir, upper_dir, work_dir, merged_dir, squashfs_dir,
                base_dir + "/snapshots",
                base_dir + "/backup",
                base_dir + "/working",
                base_dir + "/config",
                base_dir + "/incus-profiles"
            };

            for (const auto& dir : dirs) {
                if (!fs::exists(dir)) {
                    fs::create_directories(dir);
                    fs::permissions(dir, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec);
                    logger.info("Created directory: " + dir);
                }
            }

            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to create directories: " + std::string(e.what()));
            return false;
        }
    }

    bool mountOverlay() {
        logger.info("Creating SquashFS image for Incus...");
        return createSquashFSImage();
    }

    bool createSquashFSImage() {
        try {
            std::string clone_dir = base_dir + "/working/clone_system";
            std::string output_file = squashfs_dir + "/rootfs.img";
            
            // Create directories
            fs::create_directories(clone_dir);
            
            // Use mount --bind
            std::string cmd = "mount --bind / " + clone_dir;
            int result = system(cmd.c_str());
            
            if (result != 0) {
                logger.error("Failed to create bind mount");
                return false;
            }
            
            // Create necessary directories for Incus container
            cmd = "mkdir -p " + clone_dir + "/run/incus";
            result = system(cmd.c_str());
            
            if (result != 0) {
                logger.error("Failed to create /run/incus directory");
                system(("umount " + clone_dir + " 2>/dev/null").c_str());
                return false;
            }
            
            // Create SquashFS with exclusions optimized for Incus
            cmd = "mksquashfs " + clone_dir + " " + output_file + " ";
            cmd += "-noappend -comp xz -b 256K -Xbcj x86 ";
            cmd += "-e etc/udev/rules.d/70-persistent-cd.rules ";
            cmd += "-e etc/udev/rules.d/70-persistent-net.rules ";
            cmd += "-e etc/mtab ";
            cmd += "-e etc/fstab ";
            cmd += "-e etc/machine-id ";  // Exclude machine-id
            cmd += "-e dev/* ";
            cmd += "-e proc/* ";
            cmd += "-e sys/* ";
            cmd += "-e home/* ";
            cmd += "-e run/* ";
            cmd += "-e tmp/* ";
            cmd += "-e mnt/* ";
            cmd += "-e media/* ";
            cmd += "-e lost+found ";
            cmd += "-e var/lib/archfreeze ";
            cmd += "-e var/log/archfreeze.log ";
            cmd += "-e var/lib/incus ";
            cmd += "-e " + base_dir + "/*";
            
            result = system(cmd.c_str());
            
            // Cleanup
            system(("umount " + clone_dir + " 2>/dev/null").c_str());
            fs::remove_all(clone_dir);
            
            if (result != 0) {
                logger.error("Failed to create SquashFS image");
                return false;
            }
            
            logger.info("SquashFS image created: " + output_file);
            return true;
        } catch (const std::exception& e) {
            logger.error("SquashFS creation failed: " + std::string(e.what()));
            return false;
        }
    }

    void unmountOverlay() {
        logger.info("SquashFS image cleanup completed");
    }

    bool createFSTABEntry() {
        try {
            std::ifstream fstab_in("/etc/fstab");
            if (fstab_in.is_open()) {
                std::string line;
                while (std::getline(fstab_in, line)) {
                    if (line.find("archfreeze") != std::string::npos) {
                        logger.warn("Arch Freeze entry already exists in fstab");
                        return true;
                    }
                }
                fstab_in.close();
            }

            if (fs::exists("/etc/fstab")) {
                fs::copy("/etc/fstab", "/etc/fstab.backup", fs::copy_options::overwrite_existing);
                logger.info("Backed up /etc/fstab to /etc/fstab.backup");
            }

            std::ofstream fstab("/etc/fstab", std::ios::app);
            if (!fstab.is_open()) {
                logger.error("Cannot open /etc/fstab");
                return false;
            }

            fstab << "\n# Arch Freeze Immutable System with Incus\n";
            fstab << "# Managed by archfreeze scripts\n";
            fstab.close();
            
            logger.info("Updated /etc/fstab");
            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to update fstab: " + std::string(e.what()));
            return false;
        }
    }

    bool setupIncusImmutableContainer() {
        try {
            logger.info("Setting up Incus immutable container...");
            
            // Create Incus storage pool for archfreeze
            std::string cmd = "incus storage list --format csv | grep -q archfreeze-pool";
            int result = system(cmd.c_str());
            
            if (result != 0) {
                cmd = "incus storage create archfreeze-pool dir source=/var/lib/incus/storage-pools/archfreeze";
                result = system(cmd.c_str());
                if (result != 0) {
                    logger.error("Failed to create Incus storage pool");
                    return false;
                }
                logger.info("Created Incus storage pool: archfreeze-pool");
            }
            
            // Create Incus profile for immutable system
            cmd = "incus profile show immutable-system >/dev/null 2>&1";
            result = system(cmd.c_str());
            
            if (result != 0) {
                // Create profile with immutability settings
                cmd = "incus profile create immutable-system";
                result = system(cmd.c_str());
                
                if (result == 0) {
                    // Configure profile for true immutability
                    cmd = "incus profile set immutable-system security.privileged false";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system security.nesting false";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system security.protection.delete shifted";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system security.protection.shift true";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system security.syscalls.blacklist \"mount\"";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system security.syscalls.blacklist \"umount\"";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system security.syscalls.blacklist \"mount2\"";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system security.syscalls.blacklist \"umount2\"";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system security.syscalls.blacklist \"chroot\"";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system security.syscalls.blacklist \"pivot_root\"";
                    system(cmd.c_str());
                    
                    // Set boot.autostart
                    cmd = "incus profile set immutable-system boot.autostart true";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system boot.autostart.delay 5";
                    system(cmd.c_str());
                    
                    cmd = "incus profile set immutable-system boot.autostart.priority 0";
                    system(cmd.c_str());
                    
                    // Set readonly rootfs
                    cmd = "incus profile device add immutable-system root disk source=/ path=/ readonly=true";
                    system(cmd.c_str());
                    
                    logger.info("Created Incus profile: immutable-system");
                }
            }
            
            return true;
        } catch (const std::exception& e) {
            logger.error("Incus setup failed: " + std::string(e.what()));
            return false;
        }
    }

    bool createIncusImmutableContainer() {
        try {
            logger.info("Creating immutable Incus container...");
            
            // Check if container already exists
            std::string cmd = "incus list --format csv | grep -q ^archfreeze,";
            int result = system(cmd.c_str());
            
            if (result == 0) {
                logger.warn("Incus container 'archfreeze' already exists");
                std::cout << COLOR_CYAN << "Delete and recreate? (y/N): " << COLOR_RESET;
                std::string response;
                std::cin >> response;
                if (response == "y" || response == "Y") {
                    cmd = "incus delete archfreeze --force 2>/dev/null";
                    system(cmd.c_str());
                } else {
                    return true;
                }
            }
            
            // Create a minimal container first
            cmd = "incus init images:archlinux/current archfreeze -p immutable-system -s archfreeze-pool";
            result = system(cmd.c_str());
            
            if (result != 0) {
                logger.error("Failed to create Incus container");
                return false;
            }
            
            // Stop the container to modify it
            system("incus stop archfreeze --force 2>/dev/null");
            
            // Get container path
            std::string container_path = "/var/lib/incus/storage-pools/archfreeze-pool/containers/archfreeze";
            
            // Remove the default rootfs
            cmd = "rm -rf " + container_path + "/rootfs";
            system(cmd.c_str());
            
            // Create mount point for SquashFS
            cmd = "mkdir -p " + container_path + "/rootfs";
            system(cmd.c_str());
            
            // Create mount script that will mount SquashFS on container start
            std::string mount_script = container_path + "/mount-squashfs.sh";
            std::ofstream script(mount_script);
            
            script << "#!/bin/bash\n";
            script << "# Mount SquashFS as readonly root for immutable system\n";
            script << "SQUASHFS=\"/var/lib/archfreeze/squashfs/rootfs.img\"\n";
            script << "MOUNT_POINT=\"/var/lib/incus/storage-pools/archfreeze-pool/containers/archfreeze/rootfs\"\n\n";
            script << "if [ ! -f \"$SQUASHFS\" ]; then\n";
            script << "    echo \"ERROR: SquashFS image not found at $SQUASHFS\"\n";
            script << "    exit 1\n";
            script << "fi\n\n";
            script << "# Clean mount point\n";
            script << "umount \"$MOUNT_POINT\" 2>/dev/null || true\n";
            script << "rm -rf \"$MOUNT_POINT/*\" 2>/dev/null || true\n\n";
            script << "# Mount SquashFS as readonly\n";
            script << "mount -t squashfs \"$SQUASHFS\" \"$MOUNT_POINT\" -o loop,ro\n\n
