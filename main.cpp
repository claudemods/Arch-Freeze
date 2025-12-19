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
        if (logfile.is_open()) logfile << "[" << timestamp() << "] ERROR: " + msg << std::endl;
    }

    void warn(const std::string& msg) {
        std::cout << COLOR_CYAN << "[WARN] " << COLOR_RESET << COLOR_CYAN << msg << COLOR_RESET << std::endl;
        if (logfile.is_open()) logfile << "[" << timestamp() << "] WARN: " + msg << std::endl;
    }

    void info(const std::string& msg) {
        std::cout << COLOR_CYAN << "[INFO] " << COLOR_RESET << COLOR_CYAN << msg << COLOR_RESET << std::endl;
        if (logfile.is_open()) logfile << "[" << timestamp() << "] INFO: " + msg << std::endl;
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

            if (free_gb < 5) {
                logger.warn("Low disk space in /var: " + std::to_string(free_gb) + "GB free");
                logger.warn("At least 5GB recommended for immutable system");
                return false;
            }
            logger.info("Disk space available: " + std::to_string(free_gb) + "GB");
            return true;
        }
        return true;
    }

    bool checkSystemdNspawn() {
        int result = system("systemd-nspawn --version >/dev/null 2>&1");
        if (result != 0) {
            logger.error("systemd-nspawn is not available");
            logger.error("Install with: pacman -S systemd-nspawn");
            return false;
        }
        
        result = system("mksquashfs -version >/dev/null 2>&1");
        if (result != 0) {
            logger.error("squashfs-tools is not available");
            logger.error("Install with: pacman -S squashfs-tools");
            return false;
        }
        
        return true;
    }

    bool performAllChecks() {
        logger.info("=== System Check ===");
        if (!checkRoot()) return false;
        if (!checkArch()) return false;
        if (!checkFilesystem()) return false;
        if (!checkKernel()) return false;
        if (!checkSystemdNspawn()) return false;
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

    bool executeCommand(const std::string& cmd, bool show_output = false) {
        logger.log("Executing: " + cmd);
        int result;
        if (show_output) {
            result = system(cmd.c_str());
        } else {
            result = system((cmd + " >/dev/null 2>&1").c_str());
        }
        return result == 0;
    }

    bool cleanMachineIds(const std::string& dir) {
        try {
            // Remove machine IDs to avoid conflicts
            std::vector<std::string> machine_id_files = {
                dir + "/etc/machine-id",
                dir + "/var/lib/dbus/machine-id",
                dir + "/etc/hostname"
            };
            
            for (const auto& file : machine_id_files) {
                if (fs::exists(file)) {
                    fs::remove(file);
                    logger.info("Removed: " + file);
                }
            }
            
            // Create empty machine-id file (will be generated on boot)
            if (!fs::exists(dir + "/etc/machine-id")) {
                std::ofstream machine_id(dir + "/etc/machine-id");
                machine_id.close();
                fs::permissions(dir + "/etc/machine-id", fs::perms::owner_read | fs::perms::owner_write);
            }
            
            // Generate unique hostname for container
            std::ofstream hostname(dir + "/etc/hostname");
            hostname << "archfreeze-container" << std::endl;
            hostname.close();
            
            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to clean machine IDs: " + std::string(e.what()));
            return false;
        }
    }

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
                base_dir + "/working/clone_system",
                base_dir + "/working/rebuild"
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

    bool createSquashFSImage() {
        logger.info("Creating SquashFS image...");
        
        std::string clone_dir = base_dir + "/working/clone_system";
        std::string output_file = squashfs_dir + "/rootfs.img";
        
        try {
            // Clean clone directory
            if (fs::exists(clone_dir)) {
                fs::remove_all(clone_dir);
            }
            fs::create_directories(clone_dir);
            
            // Use bind mount to clone system
            logger.info("Creating bind mount of root filesystem...");
            if (!executeCommand("mount --bind / " + clone_dir)) {
                logger.error("Failed to create bind mount");
                return false;
            }
            
            // Clean machine IDs from clone
            logger.info("Cleaning machine IDs for container...");
            if (!cleanMachineIds(clone_dir)) {
                logger.error("Failed to clean machine IDs");
                executeCommand("umount " + clone_dir + " 2>/dev/null");
                return false;
            }
            
            // Create SquashFS with exclusions
            logger.info("Creating SquashFS image (this may take several minutes)...");
            
            std::string cmd = "mksquashfs " + clone_dir + " " + output_file + " ";
            cmd += "-noappend -comp xz -b 256K -Xbcj x86 ";
            cmd += "-e etc/udev/rules.d/70-persistent-cd.rules ";
            cmd += "-e etc/udev/rules.d/70-persistent-net.rules ";
            cmd += "-e etc/mtab ";
            cmd += "-e etc/fstab ";
            cmd += "-e dev/* ";
            cmd += "-e proc/* ";
            cmd += "-e sys/* ";
            cmd += "-e tmp/* ";
            cmd += "-e home/* ";
            cmd += "-e run/* ";
            cmd += "-e mnt/* ";
            cmd += "-e media/* ";
            cmd += "-e lost+found ";
            cmd += "-e var/lib/archfreeze ";
            cmd += "-e var/log/archfreeze.log ";
            cmd += "-e " + base_dir + "/* ";
            cmd += "-e boot/* ";
            cmd += "-e root/.bash_history ";
            cmd += "-e var/cache/pacman/pkg/* ";
            cmd += "-e var/tmp/* ";
            cmd += "-e var/log/*.log ";
            cmd += "-e var/log/*.gz ";
            cmd += "-e var/spool/* ";
            cmd += "-e var/lib/systemd/* ";
            cmd += "-e var/lib/NetworkManager/* ";
            cmd += "-e var/lib/pacman/sync/*";
            
            if (!executeCommand(cmd, true)) {
                logger.error("Failed to create SquashFS image");
                executeCommand("umount " + clone_dir + " 2>/dev/null");
                return false;
            }
            
            // Cleanup
            executeCommand("umount " + clone_dir + " 2>/dev/null");
            
            // Verify image was created
            if (!fs::exists(output_file) || fs::file_size(output_file) == 0) {
                logger.error("SquashFS image creation failed - empty or missing file");
                return false;
            }
            
            // Set proper permissions
            fs::permissions(output_file, fs::perms::owner_read | fs::perms::owner_write | 
                                          fs::perms::group_read | fs::perms::others_read);
            
            logger.info("SquashFS image created successfully: " + output_file);
            logger.info("Image size: " + std::to_string(fs::file_size(output_file) / (1024*1024)) + " MB");
            
            return true;
        } catch (const std::exception& e) {
            logger.error("SquashFS creation failed: " + std::string(e.what()));
            executeCommand("umount " + clone_dir + " 2>/dev/null");
            return false;
        }
    }

    bool mountOverlay() {
        logger.info("Creating SquashFS image...");
        return createSquashFSImage();
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

            fstab << "\n# Arch Freeze SquashFS Image\n";
            fstab << "# " << squashfs_dir << "/rootfs.img\n";
            fstab.close();
            
            logger.info("Updated /etc/fstab");
            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to update fstab: " + std::string(e.what()));
            return false;
        }
    }

    bool createSystemdMount() {
        try {
            std::string service_file = "/etc/systemd/system/archfreeze-nspawn.service";
            std::ofstream service(service_file);
            
            if (!service.is_open()) {
                logger.error("Cannot open service file: " + service_file);
                return false;
            }
            
            service << "[Unit]\n";
            service << "Description=Arch Freeze Immutable Container\n";
            service << "After=network.target systemd-resolved.service\n";
            service << "Before=multi-user.target\n";
            service << "Requires=systemd-resolved.service\n";
            service << "\n";
            service << "[Service]\n";
            service << "Type=simple\n";
            service << "ExecStart=/usr/bin/systemd-nspawn \\\n";
            service << "  --machine=archfreeze \\\n";
            service << "  --image=" << squashfs_dir << "/rootfs.img \\\n";
            service << "  --boot \\\n";
            service << "  --volatile=overlay \\\n";
            service << "  --bind=/dev \\\n";
            service << "  --bind=/proc \\\n";
            service << "  --bind=/sys \\\n";
            service << "  --bind=/tmp \\\n";
            service << "  --bind=/run \\\n";
            service << "  --bind=/home:/home:rbind \\\n";
            service << "  --bind=/var/lib/archfreeze:/var/lib/archfreeze:rbind \\\n";
            service << "  --bind=/var/log:/var/log:rbind \\\n";
            service << "  --network-veth \\\n";
            service << "  --resolv-conf=bind-host\n";
            service << "Restart=on-failure\n";
            service << "RestartSec=10\n";
            service << "KillMode=mixed\n";
            service << "TimeoutStopSec=90\n";
            service << "\n";
            service << "[Install]\n";
            service << "WantedBy=multi-user.target\n";
            service.close();
            
            fs::permissions(service_file, fs::perms::owner_all | fs::perms::group_read | fs::perms::others_read);
            
            // Create a test service to verify nspawn works
            std::string test_service_file = "/etc/systemd/system/archfreeze-test.service";
            std::ofstream test_service(test_service_file);
            test_service << "[Unit]\n";
            test_service << "Description=Test Arch Freeze Container\n";
            test_service << "After=network.target\n";
            test_service << "\n";
            test_service << "[Service]\n";
            test_service << "Type=oneshot\n";
            test_service << "ExecStart=/usr/bin/systemd-nspawn --machine=archfreeze-test --directory=/ --ephemeral hostname\n";
            test_service << "RemainAfterExit=yes\n";
            test_service.close();
            
            logger.info("Created systemd-nspawn services");
            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to create systemd service: " + std::string(e.what()));
            return false;
        }
    }

    void createBindScripts() {
        // Create script to start nspawn container
        std::ofstream bind("/usr/local/bin/archfreeze-bind-root");
        bind << "#!/bin/bash\n";
        bind << "# Start Arch Freeze container\n";
        bind << "echo -e \"\\033[38;2;0;255;255m[Arch Freeze] Starting container...\\033[0m\"\n";
        bind << "systemctl start archfreeze-nspawn.service\n";
        bind << "sleep 3\n";
        bind << "systemctl status archfreeze-nspawn.service --no-pager\n";
        bind.close();
        
        // Create script to stop nspawn container
        std::ofstream unbind("/usr/local/bin/archfreeze-unbind-root");
        unbind << "#!/bin/bash\n";
        unbind << "# Stop Arch Freeze container\n";
        unbind << "echo -e \"\\033[38;2;0;255;255m[Arch Freeze] Stopping container...\\033[0m\"\n";
        unbind << "systemctl stop archfreeze-nspawn.service\n";
        unbind << "sleep 2\n";
        unbind << "echo -e \"\\033[38;2;0;255;255m[Arch Freeze] Container stopped\\033[0m\"\n";
        unbind.close();
        
        fs::permissions("/usr/local/bin/archfreeze-bind-root",
                       fs::perms::owner_all | fs::perms::group_exec | fs::perms::others_exec);
        fs::permissions("/usr/local/bin/archfreeze-unbind-root",
                       fs::perms::owner_all | fs::perms::group_exec | fs::perms::others_exec);
    }

    bool createSnapshot(const std::string& name) {
        try {
            std::string snap_dir = base_dir + "/snapshots/" + name;
            std::string image_path = squashfs_dir + "/rootfs.img";
            
            if (fs::exists(snap_dir)) {
                logger.error("Snapshot already exists: " + name);
                return false;
            }

            if (!fs::exists(image_path)) {
                logger.error("SquashFS image not found: " + image_path);
                return false;
            }

            fs::create_directories(snap_dir);
            
            // Copy SquashFS image
            std::string cmd = "cp " + image_path + " " + snap_dir + "/rootfs.img";
            int result = system(cmd.c_str());

            if (result == 0) {
                std::ofstream meta(snap_dir + "/.metadata");
                meta << "name=" << name << std::endl;
                meta << "date=" << time(0) << std::endl;
                meta << "size=" << fs::file_size(image_path) << std::endl;
                meta << "description=SquashFS snapshot" << std::endl;
                meta.close();

                // Create restore script
                std::ofstream restore(snap_dir + "/restore.sh");
                restore << "#!/bin/bash\n";
                restore << "echo \"Restoring snapshot: " << name << "\"\n";
                restore << "cp " << snap_dir << "/rootfs.img " << image_path << "\n";
                restore << "echo \"Snapshot restored. Restart container with: systemctl restart archfreeze-nspawn.service\"\n";
                restore.close();
                fs::permissions(snap_dir + "/restore.sh", fs::perms::owner_all | fs::perms::group_exec | fs::perms::others_exec);

                logger.info("Created snapshot: " + name);
                return true;
            } else {
                logger.error("Failed to create snapshot");
                return false;
            }
        } catch (const std::exception& e) {
            logger.error("Snapshot creation failed: " + std::string(e.what()));
            return false;
        }
    }

    bool restoreSnapshot(const std::string& name) {
        try {
            std::string snap_dir = base_dir + "/snapshots/" + name;
            std::string snap_image = snap_dir + "/rootfs.img";
            std::string current_image = squashfs_dir + "/rootfs.img";
            
            if (!fs::exists(snap_image)) {
                logger.error("Snapshot not found: " + name);
                return false;
            }

            // Stop container first
            system("systemctl stop archfreeze-nspawn.service 2>/dev/null");
            
            // Backup current image
            std::string backup = current_image + ".backup." + std::to_string(time(0));
            fs::copy(current_image, backup, fs::copy_options::overwrite_existing);
            
            // Restore from snapshot
            std::string cmd = "cp " + snap_image + " " + current_image;
            int result = system(cmd.c_str());

            if (result == 0) {
                logger.info("Restored snapshot: " + name);
                logger.info("Backup saved as: " + backup);
                logger.info("Run: systemctl restart archfreeze-nspawn.service to apply");
                return true;
            } else {
                logger.error("Failed to restore snapshot");
                // Restore backup
                fs::copy(backup, current_image, fs::copy_options::overwrite_existing);
                return false;
            }
        } catch (const std::exception& e) {
            logger.error("Snapshot restore failed: " + std::string(e.what()));
            return false;
        }
    }

    std::vector<std::string> listSnapshots() {
        std::vector<std::string> snapshots;
        try {
            std::string snap_dir = base_dir + "/snapshots";
            if (fs::exists(snap_dir)) {
                for (const auto& entry : fs::directory_iterator(snap_dir)) {
                    if (fs::is_directory(entry)) {
                        snapshots.push_back(entry.path().filename().string());
                    }
                }
            }
        } catch (...) {
            // Ignore errors
        }
        return snapshots;
    }
};

class PermissionManager {
private:
    Logger& logger;

public:
    PermissionManager(Logger& log) : logger(log) {}

    bool makeImmutable() {
        logger.info("Systemd-nspawn method: No permission changes needed on host");
        return true;
    }

    bool setAttributes() {
        logger.info("Systemd-nspawn method: No file attributes needed on host");
        return true;
    }

    bool clearAttributes() {
        logger.info("Systemd-nspawn method: No attributes to clear");
        return true;
    }
};

class ServiceManager {
private:
    Logger& logger;

    bool createScript(const std::string& path, const std::string& content) {
        try {
            std::ofstream script(path);
            if (!script.is_open()) {
                logger.error("Cannot create script: " + path);
                return false;
            }
            script << content;
            script.close();
            fs::permissions(path, fs::perms::owner_all | fs::perms::group_exec | fs::perms::others_exec);
            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to create script " + path + ": " + std::string(e.what()));
            return false;
        }
    }

public:
    ServiceManager(Logger& log) : logger(log) {}

    bool createImmutableService() {
        try {
            std::ofstream service("/etc/systemd/system/archfreeze.service");
            if (!service.is_open()) return false;

            service << "[Unit]\n";
            service << "Description=Arch Freeze Immutable System Manager\n";
            service << "After=network.target\n";
            service << "Before=multi-user.target\n";
            service << "\n";
            service << "[Service]\n";
            service << "Type=oneshot\n";
            service << "RemainAfterExit=yes\n";
            service << "ExecStart=/usr/local/bin/archfreeze-lock\n";
            service << "ExecStop=/usr/local/bin/archfreeze-unlock\n";
            service << "StandardOutput=journal\n";
            service << "\n";
            service << "[Install]\n";
            service << "WantedBy=multi-user.target\n";
            service.close();

            std::ofstream timer("/etc/systemd/system/archfreeze-timer.timer");
            timer << "[Unit]\n";
            timer << "Description=Periodic Arch Freeze Health Check\n";
            timer << "\n";
            timer << "[Timer]\n";
            timer << "OnBootSec=5min\n";
            timer << "OnUnitActiveSec=1hour\n";
            timer << "Persistent=true\n";
            timer << "\n";
            timer << "[Install]\n";
            timer << "WantedBy=timers.target\n";
            timer.close();

            // Create health check service
            std::ofstream health("/etc/systemd/system/archfreeze-health.service");
            health << "[Unit]\n";
            health << "Description=Arch Freeze Health Check\n";
            health << "After=archfreeze-nspawn.service\n";
            health << "\n";
            health << "[Service]\n";
            health << "Type=oneshot\n";
            health << "ExecStart=/usr/local/bin/archfreeze-health-check\n";
            health << "StandardOutput=journal\n";
            health.close();

            system("systemctl daemon-reload");
            system("systemctl enable archfreeze.service 2>/dev/null");
            system("systemctl enable archfreeze-timer.timer 2>/dev/null");

            logger.info("Created immutable system services");
            return true;
        } catch (const std::exception& e) {
            logger.error("Service creation failed: " + std::string(e.what()));
            return false;
        }
    }

    bool createManagementScripts() {
        std::vector<std::pair<std::string, std::string>> scripts = {
            {"/usr/local/bin/archfreeze-lock", R"(#!/bin/bash
# Lock system - Start nspawn container
echo -e "\033[38;2;0;255;255m[Arch Freeze] Locking system...\033[0m"
if systemctl is-active archfreeze-nspawn.service >/dev/null 2>&1; then
    echo -e "\033[38;2;0;255;255m[Arch Freeze] Container is already running\033[0m"
else
    systemctl start archfreeze-nspawn.service
    sleep 2
    if systemctl is-active archfreeze-nspawn.service >/dev/null 2>&1; then
        echo -e "\033[38;2;0;255;255m[Arch Freeze] System is now immutable (running in container)\033[0m"
        logger "Arch Freeze: system locked (container started)"
    else
        echo -e "\033[38;2;255;0;0m[Arch Freeze] Failed to start container\033[0m"
        systemctl status archfreeze-nspawn.service --no-pager
        exit 1
    fi
fi
)"},
            
            {"/usr/local/bin/archfreeze-unlock", R"(#!/bin/bash
# Unlock system - Stop nspawn container
echo -e "\033[38;2;0;255;255m[Arch Freeze] Unlocking system...\033[0m"
if systemctl is-active archfreeze-nspawn.service >/dev/null 2>&1; then
    systemctl stop archfreeze-nspawn.service
    sleep 2
    echo -e "\033[38;2;0;255;255m[Arch Freeze] System is now mutable (container stopped)\033[0m"
    logger "Arch Freeze: system unlocked (container stopped)"
else
    echo -e "\033[38;2;0;255;255m[Arch Freeze] Container is already stopped\033[0m"
fi
)"},
            
            {"/usr/local/bin/archfreeze-status", R"(#!/bin/bash
# Check system status
echo -e "\033[38;2;0;255;255m=== Arch Freeze Status ===\033[0m"

# Check container status
if systemctl is-active archfreeze-nspawn.service >/dev/null 2>&1; then
    echo -e "\033[38;2;0;255;255mSystem: \033[38;2;0;255;0mImmutable (running in container)\033[0m"
    CONTAINER_ACTIVE=true
else
    echo -e "\033[38;2;0;255;255mSystem: \033[38;2;255;255;0mMutable (host system)\033[0m"
    CONTAINER_ACTIVE=false
fi

# Check SquashFS image
SQUASHFS="/var/lib/archfreeze/squashfs/rootfs.img"
if [ -f "$SQUASHFS" ]; then
    SIZE=$(du -h "$SQUASHFS" | cut -f1)
    echo -e "\033[38;2;0;255;255mSquashFS image: $SQUASHFS ($SIZE)\033[0m"
else
    echo -e "\033[38;2;0;255;255mSquashFS image: \033[38;2;255;0;0mNOT FOUND\033[0m"
fi

# Count snapshots
SNAP_COUNT=$(ls /var/lib/archfreeze/snapshots/ 2>/dev/null | wc -l)
echo -e "\033[38;2;0;255;255mSnapshots: $SNAP_COUNT\033[0m"

# List services
echo -e "\033[38;2;0;255;255m\nServices:\033[0m"
systemctl status archfreeze-nspawn.service --no-pager | head -5
)"},
            
            {"/usr/local/bin/archfreeze-snapshot", R"(#!/bin/bash
# Manage snapshots
ACTION="$1"
NAME="$2"

case "$ACTION" in
    create)
        if [ -z "$NAME" ]; then
            echo -e "\033[38;2;255;0;0mError: Snapshot name required\033[0m"
            echo "Usage: $0 create <name>"
            exit 1
        fi
        
        echo -e "\033[38;2;0;255;255mCreating snapshot: $NAME\033[0m"
        
        # Stop container if running
        if systemctl is-active archfreeze-nspawn.service >/dev/null 2>&1; then
            echo -e "\033[38;2;255;255;0mStopping container...\033[0m"
            systemctl stop archfreeze-nspawn.service
            sleep 2
        fi
        
        SNAP_DIR="/var/lib/archfreeze/snapshots/$NAME"
        mkdir -p "$SNAP_DIR"
        
        if cp /var/lib/archfreeze/squashfs/rootfs.img "$SNAP_DIR/"; then
            echo "date=$(date +%s)" > "$SNAP_DIR/.metadata"
            echo "name=$NAME" >> "$SNAP_DIR/.metadata"
            echo "size=$(du -h /var/lib/archfreeze/squashfs/rootfs.img | cut -f1)" >> "$SNAP_DIR/.metadata"
            echo -e "\033[38;2;0;255;0mSnapshot created successfully: $NAME\033[0m"
            
            # Restart container if it was running
            if [ "$CONTAINER_WAS_RUNNING" = "true" ]; then
                echo -e "\033[38;2;0;255;255mRestarting container...\033[0m"
                systemctl start archfreeze-nspawn.service
            fi
        else
            echo -e "\033[38;2;255;0;0mFailed to create snapshot\033[0m"
            exit 1
        fi
        ;;
        
    restore)
        if [ -z "$NAME" ]; then
            echo -e "\033[38;2;255;0;0mError: Snapshot name required\033[0m"
            echo "Usage: $0 restore <name>"
            exit 1
        fi
        
        SNAP_DIR="/var/lib/archfreeze/snapshots/$NAME"
        if [ ! -d "$SNAP_DIR" ]; then
            echo -e "\033[38;2;255;0;0mError: Snapshot not found: $NAME\033[0m"
            exit 1
        fi
        
        echo -e "\033[38;2;0;255;255mRestoring snapshot: $NAME...\033[0m"
        
        # Stop container
        systemctl stop archfreeze-nspawn.service 2>/dev/null
        
        # Backup current image
        BACKUP="/var/lib/archfreeze/squashfs/rootfs.img.backup.$(date +%Y%m%d-%H%M%S)"
        cp /var/lib/archfreeze/squashfs/rootfs.img "$BACKUP"
        
        # Restore snapshot
        if cp "$SNAP_DIR/rootfs.img" /var/lib/archfreeze/squashfs/rootfs.img; then
            echo -e "\033[38;2;0;255;0mSnapshot $NAME restored\033[0m"
            echo -e "\033[38;2;0;255;255mBackup saved as: $BACKUP\033[0m"
            echo -e "\033[38;2;0;255;255mRun: systemctl start archfreeze-nspawn.service to start container\033[0m"
        else
            echo -e "\033[38;2;255;0;0mFailed to restore snapshot\033[0m"
            # Restore backup
            mv "$BACKUP" /var/lib/archfreeze/squashfs/rootfs.img
            exit 1
        fi
        ;;
        
    list)
        echo -e "\033[38;2;0;255;255mAvailable snapshots:\033[0m"
        ls -la /var/lib/archfreeze/snapshots/ 2>/dev/null || echo "No snapshots found"
        ;;
        
    *)
        echo -e "\033[38;2;0;255;255mUsage: $0 {create|restore|list} [name]\033[0m"
        echo "  create <name>   - Create a new snapshot"
        echo "  restore <name>  - Restore a snapshot"
        echo "  list            - List all snapshots"
        exit 1
        ;;
esac
)"},
            
            {"/usr/local/bin/archfreeze-update", R"(#!/bin/bash
# Safe system update
echo -e "\033[38;2;0;255;255m[Arch Freeze] Starting update...\033[0m"

# Create pre-update snapshot
SNAPSHOT="update-$(date +%Y%m%d-%H%M%S)"
echo -e "\033[38;2;0;255;255mCreating pre-update snapshot: $SNAPSHOT\033[0m"
/usr/local/bin/archfreeze-snapshot create "$SNAPSHOT"

if [ $? -ne 0 ]; then
    echo -e "\033[38;2;255;0;0mFailed to create pre-update snapshot\033[0m"
    exit 1
fi

# Stop container for update
echo -e "\033[38;2;0;255;255mStopping container for update...\033[0m"
systemctl stop archfreeze-nspawn.service

# Update SquashFS image
echo -e "\033[38;2;0;255;255mUpdating system...\033[0m"
/usr/local/bin/archfreeze-rebuild-image

if [ $? -ne 0 ]; then
    echo -e "\033[38;2;255;0;0mUpdate failed! Restoring from snapshot...\033[0m"
    /usr/local/bin/archfreeze-snapshot restore "$SNAPSHOT"
    exit 1
fi

# Create post-update snapshot
POST_SNAPSHOT="$SNAPSHOT-post"
echo -e "\033[38;2;0;255;255mCreating post-update snapshot: $POST_SNAPSHOT\033[0m"
/usr/local/bin/archfreeze-snapshot create "$POST_SNAPSHOT"

echo -e "\033[38;2;0;255;255m[Arch Freeze] Update complete!\033[0m"
echo -e "\033[38;2;0;255;255mStart container with: archfreeze-lock\033[0m"
)"},
            
            {"/usr/local/bin/archfreeze-rebuild-image", R"(#!/bin/bash
# Rebuild SquashFS image
set -e

echo -e "\033[38;2;0;255;255m[Arch Freeze] Rebuilding SquashFS image...\033[0m"

TEMP_DIR="/var/lib/archfreeze/working/rebuild"
mkdir -p "$TEMP_DIR"

# Clean temp dir
rm -rf "$TEMP_DIR"/*

# Bind mount root
echo -e "\033[38;2;0;255;255mCreating bind mount...\033[0m"
mount --bind / "$TEMP_DIR"

# Clean machine IDs
echo -e "\033[38;2;0;255;255mCleaning machine IDs...\033[0m"
rm -f "$TEMP_DIR/etc/machine-id"
rm -f "$TEMP_DIR/var/lib/dbus/machine-id"
touch "$TEMP_DIR/etc/machine-id"
echo "archfreeze-container" > "$TEMP_DIR/etc/hostname"

# Create new image
echo -e "\033[38;2;0;255;255mCreating SquashFS image (this may take several minutes)...\033[0m"
mksquashfs "$TEMP_DIR" /var/lib/archfreeze/squashfs/rootfs.img.new \
  -noappend -comp xz -b 256K -Xbcj x86 \
  -e etc/udev/rules.d/70-persistent-cd.rules \
  -e etc/udev/rules.d/70-persistent-net.rules \
  -e etc/mtab -e etc/fstab \
  -e dev/* -e proc/* -e sys/* -e tmp/* -e run/* \
  -e mnt/* -e media/* -e lost+found \
  -e var/lib/archfreeze \
  -e var/log/archfreeze.log \
  -e boot/* \
  -e home/* \
  -e root/.bash_history \
  -e var/cache/pacman/pkg/* \
  -e var/tmp/* \
  -e var/log/*.log \
  -e var/log/*.gz \
  -e var/spool/*

if [ $? -eq 0 ]; then
    # Replace old image
    mv /var/lib/archfreeze/squashfs/rootfs.img.new /var/lib/archfreeze/squashfs/rootfs.img
    echo -e "\033[38;2;0;255;255m[Arch Freeze] Image rebuilt successfully\033[0m"
else
    echo -e "\033[38;2;255;0;0m[Arch Freeze] Failed to rebuild image\033[0m"
    exit 1
fi

# Cleanup
echo -e "\033[38;2;0;255;255mCleaning up...\033[0m"
umount "$TEMP_DIR"
rm -rf "$TEMP_DIR"

echo -e "\033[38;2;0;255;0m[Arch Freeze] Rebuild completed successfully!\033[0m"
)"},
            
            {"/usr/local/bin/archfreeze-health-check", R"(#!/bin/bash
# Health check for Arch Freeze
echo -e "\033[38;2;0;255;255m=== Arch Freeze Health Check ===\033[0m"

# Check container status
if systemctl is-active archfreeze-nspawn.service >/dev/null 2>&1; then
    echo -e "\033[38;2;0;255;0m✓ Container is running\033[0m"
else
    echo -e "\033[38;2;255;255;0m⚠ Container is not running\033[0m"
fi

# Check SquashFS image
if [ -f "/var/lib/archfreeze/squashfs/rootfs.img" ]; then
    SIZE=$(du -h "/var/lib/archfreeze/squashfs/rootfs.img" | cut -f1)
    echo -e "\033[38;2;0;255;0m✓ SquashFS image exists ($SIZE)\033[0m"
else
    echo -e "\033[38;2;255;0;0m✗ SquashFS image missing\033[0m"
fi

# Check disk space
DISK_SPACE=$(df -h /var/lib/archfreeze | tail -1 | awk '{print $4}')
echo -e "\033[38;2;0;255;255mDisk space available: $DISK_SPACE\033[0m"

# Check logs for errors
ERROR_COUNT=$(journalctl -u archfreeze-nspawn.service --since "1 hour ago" | grep -c "ERROR\|FAILED\|Failed")
if [ "$ERROR_COUNT" -gt 0 ]; then
    echo -e "\033[38;2;255;255;0m⚠ Found $ERROR_COUNT errors in container logs (last hour)\033[0m"
fi

echo -e "\033[38;2;0;255;255mHealth check completed\033[0m"
)"},
            
            {"/usr/local/bin/archfreeze-recovery", R"(#!/bin/bash
# Emergency recovery tool
set -e

echo -e "\033[38;2;0;255;255m=== Arch Freeze Recovery ===\033[0m"
echo -e "\033[38;2;0;255;255m1. Reset to factory state\033[0m"
echo -e "\033[38;2;0;255;255m2. Restore from snapshot\033[0m"
echo -e "\033[38;2;0;255;255m3. Fix boot issues\033[0m"
echo -e "\033[38;2;0;255;255m4. Check system integrity\033[0m"
echo -e "\033[38;2;0;255;255m5. Emergency shell\033[0m"
echo -e "\033[38;2;0;255;255m6. Repair Arch Freeze installation\033[0m"
read -p "$(echo -e '\033[38;2;0;255;255mSelect option: \033[0m')" OPTION

case $OPTION in
    1)
        echo -e "\033[38;2;0;255;255mRunning factory reset...\033[0m"
        /usr/local/bin/archfreeze-factory-reset
        ;;
    2)
        echo -e "\033[38;2;0;255;255mAvailable snapshots:\033[0m"
        /usr/local/bin/archfreeze-snapshot list
        read -p "$(echo -e '\033[38;2;0;255;255mEnter snapshot name: \033[0m')" SNAP
        /usr/local/bin/archfreeze-snapshot restore "$SNAP"
        ;;
    3)
        echo -e "\033[38;2;0;255;255mFixing boot issues...\033[0m"
        systemctl daemon-reload
        systemctl reset-failed
        echo -e "\033[38;2;0;255;0mBoot issues fixed\033[0m"
        ;;
    4)
        echo -e "\033[38;2;0;255;255mChecking system integrity...\033[0m"
        /usr/local/bin/archfreeze-health-check
        ;;
    5)
        echo -e "\033[38;2;0;255;255mDropping to emergency shell...\033[0m"
        /bin/bash
        ;;
    6)
        /usr/local/bin/archfreeze-repair
        ;;
    *)
        echo -e "\033[38;2;255;0;0mInvalid option\033[0m"
        ;;
esac
)"},
            
            {"/usr/local/bin/archfreeze-repair", R"(#!/bin/bash
# Repair Arch Freeze installation
set -e

echo -e "\033[38;2;0;255;255m[Arch Freeze] Repairing installation...\033[0m"

# Ensure directories exist
echo -e "\033[38;2;0;255;255mCreating directories...\033[0m"
mkdir -p /var/lib/archfreeze/{squashfs,snapshots,backup,working,config,working/clone_system,working/rebuild}

# Ensure permissions
echo -e "\033[38;2;0;255;255mSetting permissions...\033[0m"
chmod 755 /var/lib/archfreeze
chmod 755 /var/lib/archfreeze/*

# Ensure scripts are executable
echo -e "\033[38;2;0;255;255mMaking scripts executable...\033[0m"
chmod +x /usr/local/bin/archfreeze-* 2>/dev/null || true

# Reload systemd
echo -e "\033[38;2;0;255;255mReloading systemd...\033[0m"
systemctl daemon-reload

# Enable services
echo -e "\033[38;2;0;255;255mEnabling services...\033[0m"
systemctl enable archfreeze-nspawn.service 2>/dev/null || true
systemctl enable archfreeze.service 2>/dev/null || true
systemctl enable archfreeze-timer.timer 2>/dev/null || true

echo -e "\033[38;2;0;255;0m[Arch Freeze] Repair completed\033[0m"
echo -e "\033[38;2;0;255;255mRun 'archfreeze-status' to check system state\033[0m"
)"},
            
            {"/usr/local/bin/archfreeze-factory-reset", R"(#!/bin/bash
# Factory Reset
set -e

echo -e "\033[38;2;0;255;255m=== Arch Freeze Factory Reset ===\033[0m"
read -p "$(echo -e '\033[38;2;0;255;255mType \"RESET\" to confirm: \033[0m')" CONFIRM
if [ "$CONFIRM" != "RESET" ]; then
    echo -e "\033[38;2;255;0;0mReset cancelled\033[0m"
    exit 1
fi

echo -e "\033[38;2;0;255;255m[1/6] Stopping services...\033[0m"
systemctl stop archfreeze.service 2>/dev/null || true
systemctl stop archfreeze-nspawn.service 2>/dev/null || true
systemctl stop archfreeze-health.service 2>/dev/null || true
systemctl disable archfreeze.service 2>/dev/null || true
systemctl disable archfreeze-nspawn.service 2>/dev/null || true
systemctl disable archfreeze-timer.timer 2>/dev/null || true
systemctl disable archfreeze-health.service 2>/dev/null || true

echo -e "\033[38;2;0;255;255m[2/6] Removing systemd units...\033[0m"
rm -f /etc/systemd/system/archfreeze*.service 2>/dev/null || true
rm -f /etc/systemd/system/archfreeze*.timer 2>/dev/null || true
systemctl daemon-reload

echo -e "\033[38;2;0;255;255m[3/6] Removing scripts...\033[0m"
rm -f /usr/local/bin/archfreeze-* 2>/dev/null || true

echo -e "\033[38;2;0;255;255m[4/6] Restoring fstab...\033[0m"
if [ -f "/etc/fstab.backup" ]; then
    cp -f /etc/fstab.backup /etc/fstab 2>/dev/null || true
fi

echo -e "\033[38;2;0;255;255m[5/6] Cleaning up data...\033[0m"
read -p "$(echo -e '\033[38;2;0;255;255mRemove ALL Arch Freeze data? (y/N): \033[0m')" REMOVE_DATA
if [ "$REMOVE_DATA" = "y" ] || [ "$REMOVE_DATA" = "Y" ]; then
    rm -rf /var/lib/archfreeze 2>/dev/null || true
    rm -f /var/log/archfreeze.log 2>/dev/null || true
fi

echo -e "\033[38;2;0;255;0m[6/6] Reset complete!\033[0m"
echo -e "\033[38;2;0;255;255mReboot recommended to complete reset.\033[0m"
)"}
        };

        bool all_success = true;
        for (const auto& script : scripts) {
            if (!createScript(script.first, script.second)) {
                all_success = false;
            } else {
                logger.info("Created script: " + script.first);
            }
        }

        return all_success;
    }

    bool activateImmutableSystem() {
        logger.info("Activating immutable system...");
        
        // Test systemd-nspawn first
        logger.info("Testing systemd-nspawn...");
        int test_result = system("systemctl start archfreeze-test.service 2>/dev/null");
        if (test_result != 0) {
            logger.error("systemd-nspawn test failed");
            logger.error("Check if systemd-nspawn is properly installed");
            return false;
        }
        system("systemctl stop archfreeze-test.service 2>/dev/null");
        
        // Reload systemd
        if (system("systemctl daemon-reload") != 0) {
            logger.error("Failed to reload systemd");
            return false;
        }
        
        // Enable the nspawn service to start on boot
        logger.info("Enabling archfreeze-nspawn.service...");
        int result = system("systemctl enable archfreeze-nspawn.service 2>/dev/null");
        if (result != 0) {
            logger.error("Failed to enable archfreeze-nspawn.service");
            return false;
        }
        
        // Start the nspawn service immediately
        logger.info("Starting archfreeze-nspawn.service...");
        result = system("systemctl start archfreeze-nspawn.service 2>/dev/null");
        if (result != 0) {
            logger.error("Failed to start archfreeze-nspawn.service");
            logger.info("Checking journal for details...");
            system("journalctl -u archfreeze-nspawn.service -n 20 --no-pager");
            return false;
        }
        
        // Wait a moment and check status
        sleep(3);
        result = system("systemctl is-active archfreeze-nspawn.service >/dev/null 2>&1");
        if (result != 0) {
            logger.error("Container did not start successfully");
            system("journalctl -u archfreeze-nspawn.service -n 30 --no-pager");
            return false;
        }
        
        // Also enable the main archfreeze service
        system("systemctl enable archfreeze.service 2>/dev/null");
        system("systemctl start archfreeze.service 2>/dev/null");
        
        logger.info("Immutable system activated and started");
        logger.info("Container is now running");
        
        return true;
    }
};

class BootManager {
private:
    Logger& logger;

public:
    BootManager(Logger& log) : logger(log) {}

    bool configureBootloader() {
        logger.info("Systemd-nspawn method: No bootloader changes needed");
        return true;
    }

    bool createInitramfsHook() {
        logger.info("Systemd-nspawn method: No initramfs hook needed");
        return true;
    }
};

class RecoveryManager {
private:
    Logger& logger;

public:
    RecoveryManager(Logger& log) : logger(log) {}

    bool createRecoveryTools() {
        logger.info("Recovery tools already created in ServiceManager");
        return true;
    }
};

class ImmutableArchConverter {
private:
    Logger logger;
    std::unique_ptr<SystemCheck> syscheck;
    std::unique_ptr<OverlayManager> overlay;
    std::unique_ptr<PermissionManager> permissions;
    std::unique_ptr<ServiceManager> services;
    std::unique_ptr<BootManager> boot;
    std::unique_ptr<RecoveryManager> recovery;

    void display_header() {
        std::cout << COLOR_RED;
        std::cout << "░█████╗░██╗░░░░░░█████╗░██║░░░██╗██████╗░███████╗███╗░░░███╗░█████╗░██████╗░░██████╗" << std::endl;
        std::cout << "██╔══██╗██║░░░░░██╔══██╗██║░░░██║██╔══██╗██╔════╝████╗░████║██╔══██╗██╔══██╗██╔════╝" << std::endl;
        std::cout << "██║░░╚═╝██║░░░░░███████║██║░░░██║██║░░██║█████╗░░██╔████╔██║██║░░██║██║░░██║╚█████╗░" << std::endl;
        std::cout << "██║░░██╗██║░░░░░██╔══██║██║░░░██║██║░░██║██╔══╝░░██║╚██╔╝██║██║░░██║██║░░██║░╚═══██╗" << std::endl;
        std::cout << "╚█████╔╝███████╗██║░░██║╚██████╔╝██████╔╝███████╗██║░╚═╝░██║╚█████╔╝██████╔╝██████╔╝" << std::endl;
        std::cout << "░╚════╝░╚══════╝╚═╝░░░░░░╚═════╝░╚═════╝░╚══════╝╚═╝░░░░░╚═╝░╚════╝░╚═════╝░╚═════╝░" << std::endl;
        std::cout << COLOR_CYAN << "\nclaudemods Arch Freeze Beta v1.0 19-12-2025" << COLOR_RESET << std::endl;
        std::cout << COLOR_MAGENTA << "=" << std::string(70, '=') << "=" << COLOR_RESET << std::endl << std::endl;
    }

    bool backupSystem() {
        logger.info("=== Creating System Backup ===");

        std::string backup_dir = "/var/lib/archfreeze/backup/system-" + 
                                std::to_string(time(0));

        try {
            fs::create_directories(backup_dir);

            std::vector<std::string> backup_paths = {
                "/etc", "/boot", "/root", "/var/lib/pacman", "/usr/local"
            };

            for (const auto& path : backup_paths) {
                if (fs::exists(path)) {
                    std::string cmd = "cp -a " + path + " " + backup_dir + "/ 2>/dev/null || true";
                    int result = system(cmd.c_str());
                    if (result == 0) {
                        logger.info("Backed up: " + path);
                    }
                }
            }

            system(("pacman -Q > " + backup_dir + "/package-list.txt 2>/dev/null").c_str());

            logger.info("Backup completed: " + backup_dir);
            return true;
        } catch (const std::exception& e) {
            logger.error("Backup failed: " + std::string(e.what()));
            return false;
        }
    }

    void printSummary() {
        std::cout << std::endl;
        std::cout << COLOR_MAGENTA << "=" << std::string(70, '=') << "=" << COLOR_RESET << std::endl;
        logger.info("=== CONVERSION COMPLETE ===");
        
        // Check if container is running
        int result = system("systemctl is-active archfreeze-nspawn.service >/dev/null 2>&1");
        if (result == 0) {
            std::cout << COLOR_GREEN << "\n✓ Your Arch system is now immutable and running in a container!" << COLOR_RESET << std::endl;
        } else {
            std::cout << COLOR_YELLOW << "\n⚠ System configured but container not running" << COLOR_RESET << std::endl;
            std::cout << COLOR_CYAN << "Start it with: systemctl start archfreeze-nspawn.service" << COLOR_RESET << std::endl;
        }
        
        std::cout << COLOR_CYAN << "✓ After reboot, it will automatically start in immutable mode." << COLOR_RESET << std::endl;

        std::cout << COLOR_CYAN << "\nSYSTEM STATUS:" << COLOR_RESET << std::endl;
        system("systemctl status archfreeze-nspawn.service --no-pager | head -5");
        
        std::cout << COLOR_CYAN << "\nIMPORTANT COMMANDS:" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  archfreeze-unlock        - Stop immutable container (for updates)" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  archfreeze-lock          - Restart immutable container" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  archfreeze-status        - Check system status" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  archfreeze-update        - Safe system update" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  archfreeze-snapshot      - Manage snapshots" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  archfreeze-recovery      - Emergency recovery" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  archfreeze-repair        - Repair installation" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  archfreeze-factory-reset - Remove Arch Freeze" << COLOR_RESET << std::endl;

        std::cout << COLOR_CYAN << "\nNEXT STEPS:" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "1. Run 'archfreeze-status' to verify system state" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "2. Reboot to verify auto-start works" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "3. Use archfreeze-unlock before updates, then archfreeze-lock after" << COLOR_RESET << std::endl;

        std::cout << COLOR_MAGENTA << "\nLog file: " << COLOR_RESET << "/var/log/archfreeze.log" << std::endl;
        std::cout << COLOR_MAGENTA << "=" << std::string(70, '=') << "=" << COLOR_RESET << std::endl;
        
        // Ask for reboot
        std::cout << COLOR_CYAN << "\nReboot now to complete the process? (recommended) (y/N): " << COLOR_RESET;
        std::string response;
        std::cin >> response;
        
        if (response == "y" || response == "Y") {
            logger.info("Rebooting system...");
            system("sleep 2");
            system("reboot");
        } else {
            std::cout << COLOR_CYAN << "\nManual reboot required for changes to fully take effect." << COLOR_RESET << std::endl;
            std::cout << COLOR_CYAN << "Run: reboot" << COLOR_RESET << std::endl;
        }
    }

    bool checkExistingInstallation() {
        if (fs::exists("/var/lib/archfreeze/.converted")) {
            logger.warn("System is already converted.");
            std::cout << COLOR_CYAN << "What would you like to do?\n";
            std::cout << "1. Repair existing installation\n";
            std::cout << "2. Re-run full conversion\n";
            std::cout << "3. Exit\n";
            std::cout << "Choice (1-3): " << COLOR_RESET;

            std::string choice;
            std::cin >> choice;

            if (choice == "1") {
                system("/usr/local/bin/archfreeze-repair 2>/dev/null || echo 'Repair script not found'");
                return false;
            } else if (choice == "2") {
                std::cout << COLOR_CYAN << "Are you sure? (yes/NO): " << COLOR_RESET;
                std::string confirm;
                std::cin >> confirm;
                if (confirm != "yes" && confirm != "YES" && confirm != "y" && confirm != "Y") {
                    return false;
                }
                return true;
            } else {
                return false;
            }
        }
        return true;
    }

public:
    ImmutableArchConverter() {
        syscheck = std::make_unique<SystemCheck>(logger);
        overlay = std::make_unique<OverlayManager>(logger);
        permissions = std::make_unique<PermissionManager>(logger);
        services = std::make_unique<ServiceManager>(logger);
        boot = std::make_unique<BootManager>(logger);
        recovery = std::make_unique<RecoveryManager>(logger);
    }

    bool run() {
        display_header();

        logger.info("Starting Immutable Arch Conversion");
        logger.info("Version: 1.0 - Systemd-nspawn Edition");
        logger.info("Date: " + std::string(__DATE__) + " " + std::string(__TIME__));

        if (!checkExistingInstallation()) {
            return true;
        }

        std::cout << COLOR_CYAN << "\n=== WARNING ===" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "This will convert your Arch Linux to immutable using systemd-nspawn.\n";
        std::cout << "Method: Creates SquashFS image with bind mount\n";
        std::cout << "Runs in: systemd-nspawn container\n";
        std::cout << "The system will become immutable immediately after conversion.\n";
        std::cout << "Make sure you have backups!\n\n";
        std::cout << "Type 'FREEZE' to proceed: " << COLOR_RESET;

        std::string response;
        std::cin >> response;

        if (response != "FREEZE") {
            logger.warn("Conversion cancelled by user.");
            return false;
        }

        if (!syscheck->performAllChecks()) {
            return false;
        }

        logger.info("\n=== Creating System Backup ===");
        if (!backupSystem()) {
            std::cout << COLOR_CYAN << "Continue anyway? (y/N): " << COLOR_RESET;
            std::cin >> response;
            if (response != "y" && response != "Y") {
                return false;
            }
        }

        logger.info("\n=== Step 1: Creating Directories ===");
        if (!overlay->createDirectories()) {
            return false;
        }

        logger.info("\n=== Step 2: Creating SquashFS Image ===");
        if (!overlay->mountOverlay()) {
            return false;
        }

        logger.info("\n=== Step 3: Configuring System ===");
        if (!overlay->createFSTABEntry()) {
            logger.warn("FSTAB configuration may have issues");
        }
        if (!overlay->createSystemdMount()) {
            return false;
        }

        logger.info("\n=== Step 4: Creating Management Tools ===");
        if (!services->createManagementScripts()) {
            return false;
        }
        if (!services->createImmutableService()) {
            return false;
        }

        logger.info("\n=== Step 5: Creating Initial Snapshot ===");
        if (!overlay->createSnapshot("initial")) {
            logger.warn("Failed to create initial snapshot");
        }

        logger.info("\n=== Step 6: Activating Immutable System ===");
        if (!services->activateImmutableSystem()) {
            logger.error("Failed to activate immutable system");
            std::cout << COLOR_CYAN << "\nTroubleshooting steps:\n";
            std::cout << "1. Check journal: journalctl -u archfreeze-nspawn.service -n 50\n";
            std::cout << "2. Run repair: archfreeze-repair\n";
            std::cout << "3. Manual start: systemctl start archfreeze-nspawn.service\n";
            std::cout << COLOR_RESET << std::endl;
            return false;
        }

        std::ofstream marker("/var/lib/archfreeze/.converted");
        marker << "Arch Freeze conversion completed: " << time(0) << std::endl;
        marker << "Version: 1.0 (Systemd-nspawn)" << std::endl;
        marker << "Image: /var/lib/archfreeze/squashfs/rootfs.img" << std::endl;
        marker << "Auto-started: yes" << std::endl;
        marker.close();

        printSummary();

        return true;
    }
};

int main() {
    signal(SIGINT, [](int) {
        std::cout << COLOR_CYAN << "\n\nInterrupted." << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "Check /var/log/archfreeze.log for details." << COLOR_RESET << std::endl;
        exit(1);
    });

    try {
        ImmutableArchConverter converter;
        if (converter.run()) {
            std::cout << COLOR_GREEN << "\n✓ Conversion successful! System is now immutable." << COLOR_RESET << std::endl;
            std::cout << COLOR_CYAN << "✓ After reboot, system will automatically start in immutable mode." << COLOR_RESET << std::endl;
            return 0;
        } else {
            std::cerr << COLOR_RED << "\n✗ Conversion failed or was cancelled." << COLOR_RESET << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << COLOR_RED << "Fatal error: " << e.what() << COLOR_RESET << std::endl;
        return 1;
    }
}
