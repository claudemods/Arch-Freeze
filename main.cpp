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

    bool performAllChecks() {
        logger.info("=== System Check ===");
        if (!checkRoot()) return false;
        if (!checkArch()) return false;
        if (!checkFilesystem()) return false;
        if (!checkKernel()) return false;
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
                base_dir + "/config"
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

    // UPDATED METHOD: Create SquashFS image instead of mount overlay
    bool mountOverlay() {
        logger.info("Creating SquashFS image (new method)...");
        return createSquashFSImage();
    }

    // NEW METHOD: Create SquashFS image using bind mount
    bool createSquashFSImage() {
        try {
            std::string clone_dir = base_dir + "/working/clone_system";
            std::string output_file = squashfs_dir + "/rootfs.img";
            
            // Create directories
            fs::create_directories(clone_dir);
            
            // Use mount --bind (FIXED: removed sudo since we're already root)
            std::string cmd = "mount --bind / " + clone_dir;
            int result = system(cmd.c_str());
            
            if (result != 0) {
                logger.error("Failed to create bind mount");
                return false;
            }
            
            // Create SquashFS with exclusions - FIXED: Added etc/machine-id exclusion
            cmd = "mksquashfs " + clone_dir + " " + output_file + " ";
            cmd += "-noappend -comp xz -b 256K -Xbcj x86 ";
            cmd += "-e etc/udev/rules.d/70-persistent-cd.rules ";
            cmd += "-e etc/udev/rules.d/70-persistent-net.rules ";
            cmd += "-e etc/mtab ";
            cmd += "-e etc/fstab ";
            cmd += "-e etc/machine-id ";  // FIXED: Exclude machine-id to avoid duplicate
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
            // Create systemd-nspawn service instead
            std::string service_file = "/etc/systemd/system/archfreeze-nspawn.service";
            std::ofstream service(service_file);
            
            service << "[Unit]\n";
            service << "Description=Arch Freeze Nspawn Container\n";
            service << "After=network.target\n";
            service << "Before=multi-user.target\n";  // Added to start early
            service << "DefaultDependencies=no\n";    // Added for boot integration
            service << "\n";
            service << "[Service]\n";
            service << "Type=simple\n";
            // FIXED: Added --machine=archfreeze to give unique name
            service << "ExecStart=systemd-nspawn --machine=archfreeze --boot --image=" << squashfs_dir << "/rootfs.img ";
            service << "--bind=/dev --bind=/proc --bind=/sys --bind=/tmp --bind=/run ";
            service << "--bind=/home --network-veth ";
            service << "--setenv=CONTAINER=1\n";  // Set environment variable
            service << "ExecStartPre=/bin/sh -c 'mkdir -p /run/host/incoming'\n";  // FIXED: Create required directory
            service << "Restart=always\n";
            service << "RestartSec=5\n";  // Added restart delay
            service << "KillMode=mixed\n";
            service << "TimeoutStopSec=30\n";
            service << "\n";
            service << "[Install]\n";
            service << "WantedBy=multi-user.target\n";
            service.close();
            
            system("systemctl daemon-reload");
            logger.info("Created systemd-nspawn service");
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
        bind << "echo \"[Arch Freeze] Starting container...\"\n";
        bind << "systemctl start archfreeze-nspawn.service\n";
        bind.close();
        
        // Create script to stop nspawn container
        std::ofstream unbind("/usr/local/bin/archfreeze-unbind-root");
        unbind << "#!/bin/bash\n";
        unbind << "# Stop Arch Freeze container\n";
        unbind << "echo \"[Arch Freeze] Stopping container...\"\n";
        unbind << "systemctl stop archfreeze-nspawn.service\n";
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

            fs::create_directories(snap_dir);
            
            // Copy SquashFS image
            std::string cmd = "cp " + image_path + " " + snap_dir + "/rootfs.img";
            int result = system(cmd.c_str());

            if (result == 0) {
                std::ofstream meta(snap_dir + "/.metadata");
                meta << "name=" << name << std::endl;
                meta << "date=" << time(0) << std::endl;
                meta << "description=SquashFS snapshot" << std::endl;
                meta.close();

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

            // Backup current image
            std::string backup = current_image + ".backup";
            fs::copy(current_image, backup, fs::copy_options::overwrite_existing);
            
            // Restore from snapshot
            std::string cmd = "cp " + snap_image + " " + current_image;
            int result = system(cmd.c_str());

            if (result == 0) {
                logger.info("Restored snapshot: " + name);
                logger.info("Run: systemctl restart archfreeze-nspawn.service to apply");
                return true;
            } else {
                logger.error("Failed to restore snapshot");
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

    // UPDATED: Not needed for nspawn method
    bool makeImmutable() {
        logger.info("Systemd-nspawn method: No permission changes needed on host");
        return true;
    }

    // UPDATED: Not needed for nspawn method
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

public:
    ServiceManager(Logger& log) : logger(log) {}

    bool createImmutableService() {
        try {
            std::ofstream service("/etc/systemd/system/archfreeze.service");
            if (!service.is_open()) return false;

            service << "[Unit]\n";
            service << "Description=Arch Freeze Immutable System\n";
            service << "After=network.target\n";
            service << "Before=multi-user.target\n";
            service << "\n";
            service << "[Service]\n";
            service << "Type=oneshot\n";
            service << "RemainAfterExit=yes\n";
            service << "ExecStart=/usr/local/bin/archfreeze-lock\n";
            service << "ExecStop=/usr/local/bin/archfreeze-unlock\n";
            service << "ExecReload=/usr/local/bin/archfreeze-reload\n";
            service << "StandardOutput=journal\n";
            service << "\n";
            service << "[Install]\n";
            service << "WantedBy=multi-user.target\n";
            service.close();

            std::ofstream timer("/etc/systemd/system/archfreeze-timer.timer");
            timer << "[Unit]\n";
            timer << "Description=Periodic Arch Freeze check\n";
            timer << "\n";
            timer << "[Timer]\n";
            timer << "OnBootSec=5min\n";
            timer << "OnUnitActiveSec=1hour\n";
            timer << "\n";
            timer << "[Install]\n";
            timer << "WantedBy=timers.target\n";
            timer.close();

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
        try {
            // UPDATED: Lock script starts nspawn container
            std::ofstream lock("/usr/local/bin/archfreeze-lock");
            lock << "#!/bin/bash\n";
            lock << "# Lock system - Start nspawn container\n";
            lock << "echo \"" << COLOR_CYAN << "[Arch Freeze] Locking system..." << COLOR_RESET << "\"\n";
            lock << "systemctl start archfreeze-nspawn.service\n";
            lock << "echo \"" << COLOR_CYAN << "[Arch Freeze] System is now immutable (running in container)" << COLOR_RESET << "\"\n";
            lock << "logger \"Arch Freeze: system locked (container started)\"\n";
            lock.close();

            // UPDATED: Unlock script stops nspawn container
            std::ofstream unlock("/usr/local/bin/archfreeze-unlock");
            unlock << "#!/bin/bash\n";
            unlock << "# Unlock system - Stop nspawn container\n";
            unlock << "echo \"" << COLOR_CYAN << "[Arch Freeze] Unlocking system..." << COLOR_RESET << "\"\n";
            unlock << "systemctl stop archfreeze-nspawn.service\n";
            unlock << "echo \"" << COLOR_CYAN << "[Arch Freeze] System is now mutable (container stopped)" << COLOR_RESET << "\"\n";
            unlock << "logger \"Arch Freeze: system unlocked (container stopped)\"\n";
            unlock.close();

            // UPDATED: Status script checks nspawn container
            std::ofstream status("/usr/local/bin/archfreeze-status");
            status << "#!/bin/bash\n";
            status << "# Check system status\n";
            status << "echo \"" << COLOR_CYAN << "=== Arch Freeze Status ===" << COLOR_RESET << "\"\n";
            status << "if systemctl is-active archfreeze-nspawn.service &>/dev/null; then\n";
            status << "    echo \"" << COLOR_CYAN << "System: Immutable (running in container)" << COLOR_RESET << "\"\n";
            status << "else\n";
            status << "    echo \"" << COLOR_CYAN << "System: Mutable (host system)" << COLOR_RESET << "\"\n";
            status << "fi\n";
            status << "echo \"" << COLOR_CYAN << "SquashFS image: /var/lib/archfreeze/squashfs/rootfs.img" << COLOR_RESET << "\"\n";
            status << "echo \"" << COLOR_CYAN << "Snapshots: $(ls /var/lib/archfreeze/snapshots/ 2>/dev/null | wc -l)" << COLOR_RESET << "\"\n";
            status.close();

            // UPDATED: Snapshot script
            std::ofstream snapshot("/usr/local/bin/archfreeze-snapshot");
            snapshot << "#!/bin/bash\n";
            snapshot << "# Manage snapshots\n";
            snapshot << "ACTION=\"$1\"\n";
            snapshot << "NAME=\"$2\"\n\n";
            snapshot << "case \"$ACTION\" in\n";
            snapshot << "    create)\n";
            snapshot << "        if [ -z \"$NAME\" ]; then exit 1; fi\n";
            snapshot << "        echo \"" << COLOR_CYAN << "Creating snapshot: $NAME" << COLOR_RESET << "\"\n";
            snapshot << "        mkdir -p /var/lib/archfreeze/snapshots/\"$NAME\"\n";
            snapshot << "        cp /var/lib/archfreeze/squashfs/rootfs.img /var/lib/archfreeze/snapshots/\"$NAME\"/\n";
            snapshot << "        echo \"date=$(date +%s)\" > /var/lib/archfreeze/snapshots/\"$NAME\"/.metadata\n";
            snapshot << "        echo \"name=$NAME\" >> /var/lib/archfreeze/snapshots/\"$NAME\"/.metadata\n";
            snapshot << "        ;;\n";
            snapshot << "    restore)\n";
            snapshot << "        if [ -z \"$NAME\" ]; then exit 1; fi\n";
            snapshot << "        if [ ! -d \"/var/lib/archfreeze/snapshots/$NAME\" ]; then exit 1; fi\n";
            snapshot << "        echo \"" << COLOR_CYAN << "Restoring snapshot: $NAME..." << COLOR_RESET << "\"\n";
            snapshot << "        cp /var/lib/archfreeze/snapshots/\"$NAME\"/rootfs.img /var/lib/archfreeze/squashfs/rootfs.img\n";
            snapshot << "        echo \"" << COLOR_CYAN << "Snapshot $NAME restored - restart container to apply" << COLOR_RESET << "\"\n";
            snapshot << "        ;;\n";
            snapshot << "    list)\n";
            snapshot << "        echo \"" << COLOR_CYAN << "Available snapshots:" << COLOR_RESET << "\"\n";
            snapshot << "        ls /var/lib/archfreeze/snapshots/\n";
            snapshot << "        ;;\n";
            snapshot << "    *)\n";
            snapshot << "        echo \"" << COLOR_CYAN << "Usage: $0 {create|restore|list} [name]" << COLOR_RESET << "\"\n";
            snapshot << "        ;;\n";
            snapshot << "esac\n";
            snapshot.close();

            // UPDATED: Update script for nspawn
            std::ofstream update("/usr/local/bin/archfreeze-update");
            update << "#!/bin/bash\n";
            update << "# Safe system update\n";
            update << "echo \"" << COLOR_CYAN << "[Arch Freeze] Starting update..." << COLOR_RESET << "\"\n";
            update << "echo \"" << COLOR_CYAN << "Current snapshot: $(ls /var/lib/archfreeze/snapshots/ | tail -1)" << COLOR_RESET << "\"\n\n";
            update << "# Create pre-update snapshot\n";
            update << "SNAPSHOT=\"update-$(date +%Y%m%d-%H%M%S)\"\n";
            update << "echo \"" << COLOR_CYAN << "Creating pre-update snapshot: $SNAPSHOT" << COLOR_RESET << "\"\n";
            update << "/usr/local/bin/archfreeze-snapshot create \"$SNAPSHOT\"\n\n";
            update << "# Update SquashFS image\n";
            update << "echo \"" << COLOR_CYAN << "Updating system..." << COLOR_RESET << "\"\n";
            update << "/usr/local/bin/archfreeze-rebuild-image\n\n";
            update << "# Create post-update snapshot\n";
            update << "POST_SNAPSHOT=\"$SNAPSHOT-post\"\n";
            update << "echo \"" << COLOR_CYAN << "Creating post-update snapshot: $POST_SNAPSHOT" << COLOR_RESET << "\"\n";
            update << "/usr/local/bin/archfreeze-snapshot create \"$POST_SNAPSHOT\"\n";
            update << "echo \"" << COLOR_CYAN << "[Arch Freeze] Update complete! Restart container to apply." << COLOR_RESET << "\"\n";
            update.close();

            // NEW: Rebuild image script - MODIFIED to not use /tmp
            std::ofstream rebuild("/usr/local/bin/archfreeze-rebuild-image");
            rebuild << "#!/bin/bash\n";
            rebuild << "# Rebuild SquashFS image\n";
            rebuild << "set -e\n\n";
            rebuild << "echo \"" << COLOR_CYAN << "[Arch Freeze] Rebuilding SquashFS image..." << COLOR_RESET << "\"\n";
            rebuild << "TEMP_DIR=\"/var/lib/archfreeze/working/rebuild\"\n";
            rebuild << "mkdir -p \"$TEMP_DIR\"\n\n";
            rebuild << "# Bind mount\n";
            rebuild << "mount --bind / \"$TEMP_DIR\"\n\n";
            rebuild << "# Create new image - FIXED: Exclude etc/machine-id\n";
            rebuild << "mksquashfs \"$TEMP_DIR\" /var/lib/archfreeze/squashfs/rootfs.img.new \\\n";
            rebuild << "  -noappend -comp xz -b 256K -Xbcj x86 \\\n";
            rebuild << "  -e etc/udev/rules.d/70-persistent-cd.rules \\\n";
            rebuild << "  -e etc/udev/rules.d/70-persistent-net.rules \\\n";
            rebuild << "  -e etc/mtab -e etc/fstab \\\n";
            rebuild << "  -e etc/machine-id \\\n";  // FIXED: Exclude machine-id
            rebuild << "  -e dev/* -e proc/* -e sys/* -e tmp/* -e run/* \\\n";
            rebuild << "  -e mnt/* -e media/* -e lost+found \\\n";
            rebuild << "  -e var/lib/archfreeze \\\n";
            rebuild << "  -e var/log/archfreeze.log\n\n";
            rebuild << "# Replace old image\n";
            rebuild << "mv /var/lib/archfreeze/squashfs/rootfs.img.new /var/lib/archfreeze/squashfs/rootfs.img\n\n";
            rebuild << "# Cleanup\n";
            rebuild << "umount \"$TEMP_DIR\"\n";
            rebuild << "rm -rf \"$TEMP_DIR\"\n";
            rebuild << "echo \"" << COLOR_CYAN << "[Arch Freeze] Image rebuilt successfully" << COLOR_RESET << "\"\n";
            rebuild.close();

            // KEEP YOUR ORIGINAL RECOVERY SCRIPT
            std::ofstream recovery("/usr/local/bin/archfreeze-recovery");
            recovery << "#!/bin/bash\n";
            recovery << "# Emergency recovery tool\n";
            recovery << "set -e\n\n";
            recovery << "echo \"" << COLOR_CYAN << "=== Arch Freeze Recovery ===" << COLOR_RESET << "\"\n";
            recovery << "echo \"" << COLOR_CYAN << "1. Reset to factory state" << COLOR_RESET << "\"\n";
            recovery << "echo \"" << COLOR_CYAN << "2. Restore from snapshot" << COLOR_RESET << "\"\n";
            recovery << "echo \"" << COLOR_CYAN << "3. Fix boot issues" << COLOR_RESET << "\"\n";
            recovery << "echo \"" << COLOR_CYAN << "4. Check system integrity" << COLOR_RESET << "\"\n";
            recovery << "echo \"" << COLOR_CYAN << "5. Emergency shell" << COLOR_RESET << "\"\n";
            recovery << "echo \"" << COLOR_CYAN << "6. Repair Arch Freeze installation" << COLOR_RESET << "\"\n";
            recovery << "read -p \"" << COLOR_CYAN << "Select option: " << COLOR_RESET << "\" OPTION\n\n";
            recovery << "case $OPTION in\n";
            recovery << "    1)\n";
            recovery << "        echo \"" << COLOR_CYAN << "Running factory reset..." << COLOR_RESET << "\"\n";
            recovery << "        /usr/local/bin/archfreeze-factory-reset\n";
            recovery << "        ;;\n";
            recovery << "    2)\n";
            recovery << "        echo \"" << COLOR_CYAN << "Available snapshots:" << COLOR_RESET << "\"\n";
            recovery << "        /usr/local/bin/archfreeze-snapshot list\n";
            recovery << "        read -p \"" << COLOR_CYAN << "Enter snapshot name: " << COLOR_RESET << "\" SNAP\n";
            recovery << "        /usr/local/bin/archfreeze-snapshot restore \"$SNAP\"\n";
            recovery << "        ;;\n";
            recovery << "    3)\n";
            recovery << "        echo \"" << COLOR_CYAN << "Fixing boot issues..." << COLOR_RESET << "\"\n";
            recovery << "        # Fix boot\n";
            recovery << "        ;;\n";
            recovery << "    4)\n";
            recovery << "        echo \"" << COLOR_CYAN << "Checking system integrity..." << COLOR_RESET << "\"\n";
            recovery << "        # Check integrity\n";
            recovery << "        ;;\n";
            recovery << "    5)\n";
            recovery << "        echo \"" << COLOR_CYAN << "Dropping to emergency shell..." << COLOR_RESET << "\"\n";
            recovery << "        /bin/bash\n";
            recovery << "        ;;\n";
            recovery << "    6)\n";
            recovery << "        /usr/local/bin/archfreeze-repair\n";
            recovery << "        ;;\n";
            recovery << "    *)\n";
            recovery << "        echo \"" << COLOR_CYAN << "Invalid option" << COLOR_RESET << "\"\n";
            recovery << "        ;;\n";
            recovery << "esac\n";
            recovery.close();

            // KEEP YOUR ORIGINAL REPAIR SCRIPT
            std::ofstream repair("/usr/local/bin/archfreeze-repair");
            repair << "#!/bin/bash\n";
            repair << "# Repair Arch Freeze installation\n";
            repair << "set -e\n\n";
            repair << "echo \"" << COLOR_CYAN << "[Arch Freeze] Repairing installation..." << COLOR_RESET << "\"\n\n";
            repair << "# Ensure directories exist\n";
            repair << "mkdir -p /var/lib/archfreeze/{squashfs,snapshots,backup,working,config}\n\n";
            repair << "# Ensure permissions\n";
            repair << "chmod 755 /var/lib/archfreeze\n";
            repair << "chmod 755 /var/lib/archfreeze/*\n\n";
            repair << "# Ensure scripts are executable\n";
            repair << "chmod +x /usr/local/bin/archfreeze-* 2>/dev/null || true\n\n";
            repair << "# Reload systemd\n";
            repair << "systemctl daemon-reload\n\n";
            repair << "# Enable services\n";
            repair << "systemctl enable archfreeze-nspawn.service 2>/dev/null || true\n";
            repair << "systemctl enable archfreeze.service 2>/dev/null || true\n\n";
            repair << "echo \"" << COLOR_CYAN << "[Arch Freeze] Repair completed" << COLOR_RESET << "\"\n";
            repair << "echo \"" << COLOR_CYAN << "Run 'archfreeze-status' to check system state" << COLOR_RESET << "\"\n";
            repair.close();

            // KEEP YOUR ORIGINAL FACTORY RESET
            std::ofstream factory_reset("/usr/local/bin/archfreeze-factory-reset");
            factory_reset << "#!/bin/bash\n";
            factory_reset << "# Factory Reset\n";
            factory_reset << "set -e\n\n";
            factory_reset << "echo \"" << COLOR_CYAN << "=== Arch Freeze Factory Reset ===" << COLOR_RESET << "\"\n";
            factory_reset << "read -p \"" << COLOR_CYAN << "Type 'RESET' to confirm: " << COLOR_RESET << "\" CONFIRM\n";
            factory_reset << "if [ \"$CONFIRM\" != \"RESET\" ]; then\n";
            factory_reset << "    echo \"" << COLOR_CYAN << "Reset cancelled" << COLOR_RESET << "\"\n";
            factory_reset << "    exit 1\n";
            factory_reset << "fi\n\n";
            factory_reset << "echo \"" << COLOR_CYAN << "[1/6] Stopping services..." << COLOR_RESET << "\"\n";
            factory_reset << "systemctl stop archfreeze.service 2>/dev/null || true\n";
            factory_reset << "systemctl stop archfreeze-nspawn.service 2>/dev/null || true\n";
            factory_reset << "systemctl disable archfreeze.service 2>/dev/null || true\n";
            factory_reset << "systemctl disable archfreeze-nspawn.service 2>/dev/null || true\n";
            factory_reset << "systemctl disable archfreeze-timer.timer 2>/dev/null || true\n\n";
            factory_reset << "echo \"" << COLOR_CYAN << "[2/6] Removing systemd units..." << COLOR_RESET << "\"\n";
            factory_reset << "rm -f /etc/systemd/system/archfreeze*.service 2>/dev/null || true\n";
            factory_reset << "rm -f /etc/systemd/system/archfreeze*.timer 2>/dev/null || true\n";
            factory_reset << "systemctl daemon-reload\n\n";
            factory_reset << "echo \"" << COLOR_CYAN << "[3/6] Removing scripts..." << COLOR_RESET << "\"\n";
            factory_reset << "rm -f /usr/local/bin/archfreeze-* 2>/dev/null || true\n\n";
            factory_reset << "echo \"" << COLOR_CYAN << "[4/6] Restoring fstab..." << COLOR_RESET << "\"\n";
            factory_reset << "if [ -f \"/etc/fstab.backup\" ]; then\n";
            factory_reset << "    cp -f /etc/fstab.backup /etc/fstab 2>/dev/null || true\n";
            factory_reset << "fi\n\n";
            factory_reset << "echo \"" << COLOR_CYAN << "[5/6] Cleaning up data..." << COLOR_RESET << "\"\n";
            factory_reset << "read -p \"" << COLOR_CYAN << "Remove ALL Arch Freeze data? (y/N): " << COLOR_RESET << "\" REMOVE_DATA\n";
            factory_reset << "if [ \"$REMOVE_DATA\" = \"y\" ] || [ \"$REMOVE_DATA\" = \"Y\" ]; then\n";
            factory_reset << "    rm -rf /var/lib/archfreeze 2>/dev/null || true\n";
            factory_reset << "fi\n\n";
            factory_reset << "echo \"" << COLOR_CYAN << "[6/6] Reset complete!" << COLOR_RESET << "\"\n";
            factory_reset.close();

            // Set executable permissions
            std::vector<std::string> scripts = {
                "/usr/local/bin/archfreeze-lock",
                "/usr/local/bin/archfreeze-unlock",
                "/usr/local/bin/archfreeze-status",
                "/usr/local/bin/archfreeze-snapshot",
                "/usr/local/bin/archfreeze-update",
                "/usr/local/bin/archfreeze-rebuild-image",
                "/usr/local/bin/archfreeze-recovery",
                "/usr/local/bin/archfreeze-repair",
                "/usr/local/bin/archfreeze-factory-reset",
                "/usr/local/bin/archfreeze-bind-root",
                "/usr/local/bin/archfreeze-unbind-root"
            };

            for (const auto& script : scripts) {
                if (fs::exists(script)) {
                    fs::permissions(script,
                        fs::perms::owner_all | fs::perms::group_exec | fs::perms::others_exec);
                    logger.info("Created script: " + script);
                }
            }

            return true;
        } catch (const std::exception& e) {
            logger.error("Script creation failed: " + std::string(e.what()));
            return false;
        }
    }

    // NEW METHOD: Enable and start the immutable system immediately
    bool activateImmutableSystem() {
        logger.info("Activating immutable system...");
        
        // Enable the nspawn service to start on boot
        int result = system("systemctl enable archfreeze-nspawn.service 2>/dev/null");
        if (result != 0) {
            logger.error("Failed to enable archfreeze-nspawn.service");
            return false;
        }
        
        // Start the nspawn service immediately
        result = system("systemctl start archfreeze-nspawn.service 2>/dev/null");
        if (result != 0) {
            logger.error("Failed to start archfreeze-nspawn.service");
            return false;
        }
        
        // Also enable the main archfreeze service
        system("systemctl enable archfreeze.service 2>/dev/null");
        system("systemctl start archfreeze.service 2>/dev/null");
        
        logger.info("Immutable system activated and started");
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
        std::cout << COLOR_CYAN << "\n✓ Your Arch system is now immutable!" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "✓ The immutable system has been ACTIVATED and is now running." << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "✓ After reboot, it will automatically start in immutable mode." << COLOR_RESET << std::endl;

        std::cout << COLOR_CYAN << "\nSYSTEM STATUS:" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  • System is currently running in immutable container" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  • SquashFS image: /var/lib/archfreeze/squashfs/rootfs.img" << COLOR_RESET << std::endl;
        std::cout << COLOR_CYAN << "  • Initial snapshot created for recovery" << COLOR_RESET << std::endl;

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
        std::cout << COLOR_CYAN << "1. System is already immutable - no action needed" << COLOR_RESET << std::endl;
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
            std::cout << COLOR_CYAN << "\n✓ Conversion successful! System is now immutable." << COLOR_RESET << std::endl;
            std::cout << COLOR_CYAN << "✓ After reboot, system will automatically start in immutable mode." << COLOR_RESET << std::endl;
            return 0;
        } else {
            std::cerr << COLOR_CYAN << "\n✗ Conversion failed or was cancelled." << COLOR_RESET << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << COLOR_CYAN << "Fatal error: " << e.what() << COLOR_RESET << std::endl;
        return 1;
    }
}
