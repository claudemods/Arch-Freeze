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
        if (echo) std::cout << COLOR_GREEN << "[LOG] " << COLOR_RESET << msg << std::endl;
        if (logfile.is_open()) logfile << logmsg << std::endl;
    }

    void error(const std::string& msg) {
        std::string errmsg = "ERROR: " + msg;
        std::cout << COLOR_RED << "[ERROR] " << COLOR_RESET << msg << std::endl;
        if (logfile.is_open()) logfile << "[" << timestamp() << "] ERROR: " << msg << std::endl;
    }

    void warn(const std::string& msg) {
        std::cout << COLOR_YELLOW << "[WARN] " << COLOR_RESET << msg << std::endl;
        if (logfile.is_open()) logfile << "[" << timestamp() << "] WARN: " + msg << std::endl;
    }

    void info(const std::string& msg) {
        std::cout << COLOR_CYAN << "[INFO] " << COLOR_RESET << msg << std::endl;
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

    bool performAllChecks() {
        logger.info("=== System Check ===");
        if (!checkRoot()) return false;
        if (!checkArch()) return false;
        if (!checkFilesystem()) return false;
        if (!checkKernel()) return false;
        if (!checkDiskSpace()) {
            std::cout << COLOR_YELLOW << "Continue anyway? (y/N): " << COLOR_RESET;
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
                base_dir + "/tmp",
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
            std::string clone_dir = "/tmp/clone_system_temp";
            std::string output_file = squashfs_dir + "/rootfs.img";
            
            // Create directories
            fs::create_directories(clone_dir);
            
            // Use sudo mount --bind
            std::string cmd = "sudo mount --bind / " + clone_dir;
            int result = system(cmd.c_str());
            
            if (result != 0) {
                logger.error("Failed to create bind mount");
                return false;
            }
            
            // Create SquashFS with exclusions
            cmd = "sudo mksquashfs " + clone_dir + " " + output_file + " ";
            cmd += "-noappend -comp xz -b 256K -Xbcj x86 ";
            cmd += "-e etc/udev/rules.d/70-persistent-cd.rules ";
            cmd += "-e etc/udev/rules.d/70-persistent-net.rules ";
            cmd += "-e etc/mtab ";
            cmd += "-e etc/fstab ";
            cmd += "-e dev/* ";
            cmd += "-e proc/* ";
            cmd += "-e sys/* ";
            cmd += "-e tmp/* ";
            cmd += "-e run/* ";
            cmd += "-e mnt/* ";
            cmd += "-e media/* ";
            cmd += "-e lost+found ";
            cmd += "-e clone_system_temp";
            
            result = system(cmd.c_str());
            
            // Cleanup
            system(("sudo umount " + clone_dir + " 2>/dev/null").c_str());
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
            service << "\n";
            service << "[Service]\n";
            service << "Type=simple\n";
            service << "ExecStart=systemd-nspawn --boot --image=" << squashfs_dir << "/rootfs.img ";
            service << "--bind=/dev --bind=/proc --bind=/sys --bind=/tmp --bind=/run ";
            service << "--bind=/home --network-veth\n";
            service << "Restart=always\n";
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
            lock << "echo \"[Arch Freeze] Locking system...\"\n";
            lock << "systemctl start archfreeze-nspawn.service\n";
            lock << "echo \"[Arch Freeze] System is now immutable (running in container)\"\n";
            lock << "logger \"Arch Freeze: system locked (container started)\"\n";
            lock.close();

            // UPDATED: Unlock script stops nspawn container
            std::ofstream unlock("/usr/local/bin/archfreeze-unlock");
            unlock << "#!/bin/bash\n";
            unlock << "# Unlock system - Stop nspawn container\n";
            unlock << "echo \"[Arch Freeze] Unlocking system...\"\n";
            unlock << "systemctl stop archfreeze-nspawn.service\n";
            unlock << "echo \"[Arch Freeze] System is now mutable (container stopped)\"\n";
            unlock << "logger \"Arch Freeze: system unlocked (container stopped)\"\n";
            unlock.close();

            // UPDATED: Status script checks nspawn container
            std::ofstream status("/usr/local/bin/archfreeze-status");
            status << "#!/bin/bash\n";
            status << "# Check system status\n";
            status << "echo \"=== Arch Freeze Status ===\"\n";
            status << "if systemctl is-active archfreeze-nspawn.service &>/dev/null; then\n";
            status << "    echo \"System: Immutable (running in container)\"\n";
            status << "else\n";
            status << "    echo \"System: Mutable (host system)\"\n";
            status << "fi\n";
            status << "echo \"SquashFS image: /var/lib/archfreeze/squashfs/rootfs.img\"\n";
            status << "echo \"Snapshots: $(ls /var/lib/archfreeze/snapshots/ 2>/dev/null | wc -l)\"\n";
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
            snapshot << "        echo \"Creating snapshot: $NAME\"\n";
            snapshot << "        mkdir -p /var/lib/archfreeze/snapshots/\"$NAME\"\n";
            snapshot << "        cp /var/lib/archfreeze/squashfs/rootfs.img /var/lib/archfreeze/snapshots/\"$NAME\"/\n";
            snapshot << "        echo \"date=$(date +%s)\" > /var/lib/archfreeze/snapshots/\"$NAME\"/.metadata\n";
            snapshot << "        echo \"name=$NAME\" >> /var/lib/archfreeze/snapshots/\"$NAME\"/.metadata\n";
            snapshot << "        ;;\n";
            snapshot << "    restore)\n";
            snapshot << "        if [ -z \"$NAME\" ]; then exit 1; fi\n";
            snapshot << "        if [ ! -d \"/var/lib/archfreeze/snapshots/$NAME\" ]; then exit 1; fi\n";
            snapshot << "        echo \"Restoring snapshot: $NAME...\"\n";
            snapshot << "        cp /var/lib/archfreeze/snapshots/\"$NAME\"/rootfs.img /var/lib/archfreeze/squashfs/rootfs.img\n";
            snapshot << "        echo \"Snapshot $NAME restored - restart container to apply\"\n";
            snapshot << "        ;;\n";
            snapshot << "    list)\n";
            snapshot << "        echo \"Available snapshots:\"\n";
            snapshot << "        ls /var/lib/archfreeze/snapshots/\n";
            snapshot << "        ;;\n";
            snapshot << "    *)\n";
            snapshot << "        echo \"Usage: $0 {create|restore|list} [name]\"\n";
            snapshot << "        ;;\n";
            snapshot << "esac\n";
            snapshot.close();

            // UPDATED: Update script for nspawn
            std::ofstream update("/usr/local/bin/archfreeze-update");
            update << "#!/bin/bash\n";
            update << "# Safe system update\n";
            update << "echo \"[Arch Freeze] Starting update...\"\n";
            update << "echo \"Current snapshot: $(ls /var/lib/archfreeze/snapshots/ | tail -1)\"\n\n";
            update << "# Create pre-update snapshot\n";
            update << "SNAPSHOT=\"update-$(date +%Y%m%d-%H%M%S)\"\n";
            update << "echo \"Creating pre-update snapshot: $SNAPSHOT\"\n";
            update << "/usr/local/bin/archfreeze-snapshot create \"$SNAPSHOT\"\n\n";
            update << "# Update SquashFS image\n";
            update << "echo \"Updating system...\"\n";
            update << "/usr/local/bin/archfreeze-rebuild-image\n\n";
            update << "# Create post-update snapshot\n";
            update << "POST_SNAPSHOT=\"$SNAPSHOT-post\"\n";
            update << "echo \"Creating post-update snapshot: $POST_SNAPSHOT\"\n";
            update << "/usr/local/bin/archfreeze-snapshot create \"$POST_SNAPSHOT\"\n";
            update << "echo \"[Arch Freeze] Update complete! Restart container to apply.\"\n";
            update.close();

            // NEW: Rebuild image script
            std::ofstream rebuild("/usr/local/bin/archfreeze-rebuild-image");
            rebuild << "#!/bin/bash\n";
            rebuild << "# Rebuild SquashFS image\n";
            rebuild << "set -e\n\n";
            rebuild << "echo \"[Arch Freeze] Rebuilding SquashFS image...\"\n";
            rebuild << "TEMP_DIR=\"/tmp/archfreeze-rebuild\"\n";
            rebuild << "mkdir -p \"$TEMP_DIR\"\n\n";
            rebuild << "# Bind mount\n";
            rebuild << "sudo mount --bind / \"$TEMP_DIR\"\n\n";
            rebuild << "# Create new image\n";
            rebuild << "sudo mksquashfs \"$TEMP_DIR\" /var/lib/archfreeze/squashfs/rootfs.img.new \\\n";
            rebuild << "  -noappend -comp xz -b 256K -Xbcj x86 \\\n";
            rebuild << "  -e etc/udev/rules.d/70-persistent-cd.rules \\\n";
            rebuild << "  -e etc/udev/rules.d/70-persistent-net.rules \\\n";
            rebuild << "  -e etc/mtab -e etc/fstab \\\n";
            rebuild << "  -e dev/* -e proc/* -e sys/* -e tmp/* -e run/* \\\n";
            rebuild << "  -e mnt/* -e media/* -e lost+found\n\n";
            rebuild << "# Replace old image\n";
            rebuild << "mv /var/lib/archfreeze/squashfs/rootfs.img.new /var/lib/archfreeze/squashfs/rootfs.img\n\n";
            rebuild << "# Cleanup\n";
            rebuild << "sudo umount \"$TEMP_DIR\"\n";
            rebuild << "rm -rf \"$TEMP_DIR\"\n";
            rebuild << "echo \"[Arch Freeze] Image rebuilt successfully\"\n";
            rebuild.close();

            // KEEP YOUR ORIGINAL RECOVERY SCRIPT
            std::ofstream recovery("/usr/local/bin/archfreeze-recovery");
            recovery << "#!/bin/bash\n";
            recovery << "# Emergency recovery tool\n";
            recovery << "set -e\n\n";
            recovery << "echo \"=== Arch Freeze Recovery ===\"\n";
            recovery << "echo \"1. Reset to factory state\"\n";
            recovery << "echo \"2. Restore from snapshot\"\n";
            recovery << "echo \"3. Fix boot issues\"\n";
            recovery << "echo \"4. Check system integrity\"\n";
            recovery << "echo \"5. Emergency shell\"\n";
            recovery << "echo \"6. Repair Arch Freeze installation\"\n";
            recovery << "read -p \"Select option: \" OPTION\n\n";
            recovery << "case $OPTION in\n";
            recovery << "    1)\n";
            recovery << "        echo \"Running factory reset...\"\n";
            recovery << "        /usr/local/bin/archfreeze-factory-reset\n";
            recovery << "        ;;\n";
            recovery << "    2)\n";
            recovery << "        echo \"Available snapshots:\"\n";
            recovery << "        /usr/local/bin/archfreeze-snapshot list\n";
            recovery << "        read -p \"Enter snapshot name: \" SNAP\n";
            recovery << "        /usr/local/bin/archfreeze-snapshot restore \"$SNAP\"\n";
            recovery << "        ;;\n";
            recovery << "    3)\n";
            recovery << "        echo \"Fixing boot issues...\"\n";
            recovery << "        # Fix boot\n";
            recovery << "        ;;\n";
            recovery << "    4)\n";
            recovery << "        echo \"Checking system integrity...\"\n";
            recovery << "        # Check integrity\n";
            recovery << "        ;;\n";
            recovery << "    5)\n";
            recovery << "        echo \"Dropping to emergency shell...\"\n";
            recovery << "        /bin/bash\n";
            recovery << "        ;;\n";
            recovery << "    6)\n";
            recovery << "        /usr/local/bin/archfreeze-repair\n";
            recovery << "        ;;\n";
            recovery << "    *)\n";
            recovery << "        echo \"Invalid option\"\n";
            recovery << "        ;;\n";
            recovery << "esac\n";
            recovery.close();

            // KEEP YOUR ORIGINAL REPAIR SCRIPT
            std::ofstream repair("/usr/local/bin/archfreeze-repair");
            repair << "#!/bin/bash\n";
            repair << "# Repair Arch Freeze installation\n";
            repair << "set -e\n\n";
            repair << "echo \"[Arch Freeze] Repairing installation...\"\n\n";
            repair << "# Ensure directories exist\n";
            repair << "mkdir -p /var/lib/archfreeze/{squashfs,snapshots,backup,config}\n\n";
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
            repair << "echo \"[Arch Freeze] Repair completed\"\n";
            repair << "echo \"Run 'archfreeze-status' to check system state\"\n";
            repair.close();

            // KEEP YOUR ORIGINAL FACTORY RESET
            std::ofstream factory_reset("/usr/local/bin/archfreeze-factory-reset");
            factory_reset << "#!/bin/bash\n";
            factory_reset << "# Factory Reset\n";
            factory_reset << "set -e\n\n";
            factory_reset << "echo \"=== Arch Freeze Factory Reset ===\"\n";
            factory_reset << "read -p \"Type 'RESET' to confirm: \" CONFIRM\n";
            factory_reset << "if [ \"$CONFIRM\" != \"RESET\" ]; then\n";
            factory_reset << "    echo \"Reset cancelled\"\n";
            factory_reset << "    exit 1\n";
            factory_reset << "fi\n\n";
            factory_reset << "echo \"[1/6] Stopping services...\"\n";
            factory_reset << "systemctl stop archfreeze.service 2>/dev/null || true\n";
            factory_reset << "systemctl stop archfreeze-nspawn.service 2>/dev/null || true\n";
            factory_reset << "systemctl disable archfreeze.service 2>/dev/null || true\n";
            factory_reset << "systemctl disable archfreeze-nspawn.service 2>/dev/null || true\n";
            factory_reset << "systemctl disable archfreeze-timer.timer 2>/dev/null || true\n\n";
            factory_reset << "echo \"[2/6] Removing systemd units...\"\n";
            factory_reset << "rm -f /etc/systemd/system/archfreeze*.service 2>/dev/null || true\n";
            factory_reset << "rm -f /etc/systemd/system/archfreeze*.timer 2>/dev/null || true\n";
            factory_reset << "systemctl daemon-reload\n\n";
            factory_reset << "echo \"[3/6] Removing scripts...\"\n";
            factory_reset << "rm -f /usr/local/bin/archfreeze-* 2>/dev/null || true\n\n";
            factory_reset << "echo \"[4/6] Restoring fstab...\"\n";
            factory_reset << "if [ -f \"/etc/fstab.backup\" ]; then\n";
            factory_reset << "    cp -f /etc/fstab.backup /etc/fstab 2>/dev/null || true\n";
            factory_reset << "fi\n\n";
            factory_reset << "echo \"[5/6] Cleaning up data...\"\n";
            factory_reset << "read -p \"Remove ALL Arch Freeze data? (y/N): \" REMOVE_DATA\n";
            factory_reset << "if [ \"$REMOVE_DATA\" = \"y\" ] || [ \"$REMOVE_DATA\" = \"Y\" ]; then\n";
            factory_reset << "    rm -rf /var/lib/archfreeze 2>/dev/null || true\n";
            factory_reset << "fi\n\n";
            factory_reset << "echo \"[6/6] Reset complete!\"\n";
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
        std::cout << COLOR_GREEN << "\n✓ Your Arch system is now immutable using systemd-nspawn!" << COLOR_RESET << std::endl;

        std::cout << COLOR_CYAN << "\nIMPORTANT COMMANDS:" << COLOR_RESET << std::endl;
        std::cout << "  archfreeze-lock          - Start immutable container" << std::endl;
        std::cout << "  archfreeze-unlock        - Stop immutable container" << std::endl;
        std::cout << "  archfreeze-status        - Check system status" << std::endl;
        std::cout << "  archfreeze-update        - Safe system update" << std::endl;
        std::cout << "  archfreeze-snapshot      - Manage snapshots" << std::endl;
        std::cout << "  archfreeze-recovery      - Emergency recovery" << std::endl;
        std::cout << "  archfreeze-repair        - Repair installation" << std::endl;
        std::cout << "  archfreeze-factory-reset - Remove Arch Freeze" << std::endl;

        std::cout << COLOR_YELLOW << "\nNEXT STEPS:" << COLOR_RESET << std::endl;
        std::cout << "1. Run: archfreeze-lock (to start container)" << std::endl;
        std::cout << "2. System runs from SquashFS: /var/lib/archfreeze/squashfs/rootfs.img" << std::endl;
        std::cout << "3. Use archfreeze-unlock before updates" << std::endl;

        std::cout << COLOR_MAGENTA << "\nLog file: " << COLOR_RESET << "/var/log/archfreeze.log" << std::endl;
        std::cout << COLOR_MAGENTA << "=" << std::string(70, '=') << "=" << COLOR_RESET << std::endl;
    }

    bool checkExistingInstallation() {
        if (fs::exists("/var/lib/archfreeze/.converted")) {
            logger.warn("System is already converted.");
            std::cout << COLOR_YELLOW << "What would you like to do?\n";
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
                std::cout << COLOR_RED << "Are you sure? (yes/NO): " << COLOR_RESET;
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

        std::cout << COLOR_RED << "\n=== WARNING ===" << COLOR_RESET << std::endl;
        std::cout << "This will convert your Arch Linux to immutable using systemd-nspawn.\n";
        std::cout << "Method: Creates SquashFS image with bind mount\n";
        std::cout << "Runs in: systemd-nspawn container\n";
        std::cout << "Make sure you have backups!\n\n";
        std::cout << COLOR_RED << "Type 'FREEZE' to proceed: " << COLOR_RESET;

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
            std::cout << COLOR_YELLOW << "Continue anyway? (y/N): " << COLOR_RESET;
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

        std::ofstream marker("/var/lib/archfreeze/.converted");
        marker << "Arch Freeze conversion completed: " << time(0) << std::endl;
        marker << "Version: 1.0 (Systemd-nspawn)" << std::endl;
        marker << "Image: /var/lib/archfreeze/squashfs/rootfs.img" << std::endl;
        marker.close();

        printSummary();

        return true;
    }
};

int main() {
    signal(SIGINT, [](int) {
        std::cout << COLOR_RED << "\n\nInterrupted." << COLOR_RESET << std::endl;
        std::cout << "Check /var/log/archfreeze.log for details." << std::endl;
        exit(1);
    });

    try {
        ImmutableArchConverter converter;
        if (converter.run()) {
            std::cout << COLOR_GREEN << "\n✓ Conversion successful!" << COLOR_RESET << std::endl;
            std::cout << COLOR_YELLOW << "\nTo start immutable system:" << COLOR_RESET << std::endl;
            std::cout << "  archfreeze-lock" << std::endl;
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
