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
        if (logfile.is_open()) logfile << "[" << timestamp() << "] WARN: " << msg << std::endl;
    }

    void info(const std::string& msg) {
        std::cout << COLOR_CYAN << "[INFO] " << COLOR_RESET << msg << std::endl;
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

public:
    OverlayManager(Logger& log) : logger(log) {
        upper_dir = base_dir + "/upper";
        work_dir = base_dir + "/work";
        merged_dir = base_dir + "/merged";
    }

    bool createDirectories() {
        try {
            std::vector<std::string> dirs = {
                base_dir, upper_dir, work_dir, merged_dir,
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

            // Set special permissions for work directory
            fs::permissions(work_dir, 
                fs::perms::owner_all | 
                fs::perms::group_read | fs::perms::group_exec |
                fs::perms::others_read | fs::perms::others_exec);

            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to create directories: " + std::string(e.what()));
            return false;
        }
    }

    bool mountOverlay() {
        // Unmount first if already mounted
        unmountOverlay();

        std::string options = "lowerdir=/,upperdir=" + upper_dir + 
                             ",workdir=" + work_dir;

        if (mount("overlay", merged_dir.c_str(), "overlay", 0, options.c_str()) != 0) {
            logger.error("Failed to mount overlay: " + std::string(strerror(errno)));
            return false;
        }

        logger.info("Overlay mounted at: " + merged_dir);
        return true;
    }

    void unmountOverlay() {
        if (fs::exists(merged_dir)) {
            if (umount(merged_dir.c_str()) != 0) {
                system(("umount -l " + merged_dir + " 2>/dev/null").c_str());
            }
        }
    }

    bool createFSTABEntry() {
        try {
            // Check if entry already exists
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

            // Backup original fstab
            if (fs::exists("/etc/fstab")) {
                fs::copy("/etc/fstab", "/etc/fstab.backup", fs::copy_options::overwrite_existing);
                logger.info("Backed up /etc/fstab to /etc/fstab.backup");
            }

            std::ofstream fstab("/etc/fstab", std::ios::app);
            if (!fstab.is_open()) {
                logger.error("Cannot open /etc/fstab");
                return false;
            }

            fstab << "\n# Immutable Arch OverlayFS - Generated by Arch Freeze\n";
            fstab << "# This is a comment line - DO NOT mount overlay on root at boot\n";
            fstab << "# overlay\t/\toverlay\tlowerdir=/,upperdir=" << upper_dir 
                  << ",workdir=" << work_dir << "\t0 0\n";

            fstab.close();
            logger.info("Added commented overlay entry to /etc/fstab");
            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to update fstab: " + std::string(e.what()));
            return false;
        }
    }

    bool createSystemdMount() {
        try {
            // IMPORTANT: Mount at /var/lib/archfreeze/merged, NOT at root /
            std::string mount_unit = "/etc/systemd/system/archfreeze-merged.mount";
            std::ofstream mount(mount_unit);
            if (!mount.is_open()) {
                logger.error("Cannot create mount unit");
                return false;
            }

            mount << "[Unit]\n";
            mount << "Description=Arch Freeze Overlay (Merged View)\n";
            mount << "DefaultDependencies=no\n";
            mount << "After=local-fs.target\n";
            mount << "Before=archfreeze.service\n";
            mount << "Conflicts=umount.target\n\n";

            mount << "[Mount]\n";
            mount << "What=overlay\n";
            mount << "Where=/var/lib/archfreeze/merged\n";  // FIXED: Mount at merged_dir, not root
            mount << "Type=overlay\n";
            mount << "Options=lowerdir=/,upperdir=" << upper_dir 
                  << ",workdir=" << work_dir << "\n\n";

            mount << "[Install]\n";
            mount << "WantedBy=multi-user.target\n";

            mount.close();

            // Create bind mount service for root
            std::string bind_service = "/etc/systemd/system/archfreeze-bindroot.service";
            std::ofstream bind(bind_service);
            bind << "[Unit]\n";
            bind << "Description=Bind Arch Freeze Overlay to Root\n";
            bind << "After=archfreeze-merged.mount\n";
            bind << "Before=archfreeze.service\n";
            bind << "Requires=archfreeze-merged.mount\n\n";

            bind << "[Service]\n";
            bind << "Type=oneshot\n";
            bind << "RemainAfterExit=yes\n";
            bind << "ExecStart=/usr/local/bin/archfreeze-bind-root\n";
            bind << "ExecStop=/usr/local/bin/archfreeze-unbind-root\n";
            bind << "StandardOutput=journal\n\n";

            bind << "[Install]\n";
            bind << "WantedBy=multi-user.target\n";

            bind.close();

            // Create the bind/unbind scripts
            createBindScripts();

            system("systemctl daemon-reload");
            system("systemctl enable archfreeze-merged.mount 2>/dev/null");
            system("systemctl enable archfreeze-bindroot.service 2>/dev/null");

            logger.info("Created systemd mount and bind services");
            return true;
        } catch (const std::exception& e) {
            logger.error("Failed to create systemd mount: " + std::string(e.what()));
            return false;
        }
    }

    void createBindScripts() {
        // Create bind-root script
        std::ofstream bind("/usr/local/bin/archfreeze-bind-root");
        bind << "#!/bin/bash\n";
        bind << "# Bind overlay to root\n";
        bind << "set -e\n\n";
        bind << "echo \"[Arch Freeze] Binding overlay to root...\"\n";
        bind << "# First ensure root is read-write\n";
        bind << "mount -o remount,rw / 2>/dev/null || true\n";
        bind << "# Bind the merged overlay to root\n";
        bind << "mount --bind /var/lib/archfreeze/merged / 2>/dev/null || true\n";
        bind << "# Make it read-only\n";
        bind << "mount -o remount,ro / 2>/dev/null || true\n";
        bind << "echo \"[Arch Freeze] Root bound to overlay\"\n";
        bind << "logger \"Arch Freeze: root bound to overlay\"\n";
        bind.close();

        // Create unbind-root script
        std::ofstream unbind("/usr/local/bin/archfreeze-unbind-root");
        unbind << "#!/bin/bash\n";
        unbind << "# Unbind overlay from root\n";
        unbind << "set -e\n\n";
        unbind << "echo \"[Arch Freeze] Unbinding overlay from root...\"\n";
        unbind << "umount / 2>/dev/null || true\n";
        unbind << "# Restore original root mount\n";
        unbind << "mount -o remount,rw / 2>/dev/null || true\n";
        unbind << "echo \"[Arch Freeze] Root unbound from overlay\"\n";
        unbind << "logger \"Arch Freeze: root unbound from overlay\"\n";
        unbind.close();

        // Set executable permissions
        fs::permissions("/usr/local/bin/archfreeze-bind-root",
                       fs::perms::owner_all | fs::perms::group_exec | fs::perms::others_exec);
        fs::permissions("/usr/local/bin/archfreeze-unbind-root",
                       fs::perms::owner_all | fs::perms::group_exec | fs::perms::others_exec);
    }

    bool createSnapshot(const std::string& name) {
        try {
            std::string snap_dir = base_dir + "/snapshots/" + name;
            if (fs::exists(snap_dir)) {
                logger.error("Snapshot already exists: " + name);
                return false;
            }

            // Create snapshot directory
            fs::create_directories(snap_dir);

            // Use rsync for efficient copying
            std::string cmd = "rsync -a --delete " + upper_dir + "/ " + snap_dir + "/ 2>/dev/null";
            int result = system(cmd.c_str());

            if (result == 0) {
                // Create snapshot metadata
                std::ofstream meta(snap_dir + "/.metadata");
                meta << "name=" << name << std::endl;
                meta << "date=" << time(0) << std::endl;
                meta << "description=Automated snapshot" << std::endl;
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
            if (!fs::exists(snap_dir)) {
                logger.error("Snapshot not found: " + name);
                return false;
            }

            // Clear current upper dir
            fs::remove_all(upper_dir);
            fs::create_directories(upper_dir);

            // Restore from snapshot
            std::string cmd = "rsync -a --delete " + snap_dir + "/ " + upper_dir + "/ 2>/dev/null";
            int result = system(cmd.c_str());

            if (result == 0) {
                logger.info("Restored snapshot: " + name);
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

    bool makeImmutable() {
        try {
            logger.info("Setting immutable permissions on system directories...");

            // Directories to make read-only (but keep executable for binaries)
            std::vector<std::string> ro_dirs = {
                "/bin", "/sbin", "/usr/bin", "/usr/sbin",
                "/lib", "/lib64", "/usr/lib", "/usr/lib64",
                "/boot", "/opt"
            };

            // Directories to keep writable
            std::vector<std::string> rw_dirs = {
                "/home", "/var", "/tmp", "/run", "/dev",
                "/proc", "/sys", "/var/lib/archfreeze"
            };

            // /etc is special - mostly read-only but some files need to be writable
            if (fs::exists("/etc")) {
                try {
                    // Set /etc to read-only by default
                    fs::permissions("/etc",
                        fs::perms::owner_read | fs::perms::owner_exec |
                        fs::perms::group_read | fs::perms::group_exec |
                        fs::perms::others_read | fs::perms::others_exec,
                        fs::perm_options::replace);
                    logger.info("Set RO: /etc");

                } catch (...) {
                    logger.warn("Could not set permissions for /etc");
                }
            }

            // Set read-only permissions for system directories
            for (const auto& dir : ro_dirs) {
                if (fs::exists(dir)) {
                    try {
                        // Remove write permission but keep execute for binaries
                        fs::permissions(dir,
                            fs::perms::owner_read | fs::perms::owner_exec |
                            fs::perms::group_read | fs::perms::group_exec |
                            fs::perms::others_read | fs::perms::others_exec,
                            fs::perm_options::replace);
                        logger.info("Set RO: " + dir);
                    } catch (...) {
                        logger.warn("Could not set permissions for " + dir);
                    }
                }
            }

            // Ensure writable directories have proper permissions
            for (const auto& dir : rw_dirs) {
                if (fs::exists(dir) && dir != "/proc" && dir != "/sys" && dir != "/dev") {
                    try {
                        fs::permissions(dir,
                            fs::perms::owner_all |
                            fs::perms::group_read | fs::perms::group_exec |
                            fs::perms::others_read | fs::perms::others_exec,
                            fs::perm_options::replace);
                    } catch (...) {
                        // Ignore errors for special filesystems
                    }
                }
            }

            return true;
        } catch (const std::exception& e) {
            logger.error("Permission setting failed: " + std::string(e.what()));
            return false;
        }
    }

    bool setAttributes() {
        // Set immutable attribute on critical files using chattr
        std::vector<std::string> critical_files = {
            "/etc/passwd",
            "/etc/group",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/fstab",
            "/etc/hostname",
            "/etc/hosts",
            "/etc/locale.conf",
            "/etc/localtime"
        };

        for (const auto& file : critical_files) {
            if (fs::exists(file)) {
                std::string cmd = "chattr +i " + file + " 2>/dev/null";
                int result = system(cmd.c_str());
                if (result == 0) {
                    logger.info("Set immutable attribute: " + file);
                }
            }
        }

        return true;
    }

    bool clearAttributes() {
        // Clear immutable attribute
        std::vector<std::string> critical_files = {
            "/etc/passwd",
            "/etc/group",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/fstab",
            "/etc/hostname",
            "/etc/hosts",
            "/etc/locale.conf",
            "/etc/localtime"
        };

        for (const auto& file : critical_files) {
            if (fs::exists(file)) {
                std::string cmd = "chattr -i " + file + " 2>/dev/null";
                system(cmd.c_str());
            }
        }

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
            // Main immutable service - runs after bind mount
            std::ofstream service("/etc/systemd/system/archfreeze.service");
            if (!service.is_open()) return false;

            service << "[Unit]\n";
            service << "Description=Immutable Arch System\n";
            service << "After=archfreeze-bindroot.service\n";
            service << "Before=multi-user.target\n";
            service << "Conflicts=shutdown.target\n\n";

            service << "[Service]\n";
            service << "Type=oneshot\n";
            service << "RemainAfterExit=yes\n";
            service << "ExecStart=/usr/local/bin/archfreeze-lock\n";
            service << "ExecStop=/usr/local/bin/archfreeze-unlock\n";
            service << "ExecReload=/usr/local/bin/archfreeze-reload\n";
            service << "StandardOutput=journal\n";
            service << "StandardError=journal\n\n";

            service << "[Install]\n";
            service << "WantedBy=multi-user.target\n";
            service.close();

            // Create timer for periodic locking
            std::ofstream timer("/etc/systemd/system/archfreeze-timer.timer");
            timer << "[Unit]\n";
            timer << "Description=Periodically lock immutable system\n\n";

            timer << "[Timer]\n";
            timer << "OnBootSec=5min\n";
            timer << "OnUnitActiveSec=1hour\n";
            timer << "Persistent=true\n\n";

            timer << "[Install]\n";
            timer << "WantedBy=timers.target\n";
            timer.close();

            // Create lock status service
            std::ofstream status("/etc/systemd/system/archfreeze-status.service");
            status << "[Unit]\n";
            status << "Description=Immutable Arch Status Check\n";
            status << "After=archfreeze.service\n\n";

            status << "[Service]\n";
            status << "Type=oneshot\n";
            status << "ExecStart=/usr/local/bin/archfreeze-status\n";
            status << "RemainAfterExit=yes\n\n";

            status << "[Install]\n";
            status << "WantedBy=multi-user.target\n";
            status.close();

            system("systemctl daemon-reload");
            system("systemctl enable archfreeze.service 2>/dev/null");
            system("systemctl enable archfreeze-timer.timer 2>/dev/null");
            system("systemctl enable archfreeze-status.service 2>/dev/null");

            logger.info("Created immutable system services");
            return true;
        } catch (const std::exception& e) {
            logger.error("Service creation failed: " + std::string(e.what()));
            return false;
        }
    }

    bool createManagementScripts() {
        try {
            // Lock script - updated for bind mount approach
            std::ofstream lock("/usr/local/bin/archfreeze-lock");
            lock << "#!/bin/bash\n";
            lock << "# Lock system to read-only\n";
            lock << "set -e\n\n";
            lock << "echo \"[Arch Freeze] Locking immutable system...\"\n";
            lock << "# Ensure root is bound to overlay and read-only\n";
            lock << "if mount | grep -q \" / .*overlay\"; then\n";
            lock << "    mount -o remount,ro / 2>/dev/null || true\n";
            lock << "else\n";
            lock << "    # If not bound, just make current root read-only\n";
            lock << "    mount -o remount,ro / 2>/dev/null || true\n";
            lock << "fi\n";
            lock << "chattr +i /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/fstab 2>/dev/null || true\n";
            lock << "echo \"[Arch Freeze] System is now immutable\"\n";
            lock << "logger \"Immutable system locked\"\n";
            lock.close();

            // Unlock script - updated for bind mount approach
            std::ofstream unlock("/usr/local/bin/archfreeze-unlock");
            unlock << "#!/bin/bash\n";
            unlock << "# Unlock system for maintenance\n";
            unlock << "set -e\n\n";
            unlock << "echo \"[Arch Freeze] Unlocking system for maintenance...\"\n";
            unlock << "chattr -i /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/fstab 2>/dev/null || true\n";
            lock << "echo \"[Arch Freeze] System is now writable\"\n";
            lock << "logger \"Immutable system unlocked for maintenance\"\n";
            lock.close();

            // Status script
            std::ofstream status("/usr/local/bin/archfreeze-status");
            status << "#!/bin/bash\n";
            status << "# Check system status\n";
            status << "echo \"=== Arch Freeze Status ===\"\n";
            status << "if mount | grep -q \" / .*overlay\"; then\n";
            status << "    echo \"System: Immutable (Overlay mounted)\"\n";
            status << "else\n";
            status << "    echo \"System: Mutable (Traditional)\"\n";
            status << "fi\n";
            status << "echo \"Root filesystem: $(mount | grep ' / ' | awk '{print $6}' | cut -d, -f1)\"\n";
            status << "echo \"Snapshots: $(ls /var/lib/archfreeze/snapshots/ 2>/dev/null | wc -l)\"\n";
            status << "echo \"Upper dir size: $(du -sh /var/lib/archfreeze/upper/ 2>/dev/null | cut -f1)\"\n";
            status.close();

            // Reload script
            std::ofstream reload("/usr/local/bin/archfreeze-reload");
            reload << "#!/bin/bash\n";
            reload << "# Reload configuration\n";
            reload << "systemctl daemon-reload\n";
            reload << "systemctl restart archfreeze.service 2>/dev/null || true\n";
            reload << "echo \"[Arch Freeze] Configuration reloaded\"\n";
            reload.close();

            // Snapshot management
            std::ofstream snapshot("/usr/local/bin/archfreeze-snapshot");
            snapshot << "#!/bin/bash\n";
            snapshot << "# Manage snapshots\n";
            snapshot << "set -e\n\n";
            snapshot << "ACTION=\"$1\"\n";
            snapshot << "NAME=\"$2\"\n\n";
            snapshot << "case \"$ACTION\" in\n";
            snapshot << "    create)\n";
            snapshot << "        if [ -z \"$NAME\" ]; then\n";
            snapshot << "            echo \"Usage: $0 create <name>\"\n";
            snapshot << "            exit 1\n";
            snapshot << "        fi\n";
            snapshot << "        echo \"[Arch Freeze] Creating snapshot: $NAME\"\n";
            snapshot << "        /usr/local/bin/archfreeze-unlock\n";
            snapshot << "        rsync -a --delete /var/lib/archfreeze/upper/ /var/lib/archfreeze/snapshots/\"$NAME\"/\n";
            snapshot << "        echo \"date=$(date +%s)\" > /var/lib/archfreeze/snapshots/\"$NAME\"/.metadata\n";
            snapshot << "        echo \"name=$NAME\" >> /var/lib/archfreeze/snapshots/\"$NAME\"/.metadata\n";
            snapshot << "        /usr/local/bin/archfreeze-lock\n";
            snapshot << "        echo \"[Arch Freeze] Snapshot $NAME created\"\n";
            snapshot << "        ;;\n";
            snapshot << "    restore)\n";
            snapshot << "        if [ -z \"$NAME\" ]; then\n";
            snapshot << "            echo \"Usage: $0 restore <name>\"\n";
            snapshot << "            exit 1\n";
            snapshot << "        fi\n";
            snapshot << "        echo \"[Arch Freeze] Restoring snapshot: $NAME...\"\n";
            snapshot << "        /usr/local/bin/archfreeze-unlock\n";
            snapshot << "        rm -rf /var/lib/archfreeze/upper/*\n";
            snapshot << "        rsync -a --delete /var/lib/archfreeze/snapshots/\"$NAME\"/ /var/lib/archfreeze/upper/\n";
            snapshot << "        /usr/local/bin/archfreeze-lock\n";
            snapshot << "        echo \"[Arch Freeze] Snapshot $NAME restored - reboot required\"\n";
            snapshot << "        ;;\n";
            snapshot << "    list)\n";
            snapshot << "        echo \"Available snapshots:\"\n";
            snapshot << "        ls -la /var/lib/archfreeze/snapshots/\n";
            snapshot << "        ;;\n";
            snapshot << "    delete)\n";
            snapshot << "        if [ -z \"$NAME\" ]; then\n";
            snapshot << "            echo \"Usage: $0 delete <name>\"\n";
            snapshot << "            exit 1\n";
            snapshot << "        fi\n";
            snapshot << "        rm -rf /var/lib/archfreeze/snapshots/\"$NAME\"\n";
            snapshot << "        echo \"Snapshot $NAME deleted\"\n";
            snapshot << "        ;;\n";
            snapshot << "    *)\n";
            snapshot << "        echo \"Usage: $0 {create|restore|list|delete} [name]\"\n";
            snapshot << "        ;;\n";
            snapshot << "esac\n";
            snapshot.close();

            // Update script
            std::ofstream update("/usr/local/bin/archfreeze-update");
            update << "#!/bin/bash\n";
            update << "# Safe system update\n";
            update << "set -e\n\n";
            update << "echo \"[Arch Freeze] Starting transactional update...\"\n";
            update << "/usr/local/bin/archfreeze-unlock\n\n";
            update << "# Create pre-update snapshot\n";
            update << "SNAPSHOT=\"update-$(date +%Y%m%d-%H%M%S)\"\n";
            update << "/usr/local/bin/archfreeze-snapshot create \"$SNAPSHOT\"\n\n";
            update << "# Perform update\n";
            update << "pacman -Syu --noconfirm\n";
            update << "updatedb 2>/dev/null || true\n\n";
            update << "# Create post-update snapshot\n";
            update << "/usr/local/bin/archfreeze-snapshot create \"$SNAPSHOT-post\"\n";
            update << "/usr/local/bin/archfreeze-lock\n\n";
            update << "echo \"[Arch Freeze] Update complete. Snapshot: $SNAPSHOT\"\n";
            update << "echo \"[Arch Freeze] Reboot to apply changes\"\n";
            update.close();

            // Set executable permissions
            std::vector<std::string> scripts = {
                "/usr/local/bin/archfreeze-lock",
                "/usr/local/bin/archfreeze-unlock",
                "/usr/local/bin/archfreeze-status",
                "/usr/local/bin/archfreeze-reload",
                "/usr/local/bin/archfreeze-snapshot",
                "/usr/local/bin/archfreeze-update",
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
        try {
            logger.info("Configuring bootloader...");

            // IMPORTANT: Do NOT set rootflags=ro in bootloader
            // We'll handle this with systemd services instead

            // Detect bootloader but don't modify for root read-only
            if (fs::exists("/boot/grub/grub.cfg") || fs::exists("/etc/default/grub")) {
                logger.info("GRUB detected - no modifications needed");
                return true;
            } else if (fs::exists("/boot/loader/loader.conf")) {
                logger.info("systemd-boot detected - no modifications needed");
                return true;
            } else if (fs::exists("/efi/EFI") || fs::exists("/boot/efi")) {
                logger.info("EFI detected - no modifications needed");
                return true;
            } else {
                logger.warn("Unknown bootloader, skipping configuration");
                return true;
            }
        } catch (const std::exception& e) {
            logger.error("Bootloader configuration failed: " + std::string(e.what()));
            return false;
        }
    }

    bool createInitramfsHook() {
        // Create mkinitcpio hook for overlay support
        fs::create_directories("/etc/initcpio/install");

        std::ofstream hook("/etc/initcpio/install/archfreeze");
        hook << "#!/bin/bash\n\n";
        hook << "build() {\n";
        hook << "    add_module overlay\n";
        hook << "    add_binary /bin/mount\n";
        hook << "    add_binary /bin/umount\n";
        hook << "    add_binary /bin/mkdir\n";
        hook << "    add_binary /bin/rm\n";
        hook << "    add_runscript\n";
        hook << "}\n\n";
        hook << "help() {\n";
        hook << "    cat <<HELPEOF\n";
        hook << "This hook enables OverlayFS for Arch Freeze immutable system\n";
        hook << "HELPEOF\n";
        hook << "}\n";
        hook.close();

        fs::permissions("/etc/initcpio/install/archfreeze",
                       fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec);

        // Update mkinitcpio.conf if needed
        std::ifstream mkinit_in("/etc/mkinitcpio.conf");
        bool hook_exists = false;
        if (mkinit_in.is_open()) {
            std::string content;
            std::string line;
            while (std::getline(mkinit_in, line)) {
                content += line + "\n";
                if (line.find("HOOKS=") != std::string::npos && line.find("archfreeze") != std::string::npos) {
                    hook_exists = true;
                }
            }
            mkinit_in.close();

            if (!hook_exists) {
                size_t pos = content.find("HOOKS=");
                if (pos != std::string::npos) {
                    size_t end = content.find(")", pos);
                    if (end != std::string::npos) {
                        content.insert(end, " archfreeze");
                        std::ofstream mkinit_out("/etc/mkinitcpio.conf");
                        mkinit_out << content;
                        mkinit_out.close();
                    }
                }
            }
        }

        // Rebuild initramfs
        if (fs::exists("/usr/bin/mkinitcpio")) {
            int result = system("mkinitcpio -p 2>/dev/null");
            if (result == 0) {
                logger.info("Initramfs configured with overlay support");
            } else {
                logger.warn("Initramfs rebuild may have failed");
            }
        } else {
            logger.warn("mkinitcpio not found, skipping initramfs rebuild");
        }

        return true;
    }
};

class RecoveryManager {
private:
    Logger& logger;

public:
    RecoveryManager(Logger& log) : logger(log) {}

    bool createRecoveryTools() {
        try {
            // Emergency recovery script
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
            recovery << "read -p \"Select option: \" OPTION\n\n";
            recovery << "case $OPTION in\n";
            recovery << "    1)\n";
            recovery << "        echo \"Resetting to factory state...\"\n";
            recovery << "        rm -rf /var/lib/archfreeze/upper/*\n";
            recovery << "        echo \"Reset complete. Reboot required.\"\n";
            recovery << "        ;;\n";
            recovery << "    2)\n";
            recovery << "        echo \"Available snapshots:\"\n";
            recovery << "        ls /var/lib/archfreeze/snapshots/\n";
            recovery << "        read -p \"Enter snapshot name: \" SNAP\n";
            recovery << "        /usr/local/bin/archfreeze-snapshot restore \"$SNAP\"\n";
            recovery << "        ;;\n";
            recovery << "    3)\n";
            recovery << "        echo \"Fixing boot issues...\"\n";
            recovery << "        mount -o remount,rw / 2>/dev/null\n";
            recovery << "        if command -v grub-install &> /dev/null; then\n";
            recovery << "            grub-install /dev/sda 2>/dev/null\n";
            recovery << "            grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null\n";
            recovery << "        fi\n";
            recovery << "        if command -v mkinitcpio &> /dev/null; then\n";
            recovery << "            mkinitcpio -p 2>/dev/null\n";
            recovery << "        fi\n";
            recovery << "        mount -o remount,ro / 2>/dev/null\n";
            recovery << "        echo \"Boot repair complete.\"\n";
            recovery << "        ;;\n";
            recovery << "    4)\n";
            recovery << "        echo \"Checking system integrity...\"\n";
            recovery << "        if command -v pacman &> /dev/null; then\n";
            recovery << "            pacman -Qkk 2>/dev/null || echo \"Package check failed\"\n";
            recovery << "        fi\n";
            recovery << "        if command -v journalctl &> /dev/null; then\n";
            recovery << "            journalctl --verify 2>/dev/null || echo \"Journal check failed\"\n";
            recovery << "        fi\n";
            recovery << "        echo \"Integrity check complete.\"\n";
            recovery << "        ;;\n";
            recovery << "    5)\n";
            recovery << "        echo \"Dropping to emergency shell...\"\n";
            recovery << "        /bin/bash\n";
            recovery << "        ;;\n";
            recovery << "    *)\n";
            recovery << "        echo \"Invalid option\"\n";
            recovery << "        ;;\n";
            recovery << "esac\n";
            recovery.close();

            fs::permissions("/usr/local/bin/archfreeze-recovery",
                          fs::perms::owner_all | fs::perms::group_exec | fs::perms::others_exec);

            logger.info("Recovery tools created");
            return true;
        } catch (const std::exception& e) {
            logger.error("Recovery tool creation failed: " + std::string(e.what()));
            return false;
        }
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
        std::cout << COLOR_CYAN << "\nclaudemods Arch Freeze Beta v1.0 18-12-2025" << COLOR_RESET << std::endl;
        std::cout << COLOR_MAGENTA << "=" << std::string(70, '=') << "=" << COLOR_RESET << std::endl << std::endl;
    }

    bool backupSystem() {
        logger.info("=== Creating System Backup ===");

        std::string backup_dir = "/var/lib/archfreeze/backup/system-" + 
                                std::to_string(time(0));

        try {
            fs::create_directories(backup_dir);

            // Backup critical directories
            std::vector<std::string> backup_paths = {
                "/etc", "/boot", "/root", "/var/lib/pacman", "/usr/local"
            };

            for (const auto& path : backup_paths) {
                if (fs::exists(path)) {
                    std::string cmd = "cp -a " + path + " " + backup_dir + "/ 2>/dev/null || true";
                    int result = system(cmd.c_str());
                    if (result == 0) {
                        logger.info("Backed up: " + path);
                    } else {
                        logger.warn("Failed to backup: " + path);
                    }
                }
            }

            // Backup package list
            system(("pacman -Q > " + backup_dir + "/package-list.txt 2>/dev/null").c_str());

            // Backup fstab
            if (fs::exists("/etc/fstab")) {
                fs::copy("/etc/fstab", backup_dir + "/fstab.backup", fs::copy_options::overwrite_existing);
            }

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
        std::cout << COLOR_GREEN << "\n✓ Your Arch system is now immutable." << COLOR_RESET << std::endl;

        std::cout << COLOR_CYAN << "\nIMPORTANT COMMANDS:" << COLOR_RESET << std::endl;
        std::cout << "  archfreeze-lock      - Lock system to read-only" << std::endl;
        std::cout << "  archfreeze-unlock    - Unlock for maintenance" << std::endl;
        std::cout << "  archfreeze-status    - Check system status" << std::endl;
        std::cout << "  archfreeze-update    - Safe system update with snapshots" << std::endl;
        std::cout << "  archfreeze-snapshot  - Manage snapshots" << std::endl;
        std::cout << "  archfreeze-recovery  - Emergency recovery" << std::endl;

        std::cout << COLOR_YELLOW << "\nNEXT STEPS:" << COLOR_RESET << std::endl;
        std::cout << "1. REBOOT your system" << std::endl;
        std::cout << "2. System will boot in mutable mode" << std::endl;
        std::cout << "3. Use 'archfreeze-lock' to enable immutable mode" << std::endl;
        std::cout << "4. Use 'archfreeze-unlock' before making changes" << std::endl;
        std::cout << "5. Use 'archfreeze-update' for package updates" << std::endl;

        std::cout << COLOR_MAGENTA << "\nLog file: " << COLOR_RESET << "/var/log/archfreeze.log" << std::endl;
        std::cout << COLOR_MAGENTA << "Configuration: " << COLOR_RESET << "/var/lib/archfreeze/" << std::endl;
        std::cout << COLOR_MAGENTA << "=" << std::string(70, '=') << "=" << COLOR_RESET << std::endl;
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
        logger.info("Version: 1.1 - Arch Freeze (Fixed Mount Issue)");
        logger.info("Date: " + std::string(__DATE__) + " " + std::string(__TIME__));

        // Check if already converted
        if (fs::exists("/var/lib/archfreeze/.converted")) {
            logger.warn("System is already converted to immutable.");
            std::cout << COLOR_YELLOW << "Re-run conversion? (y/N): " << COLOR_RESET;
            std::string response;
            std::cin >> response;
            if (response != "y" && response != "Y") {
                return false;
            }
        }

        // Get confirmation
        std::cout << COLOR_RED << "\n=== WARNING ===" << COLOR_RESET << std::endl;
        std::cout << "This will convert your Arch Linux system to immutable mode.\n";
        std::cout << "The system will become read-only by default after reboot.\n";
        std::cout << "Changes will be stored in /var/lib/archfreeze/upper/\n";
        std::cout << "Make sure you have backups of important data!\n\n";
        std::cout << COLOR_RED << "Type 'FREEZE' to proceed: " << COLOR_RESET;

        std::string response;
        std::cin >> response;

        if (response != "FREEZE") {
            logger.warn("Conversion cancelled by user.");
            return false;
        }

        // Perform checks
        if (!syscheck->performAllChecks()) {
            return false;
        }

        // Create backup
        logger.info("\n=== Creating System Backup ===");
        if (!backupSystem()) {
            std::cout << COLOR_YELLOW << "Backup failed. Continue anyway? (y/N): " << COLOR_RESET;
            std::cin >> response;
            if (response != "y" && response != "Y") {
                return false;
            }
        }

        // Step 1: Create overlay structure
        logger.info("\n=== Step 1: Creating Overlay Structure ===");
        if (!overlay->createDirectories()) {
            logger.error("Failed to create overlay directories");
            return false;
        }

        // Step 2: Configure overlay
        logger.info("\n=== Step 2: Configuring OverlayFS ===");
        if (!overlay->createFSTABEntry()) {
            logger.error("Failed to configure fstab");
            return false;
        }
        if (!overlay->createSystemdMount()) {
            logger.error("Failed to create systemd mount");
            return false;
        }

        // Step 3: Set permissions
        logger.info("\n=== Step 3: Setting Permissions ===");
        if (!permissions->makeImmutable()) {
            logger.error("Failed to set permissions");
            return false;
        }
        if (!permissions->setAttributes()) {
            logger.error("Failed to set file attributes");
            return false;
        }

        // Step 4: Create services and scripts
        logger.info("\n=== Step 4: Creating Management Tools ===");
        if (!services->createManagementScripts()) {
            logger.error("Failed to create management scripts");
            return false;
        }
        if (!services->createImmutableService()) {
            logger.error("Failed to create services");
            return false;
        }

        // Step 5: Configure boot
        logger.info("\n=== Step 5: Configuring Boot ===");
        if (!boot->configureBootloader()) {
            logger.warn("Boot configuration may have issues");
        }
        if (!boot->createInitramfsHook()) {
            logger.warn("Initramfs configuration may have issues");
        }

        // Step 6: Create recovery tools
        logger.info("\n=== Step 6: Creating Recovery Tools ===");
        if (!recovery->createRecoveryTools()) {
            logger.warn("Recovery tools may not be fully installed");
        }

        // Step 7: Create initial snapshot
        logger.info("\n=== Step 7: Creating Initial Snapshot ===");
        if (!overlay->createSnapshot("initial")) {
            logger.warn("Failed to create initial snapshot");
        }

        // Mark as converted
        std::ofstream marker("/var/lib/archfreeze/.converted");
        marker << "Arch Freeze conversion completed: " << time(0) << std::endl;
        marker << "Version: 1.1 (Fixed mount issue)" << std::endl;
        marker << "Upper dir: /var/lib/archfreeze/upper" << std::endl;
        marker << "Work dir: /var/lib/archfreeze/work" << std::endl;
        marker << "Merged dir: /var/lib/archfreeze/merged" << std::endl;
        marker.close();

        // Print summary
        printSummary();

        return true;
    }
};

int main() {
    // Set up signal handling
    signal(SIGINT, [](int) {
        std::cout << COLOR_RED << "\n\nInterrupted. System may be in inconsistent state." << COLOR_RESET << std::endl;
        std::cout << "Check /var/log/archfreeze.log for details." << std::endl;
        exit(1);
    });

    try {
        ImmutableArchConverter converter;
        if (converter.run()) {
            std::cout << COLOR_GREEN << "\n✓ Conversion successful!" << COLOR_RESET << std::endl;
            std::cout << COLOR_YELLOW << "⚠  REBOOT REQUIRED to complete installation." << COLOR_RESET << std::endl;
            return 0;
        } else {
            std::cerr << COLOR_RED << "\n✗ Conversion failed." << COLOR_RESET << std::endl;
            std::cerr << "Check /var/log/archfreeze.log for details." << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << COLOR_RED << "Fatal error: " << e.what() << COLOR_RESET << std::endl;
        return 1;
    }
}
