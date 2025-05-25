/* Copyright 2022-2023 John "topjohnwu" Wu
 * Copyright 2024 The NoHello Contributors
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <filesystem>
#include <ranges>
#include <vector>
#include <utility> // For std::pair, std::move

#include "zygisk.hpp"
#include "external/android_filesystem_config.h"
#include "mountsinfo.cpp"
#include "utils.cpp"
#include "external/fdutils/fd_utils.cpp"
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <endian.h>
#include <thread>
#include "PropertyManager.cpp"
#include "MountRuleParser.cpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

namespace fs = std::filesystem;

static constexpr off_t EXT_SUPERBLOCK_OFFSET = 0x400;
static constexpr off_t EXT_MAGIC_OFFSET = 0x38;
static constexpr off_t EXT_ERRORS_OFFSET = 0x3C;
static constexpr uint16_t EXT_MAGIC = 0xEF53;

#define MODULE_CONFLICT  2

static const std::set<std::string> toumount_sources = {"KSU", "APatch", "magisk", "worker"};
static const std::string adbPathPrefix = "/data/adb";

static bool anomaly(MountRootResolver mrs, const MountInfo &mount) {
	const std::string resolved_root = mrs.resolveRoot(mount);
	if (resolved_root.starts_with(adbPathPrefix) || mount.getMountPoint().starts_with(adbPathPrefix)) {
		return true;
	}
	const auto& fs_type = mount.getFsType();
	const auto& mnt_src = mount.getMountSource();
	if (toumount_sources.count(mnt_src)) {
		return true;
	}
	if (fs_type == "overlay") {
		if (toumount_sources.count(mnt_src)) {
			return true;
		}
		const auto& fm = mount.getMountOptions().flagmap;
		if (fm.count("lowerdir") && fm.at("lowerdir").starts_with(adbPathPrefix)) {
			return true;
		}
		if (fm.count("upperdir") && fm.at("upperdir").starts_with(adbPathPrefix)) {
			return true;
		}
		if (fm.count("workdir") && fm.at("workdir").starts_with(adbPathPrefix)) {
			return true;
		}
	} else if (fs_type == "tmpfs") {
		if (toumount_sources.count(mnt_src)) {
			return true;
		}
	}
	return false;
}

static bool anomaly(const MountRuleParser::MountRule& rule, MountRootResolver mrs, const MountInfo &mount) {
	const std::string resolvedRoot = mrs.resolveRoot(mount);
	const auto& fsType = mount.getFsType();
	if (fsType != "overlay") {
		return rule.matches(resolvedRoot, mount.getMountPoint(), fsType, mount.getMountSource());
	} else {
		const auto& fm = mount.getMountOptions().flagmap;
		std::vector<std::string> roots = {resolvedRoot};
		for (const auto* key : {"lowerdir", "upperdir", "workdir"}) {
			auto it = fm.find(key);
			if (it != fm.end()) {
				roots.push_back(it->second);
			}
		}
		return rule.matches(roots, mount.getMountPoint(), fsType, mount.getMountSource());
	}
	return false;
}

static bool anomaly(const std::vector<MountRuleParser::MountRule>& rules, MountRootResolver mrs, const MountInfo &mount) {
	const std::string resolvedRoot = mrs.resolveRoot(mount);
	const auto& fsType = mount.getFsType();
	const auto& fm = mount.getMountOptions().flagmap;
	for (const auto& rule : rules) {
		if (fsType != "overlay") {
			if (rule.matches(resolvedRoot, mount.getMountPoint(), fsType, mount.getMountSource()))
				return true;
		} else {
			std::vector<std::string> roots = {resolvedRoot};
			for (const auto* key : {"lowerdir", "upperdir", "workdir"}) {
				auto it = fm.find(key);
				if (it != fm.end()) {
					roots.push_back(it->second);
				}
			}
			if (rule.matches(roots, mount.getMountPoint(), fsType, mount.getMountSource()))
				return true;
		}
	}
	return false;
}

static std::pair<bool, bool> anomaly(const std::unique_ptr<FileDescriptorInfo> fdi) {
	if (fdi->is_sock) {
		std::string socket_name;
		if (fdi->GetSocketName(&socket_name)) {
			if (socket_name.find("magisk") != std::string::npos ||
				socket_name.find("kernelsu") != std::string::npos || // For KernelSU daemon, common pattern
				socket_name.find("ksud") != std::string::npos || // KernelSU daemon
				socket_name.find("apatchd") != std::string::npos || // For APatch daemon, common pattern
				socket_name.find("apd") != std::string::npos      // APatch daemon
					) {
				return {true, true};
			}
		}
	} else { // Not a socket
		if (!fdi->file_path.starts_with("/memfd:") &&
			!fdi->file_path.starts_with("/dev/ashmem") && // Common, usually not root related
			!fdi->file_path.starts_with("[anon_inode:") && // e.g., [anon_inode:sync_fence]
			!fdi->file_path.empty() // Ensure path is not empty
				) {
			if (fdi->file_path.starts_with(adbPathPrefix) ||
				fdi->file_path.find("magisk") != std::string::npos ||
				fdi->file_path.find("kernelsu") != std::string::npos ||
				fdi->file_path.find("apatch") != std::string::npos) {
				return {true, true};
			}
		}
	}
	return {false, false};
}


static std::unique_ptr<std::string> getExternalErrorBehaviour(const MountInfo& mount) {
	const auto& fs = mount.getFsType();
	if (fs != "ext2" && fs != "ext3" && fs != "ext4")
		return nullptr;
	std::ifstream mntsrc(mount.getMountSource(), std::ios::binary);
	if (!mntsrc || !mntsrc.is_open())
		return nullptr;
	uint16_t magic;
	mntsrc.seekg(EXT_SUPERBLOCK_OFFSET + EXT_MAGIC_OFFSET, std::ios::beg);
	mntsrc.read(reinterpret_cast<char *>(&magic), sizeof(magic));
	if (!mntsrc || mntsrc.gcount() != sizeof(magic))
		return nullptr;
	magic = le16toh(magic);
	if (magic != EXT_MAGIC)
		return nullptr;
	uint16_t errors;
	mntsrc.seekg(EXT_SUPERBLOCK_OFFSET + EXT_ERRORS_OFFSET, std::ios::beg);
	mntsrc.read(reinterpret_cast<char *>(&errors), sizeof(errors));
	if (!mntsrc || mntsrc.gcount() != sizeof(errors))
		return nullptr;
	errors = le16toh(errors);
	switch (errors)
	{
		case 1:
			return std::make_unique<std::string>("continue");
		case 2:
			return std::make_unique<std::string>("remount-ro");
		case 3:
			return std::make_unique<std::string>("panic");
		default:
			return nullptr;
	}
	return nullptr;
}

static void doumount(const std::string& mntPnt);

static void unmount(const std::vector<MountInfo>& mounts) {
	MountRootResolver mrs(mounts);
	for (const auto& mount : std::ranges::reverse_view(mounts)) {
		if (anomaly(mrs, mount))
			doumount(mount.getMountPoint());
	}
}

static void unmount(const std::vector<MountRuleParser::MountRule>& rules, const std::vector<MountInfo>& mounts) {
	MountRootResolver mrs(mounts);
	for (const auto& mount : std::ranges::reverse_view(mounts)) {
		if (anomaly(rules, mrs, mount))
			doumount(mount.getMountPoint());
	}
}

static void unmount(const MountRuleParser::MountRule& rule, const std::vector<MountInfo>& mounts) {
	MountRootResolver mrs(mounts);
	for (const auto& mount : std::ranges::reverse_view(mounts)) {
		if (anomaly(rule, mrs, mount))
			doumount(mount.getMountPoint());
	}
}

static void doumount(const std::string& mntPnt) {
	errno = 0;
	int res;
	const char *mntpnt = mntPnt.c_str();
	res = umount2(mntpnt, MNT_DETACH);
}

static void remount(const std::vector<MountInfo>& mounts) {
	for (const auto& mount : mounts) {
		if (mount.getMountPoint() == "/data") {
			const auto& mntopts = mount.getMountOptions();
			const auto& fm = mntopts.flagmap;
			if (!fm.count("errors"))
				break;
			auto errors = getExternalErrorBehaviour(mount);
			if (!errors || fm.at("errors") == *errors)
				break;
			auto mntflags = mount.getFlags();
			unsigned int flags = MS_REMOUNT;
			if (mntflags & MountFlags::NOSUID) {
				flags |= MS_NOSUID;
			}
			if (mntflags & MountFlags::NODEV) {
				flags |= MS_NODEV;
			}
			if (mntflags & MountFlags::NOEXEC) {
				flags |= MS_NOEXEC;
			}
			if (mntflags & MountFlags::NOATIME) {
				flags |= MS_NOATIME;
			}
			if (mntflags & MountFlags::NODIRATIME) {
				flags |= MS_NODIRATIME;
			}
			if (mntflags & MountFlags::RELATIME) {
				flags |= MS_RELATIME;
			}
			if (mntflags & MountFlags::NOSYMFOLLOW) {
				flags |= MS_NOSYMFOLLOW;
			}
			int res;
			res = ::mount(nullptr, "/data", nullptr, flags, (std::string("errors=") + *errors).c_str());
			break;
		}
	}
}

static std::function<void()> nocb = []() {};

int (*ar_unshare)(int) = nullptr;
int (*ar_setresuid)(uid_t, uid_t, uid_t) = nullptr;

static int reshare(int flags) {
	nocb();
	errno = 0;
	return flags == CLONE_NEWNS ? 0 : ar_unshare(flags & ~CLONE_NEWNS);
}

static int resetresuid(uid_t ruid, uid_t euid, uid_t suid) {
	nocb();
	return ar_setresuid(ruid, euid, suid);
}

class NoHello : public zygisk::ModuleBase {
public:
    void onLoad(Api *_api, JNIEnv *_env) override {
        this->api = _api;
        this->env = _env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        preSpecialize(args);
    }

	void postAppSpecialize(const AppSpecializeArgs *args) override {
		const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
		postSpecialize(process);
		env->ReleaseStringUTFChars(args->nice_name, process);
	}

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        //preSpecialize("system_server"); // System server usually doesn't need this level of hiding
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api{};
    JNIEnv *env{};
	int cfd{};
	dev_t rundev{};
	ino_t runinode{};
	dev_t cdev{};
	ino_t cinode{};


    void preSpecialize(AppSpecializeArgs *args) {
		unsigned int flags = api->getFlags();
		const bool whitelist = access("/data/adb/nohello/whitelist", F_OK) == 0;
		if (flags & zygisk::StateFlag::PROCESS_GRANTED_ROOT) {
			api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
			return;
		}
		auto fn = [this](const std::string& lib) {
			auto di = devinoby(lib.c_str());
			if (di) {
				return *di;
			} else {
				return devinobymap(lib);
			}
		};
		if ((whitelist && isuserapp(args->uid)) || flags & zygisk::StateFlag::PROCESS_ON_DENYLIST) {
			pid_t pid = getpid();
			cfd = api->connectCompanion(); // Companion FD
			api->exemptFd(cfd);
			std::tie(cdev, cinode) = fn("libc.so");
			if (!cdev && !cinode) {
				close(cfd);
				api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
				return;
			}
			std::tie(rundev, runinode) = fn("libandroid_runtime.so");
			if (!rundev && !runinode) {
				close(cfd);
				api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
				return;
			}
			api->pltHookRegister(rundev, runinode, "unshare", (void*) reshare, (void**) &ar_unshare);
			api->pltHookRegister(rundev, runinode, "setresuid", (void*) resetresuid, (void**) &ar_setresuid);
			api->pltHookCommit();
			nocb = [pid, this]() { // Capture this for api access
				nocb = []() {};
                std::vector<std::pair<std::unique_ptr<FileDescriptorInfo>, bool>> fdSanitizeList; // bool is shouldDetach
                auto fds = GetOpenFds([](const std::string &error){
                });
                if (fds) {
                    for (auto &fd : *fds) {
                        if (fd == cfd) continue; // Skip companion FD itself
                        auto fdi = FileDescriptorInfo::CreateFromFd(fd, [fd](const std::string &error){
                        });
						if (!fdi)
							continue;
						auto [canSanitize, shouldDetach] = anomaly(std::move(fdi));
                        if (canSanitize) {
							fdSanitizeList.emplace_back(std::move(fdi), shouldDetach);
						}
                    }
                }

				int res = ar_unshare(CLONE_NEWNS);
				if (res != 0) {
					// There's nothing we can do except returning
					close(cfd);
					return;
				}
				res = mount("rootfs", "/", nullptr, MS_SLAVE | MS_REC, nullptr);
				if (res != 0) {
                    // There's nothing we can do except returning
					close(cfd);
					return;
				}

				if (write(cfd, &pid, sizeof(pid)) != sizeof(pid)) {
					res = EXIT_FAILURE; // Fallback to unmount from zygote
                } else if (read(cfd, &res, sizeof(res)) != sizeof(res)) {
					res = EXIT_FAILURE; // Fallback to unmount from zygote
				}

				// Closing in postAppSpecialize to generalize
				// for other processes too
				//close(cfd);

				if (res == MODULE_CONFLICT) {
					// Revert mount changes if conflict
					mount(nullptr, "/", nullptr, MS_SHARED | MS_REC, nullptr);
					return;
				} else if (res == EXIT_FAILURE) {
					// We didn't make Mount Rule System yet supported in preAppSpecalize
					// Because it's less often to come here
					unmount(getMountInfo()); // Unmount in current (zygote) namespace as fallback
				}

                // Sanitize FDs after companion communication and potential mount changes
                for (auto &[fdi, shouldDetach] : fdSanitizeList) {
					fdi->ReopenOrDetach([
						fd = fdi->fd,
						path = fdi->file_path // Capture path by value for lambda
					](const std::string &error){
					}, shouldDetach);
                }
			};
			return;
		}
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

	void postSpecialize(const char *process) {
        // Unhook PLT hooks
		if (ar_unshare) {
			api->pltHookRegister(rundev, runinode, "unshare", (void*) ar_unshare, nullptr);
            ar_unshare = nullptr; // Clear pointer
        }
		if (ar_setresuid) {
			api->pltHookRegister(rundev, runinode, "setresuid", (void*) ar_setresuid, nullptr);
            ar_setresuid = nullptr; // Clear pointer
        }
		api->pltHookCommit();
		close(cfd);
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
	}

};

static void NoRoot(int fd) {
	pid_t pid = -1;
	static unsigned int successRate = 0;
	static const std::string description = [] {
		std::ifstream f("/data/adb/modules/zygisk_nohello/description");
		// This file exists only after installing/updating the module
		// It should have the default description
		// Since this is static const it's only evaluated once per boot since companion won't exit
		return f ? ([](std::ifstream& s){ std::string l; std::getline(s, l); return l; })(f) : "A Zygisk module to hide root.";
	}();
	static PropertyManager pm("/data/adb/modules/zygisk_nohello/module.prop");

	static const bool compatbility = [] {
		if (fs::exists("/data/adb/modules/zygisk_shamiko") && !fs::exists("/data/adb/modules/zygisk_shamiko/disable"))
			return false;
		if (fs::exists("/data/adb/modules/zygisk-assistant") && !fs::exists("/data/adb/modules/zygisk-assistant/disable"))
			return false;
		if (fs::exists("/data/adb/modules/treat_wheel") && !fs::exists("/data/adb/modules/treat_wheel/disable"))
			return false;
		return true;
	}();

	static const bool doesUmountPersists = []() {
		return fs::exists("/data/adb/nohello/umount_persist") || fs::exists("/data/adb/nohello/umount_persists");
	}();

	static const int cleanSignal = forkcall([]() {
		bool z64 = false, z32 = false;
		for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
			if (!entry.is_directory())
				continue;
			std::string name = entry.path().filename();
			if (!std::all_of(name.begin(), name.end(), ::isdigit)) continue;
			auto pid = static_cast<pid_t>(std::stoi(name));
			std::ifstream cmdline(entry.path() / "cmdline");
			std::string cmd;
			std::getline(cmdline, cmd, '\0');
			if (cmd == "zygote64") {
				std::ifstream statusFile(("/proc/" + std::to_string(pid) + "/status"));
				std::string line;
				pid_t ppid = -1;
				while (std::getline(statusFile, line)) {
					if (line.rfind("PPid:", 0) == 0) {
						ppid = std::stoi(line.substr(5));
						break;
					}
				}
				if (ppid != 1) continue;
				if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
					LOGE("#[ps::Companion] ptrace(PTRACE_ATTACH, %d, nullptr, nullptr): %s", pid,
						 strerror(errno));
					continue;
				}
				waitpid(pid, nullptr, 0);
				if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACEFORK) == -1) {
					LOGE("#[ps::Companion] ptrace(PTRACE_SETOPTIONS, %d, nullptr, PTRACE_O_TRACEFORK): %s", pid, strerror(errno));
					ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
					continue;
				}
				if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
					LOGE("#[ps::Companion] ptrace(PTRACE_CONT, %d, nullptr, nullptr): %s", pid, strerror(errno));
					ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
					continue;
				}
				while (true) {
					int status = 0;
					pid_t eventPid = waitpid(-1, &status, 0);
					if (WIFSTOPPED(status)) {
						if (status >> 16 == PTRACE_EVENT_FORK) {
							unsigned long newChildPid = 0;
							ptrace(PTRACE_GETEVENTMSG, eventPid, nullptr, &newChildPid);
							LOGD("#[ps::Companion] Fork detected (%d -> fork() -> %lu)", pid, newChildPid);
							ptrace(PTRACE_DETACH, newChildPid, nullptr, nullptr);
							LOGD("#[ps::Companion] Detaching (%lu)", newChildPid);
							ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
							LOGD("#[ps::Companion] Detaching (%d)", pid);
							break;
						} else {
							ptrace(PTRACE_CONT, eventPid, nullptr, nullptr);
						}
					}
				}
				z64 = true;
				continue;
			}
			if (cmd == "zygote32") {
				std::ifstream statusFile(("/proc/" + std::to_string(pid) + "/status"));
				std::string line;
				pid_t ppid = -1;
				while (std::getline(statusFile, line)) {
					if (line.rfind("PPid:", 0) == 0) {
						ppid = std::stoi(line.substr(5));
						break;
					}
				}
				if (ppid != 1) continue;
				if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
					LOGE("#[ps::Companion] ptrace(PTRACE_ATTACH, %d, nullptr, nullptr): %s", pid,
						 strerror(errno));
					continue;
				}
				waitpid(pid, nullptr, 0);
				if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_TRACEFORK) == -1) {
					LOGE("#[ps::Companion] ptrace(PTRACE_SETOPTIONS, %d, nullptr, PTRACE_O_TRACEFORK): %s", pid, strerror(errno));
					ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
					continue;
				}
				if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
					LOGE("#[ps::Companion] ptrace(PTRACE_CONT, %d, nullptr, nullptr): %s", pid, strerror(errno));
					ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
					continue;
				}
				while (true) {
					int status = 0;
					pid_t eventPid = waitpid(-1, &status, 0);
					if (WIFSTOPPED(status)) {
						if (status >> 16 == PTRACE_EVENT_FORK) {
							unsigned long newChildPid = 0;
							ptrace(PTRACE_GETEVENTMSG, eventPid, nullptr, &newChildPid);
							LOGD("#[ps::Companion] Fork detected (%d -> fork() -> %lu)", pid, newChildPid);
							ptrace(PTRACE_DETACH, newChildPid, nullptr, nullptr);
							LOGD("#[ps::Companion] Detaching (%lu)", newChildPid);
							ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
							LOGD("#[ps::Companion] Detaching (%d)", pid);
							break;
						} else {
							ptrace(PTRACE_CONT, eventPid, nullptr, nullptr);
						}
					}
				}
				z32 = true;
				continue;
			}
		}
		return z64 || z32;
	});

	static std::vector<MountRuleParser::MountRule> persistMountRules;
	std::vector<MountRuleParser::MountRule> mountRules;

	if (!doesUmountPersists) {
		mountRules = MountRuleParser::parseMultipleRules([]() {
			std::vector<std::string> rules;
			std::ifstream f("/data/adb/nohello/umount");
			if (f && f.is_open()) {
				std::string line;
				while (std::getline(f, line)) {
					if (!line.empty())
						rules.push_back(line);
				}
				f.close();
			}
			return rules;
		}());
	} else {
		persistMountRules = MountRuleParser::parseMultipleRules([]() {
			std::vector<std::string> rules;
			std::ifstream f("/data/adb/nohello/umount");
			if (f && f.is_open()) {
				std::string line;
				while (std::getline(f, line)) {
					if (!line.empty())
						rules.push_back(line);
				}
				f.close();
			}
			return rules;
		}());
	}

	int result;
	if (read(fd, &pid, sizeof(pid)) != sizeof(pid)) {
		close(fd);
		return;
	}
	if (!compatbility) {
		result = MODULE_CONFLICT;
		pm.setProp("description", "[\U0000274C Conflicting modules] " + description);
		goto skip;
	}
	result = forkcall(
		[pid, mountRules]()
		{
			int res = switchnsto(pid);
			if (!res) { // switchnsto returns true on success (0 from setns)
				return EXIT_FAILURE;
			}
			auto mounts = getMountInfo();
			if (mountRules.empty())
				unmount(mounts);
			else if (!doesUmountPersists)
				unmount(mountRules, mounts);
			else
				unmount(persistMountRules, mounts);
			remount(mounts);
			return EXIT_SUCCESS;
		}
	);
	if (result == EXIT_SUCCESS) {
		successRate++;
		pm.setProp("description", "[\U0001F60B Nohello unmounted " +
								  std::to_string(successRate) + " time(s)] " + description);
	}
	skip:
	if (write(fd, &result, sizeof(result)) != sizeof(result)) {
	}
	close(fd);
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(NoHello)
REGISTER_ZYGISK_COMPANION(NoRoot)
