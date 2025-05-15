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
#include <android/log.h>
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
#include <endian.h>
#include <thread>
#include "log.h"
#include "PropertyManager.cpp"
#include "external/emoji.h"

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
				LOGD("Marking sensitive socket FD %d (%s) for sanitization.", fdi->fd, socket_name.c_str());
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
				LOGD("Marking sensitive file FD %d (%s) for sanitization.", fdi->fd, fdi->file_path.c_str());
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

static void unmount(const std::vector<MountInfo>& mounts) {
	MountRootResolver mrs(mounts);
	for (const auto& mount : std::ranges::reverse_view(mounts)) {
        	if (anomaly(mrs, mount)) {
			errno = 0;
			int res;
			if ((res = umount2(mount.getMountPoint().c_str(), MNT_DETACH)) == 0)
				LOGD("umount2(\"%s\", MNT_DETACH): returned (0): 0 (Success)", mount.getMountPoint().c_str());
			else
				LOGE("umount2(\"%s\", MNT_DETACH): returned %d: %d (%s)", mount.getMountPoint().c_str(), res, errno, strerror(errno));
		}
	}
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
			if ((res = ::mount(nullptr, "/data", nullptr, flags, (std::string("errors=") + *errors).c_str())) == 0)
				LOGD("mount(nullptr, \"/data\", nullptr, 0x%x, \"errors=%s\"): returned 0: 0 (Success)", flags, errors->c_str());
			else
				LOGW("mount(NULL, \"/data\", NULL, 0x%x, \"errors=%s\"): returned %d: %d (%s)", flags, errors->c_str(), res, errno, strerror(errno));
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
	dev_t dev{};
	ino_t inode{};

    void preSpecialize(AppSpecializeArgs *args) {
		unsigned int flags = api->getFlags();
		const bool whitelist = []() {
			std::error_code ec;
			auto status = fs::status("/data/adb/nohello/whitelist");
			if (ec)
				return false;
			return fs::is_regular_file(status);
		}();
		if (flags & zygisk::StateFlag::PROCESS_GRANTED_ROOT) {
			api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
			return;
		}
		if ((whitelist && isuserapp(args->uid)) || flags & zygisk::StateFlag::PROCESS_ON_DENYLIST) {
			pid_t pid = getpid();
			cfd = api->connectCompanion(); // Companion FD
			api->exemptFd(cfd);
			auto di = devinoby("libandroid_runtime.so");
			if (di) {
				std::tie(dev, inode) = *di;
			} else {
				LOGW("$[zygisk::PreSpecialize] devino[dl_iterate_phdr]: Failed to get device & inode for libandroid_runtime.so");
				LOGI("$[zygisk::PreSpecialize] Fallback to use `/proc/self/maps`");
				std::tie(dev, inode) = devinobymap("libandroid_runtime.so");
				if (!dev && !inode) {
					LOGE("$[zygisk::PreSpecialize] devino[/proc/self/maps]: Failed to get device & inode for libandroid_runtime.so");
					close(cfd);
					api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
					return;
				}
			}

			api->pltHookRegister(dev, inode, "unshare", (void*) reshare, (void**) &ar_unshare);
			api->pltHookRegister(dev, inode, "setresuid", (void*) resetresuid, (void**) &ar_setresuid);
			api->pltHookCommit();
			nocb = [pid, this]() { // Capture this for api access
				nocb = []() {};
                std::vector<std::pair<std::unique_ptr<FileDescriptorInfo>, bool>> fdSanitizeList; // bool is shouldDetach
                auto fds = GetOpenFds([](const std::string &error){
                    LOGE("#[zygisk::PreSpecialize] GetOpenFds: %s", error.c_str());
                });
                if (fds) {
                    for (auto &fd : *fds) {
                        if (fd == cfd) continue; // Skip companion FD itself
                        auto fdi = FileDescriptorInfo::CreateFromFd(fd, [fd](const std::string &error){
                            LOGE("#[zygisk::PreSpecialize] CreateFromFd(%d): %s", fd, error.c_str());
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
					LOGE("#[zygisk::PreSpecialize] ar_unshare: %s", strerror(errno));
					// There's nothing we can do except returning
					close(cfd);
					return;
				}
				res = mount("rootfs", "/", nullptr, MS_SLAVE | MS_REC, nullptr);
				if (res != 0) {
					LOGE("#[zygisk::PreSpecialize] mount(rootfs, \"/\", nullptr, MS_SLAVE | MS_REC, nullptr): returned %d: %d (%s)", res, errno, strerror(errno));
                    // There's nothing we can do except returning
					close(cfd);
					return;
				}

				if (write(cfd, &pid, sizeof(pid)) != sizeof(pid)) {
					LOGE("#[zygisk::PreSpecialize] write: [-> pid]: %s", strerror(errno));
					res = EXIT_FAILURE; // Fallback to unmount from zygote
                } else if (read(cfd, &res, sizeof(res)) != sizeof(res)) {
					LOGE("#[zygisk::PreSpecialize] read: [<- status]: %s", strerror(errno));
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
					LOGW("#[zygisk::PreSpecialize]: Companion failed, fallback to unmount in zygote process");
					unmount(getMountInfo()); // Unmount in current (zygote) namespace as fallback
				}

                // Sanitize FDs after companion communication and potential mount changes
                for (auto &[fdi, shouldDetach] : fdSanitizeList) {
					LOGD("#[zygisk::PreSpecialize]: Sanitizing FD %d (path: %s, socket: %d), detach: %d",
							fdi->fd, fdi->file_path.c_str(), fdi->is_sock, shouldDetach);
					fdi->ReopenOrDetach([
						fd = fdi->fd,
						path = fdi->file_path // Capture path by value for lambda
					](const std::string &error){
						LOGE("#[zygisk::PreSpecialize] Sanitize FD %d (%s): %s", fd, path.c_str(), error.c_str());
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
			api->pltHookRegister(dev, inode, "unshare", (void*) ar_unshare, nullptr);
            ar_unshare = nullptr; // Clear pointer
        }
		if (ar_setresuid) {
			api->pltHookRegister(dev, inode, "setresuid", (void*) ar_setresuid, nullptr);
            ar_setresuid = nullptr; // Clear pointer
        }
		api->pltHookCommit();
		// DO NOT UNCOMMENT THIS
		// For some reasons it causes apps to loop infinitely after
		// 2~3 executions
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

	static const bool compatbility = [] {
		if (fs::exists("/data/adb/modules/zygisk_shamiko") && !fs::exists("/data/adb/modules/zygisk_shamiko/disable"))
			return false;
		if (fs::exists("/data/adb/modules/zygisk-assistant") && !fs::exists("/data/adb/modules/zygisk-assistant/disable"))
			return false;
		if (fs::exists("/data/adb/modules/treat_wheel") && !fs::exists("/data/adb/modules/treat_wheel/disable"))
			return false;
		return true;
	}();

	int result;
	if (read(fd, &pid, sizeof(pid)) != sizeof(pid)) {
        LOGE("#[ps::Companion] Failed to read PID: %s", strerror(errno));
		close(fd);
		return;
	}
	PropertyManager pm("/data/adb/modules/zygisk_nohello/module.prop");
	if (!compatbility) {
		result = MODULE_CONFLICT;
		pm.setProp("description", "[" + emoji::emojize(":x: ") + "Conflicting modules] " + description);
		goto skip;
	}
	result = forkcall(
		[pid]()
		{
			int res = switchnsto(pid);
			if (!res) { // switchnsto returns true on success (0 from setns)
				LOGE("#[ps::Companion] setns failed for PID %d: %s", pid, strerror(errno));
				return EXIT_FAILURE;
			}
			auto mounts = getMountInfo();
			unmount(mounts);
			remount(mounts);
			return EXIT_SUCCESS;
		}
	);
	if (result == EXIT_SUCCESS) {
		successRate++;
		pm.setProp("description", "[" + emoji::emojize(":yum: ") + "Nohello unmounted " +
								  std::to_string(successRate) + " time(s)] " + description);
	}
	skip:
	if (write(fd, &result, sizeof(result)) != sizeof(result)) {
		LOGE("#[ps::Companion] Failed to write result: %s", strerror(errno));
	}
	close(fd);
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(NoHello)
REGISTER_ZYGISK_COMPANION(NoRoot)
