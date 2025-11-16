/*
 * This file includes modifications derived from The Android Open Source Project,
 * which is licensed under the Apache License, Version 2.0 (the "License").
 * These modifications are provided under the same License terms as the original work.
 *
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "fd_utils.h"
#include <algorithm>
#include <utility>
#include <fcntl.h>
#include <grp.h>
#include <cstdlib>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <cerrno> // For errno
#include <cstring> // For strerror
#include "stringprintf.cpp"

static const char kFdPath[] = "/proc/self/fd";


namespace android::base {
	static bool Readlink(const std::string& path, std::string* result) {
		result->clear();
		// Most Linux file systems (ext2 and ext4, say) limit symbolic links to
		// 4095 bytes. Since we'll copy out into the string anyway, it doesn't
		// waste memory to just start there. We add 1 so that we can recognize
		// whether it actually fit (rather than being truncated to 4095).
		std::vector<char> buf(4095 + 1);
		while (true) {
			ssize_t size = readlink(path.c_str(), &buf[0], buf.size());
			// Unrecoverable error?
			if (size == -1) return false;
			// It fit! (If size == buf.size(), it may have been truncated.)
			if (static_cast<size_t>(size) < buf.size()) {
				result->assign(&buf[0], size);
				return true;
			}
			// Double our buffer and try again.
			buf.resize(buf.size() * 2);
		}
	}
} // namespace android::base


std::unique_ptr<FileDescriptorInfo> FileDescriptorInfo::CreateFromFd(int fd, fail_fn_t fail_fn) {
	struct stat f_stat;
	// This should never happen; the zygote should always have the right set
	// of permissions required to stat all its open files.
	if (TEMP_FAILURE_RETRY(fstat(fd, &f_stat)) == -1) {
		fail_fn(android::base::StringPrintf("Unable to stat %d: %s", fd, strerror(errno)));
		return {};
	}
	if (S_ISSOCK(f_stat.st_mode)) {
		return std::unique_ptr<FileDescriptorInfo>(new FileDescriptorInfo(fd));
	}
	// We only handle allowlisted regular files and character devices. Allowlisted
	// character devices must provide a guarantee of sensible behaviour when
	// reopened.
	//
	// S_ISDIR : Not supported. (We could if we wanted to, but it's unused).
	// S_ISLINK : Not supported.
	// S_ISBLK : Not supported.
	// S_ISFIFO : Not supported. Note that the Zygote and USAPs use pipes to
	// communicate with the child processes across forks but those should have been
	// added to the redirection exemption list.
	if (!S_ISCHR(f_stat.st_mode) && !S_ISREG(f_stat.st_mode)) {
		std::string mode = "Unknown";
		if (S_ISDIR(f_stat.st_mode)) {
			mode = "DIR";
		} else if (S_ISLNK(f_stat.st_mode)) {
			mode = "LINK";
		} else if (S_ISBLK(f_stat.st_mode)) {
			mode = "BLOCK";
		} else if (S_ISFIFO(f_stat.st_mode)) {
			mode = "FIFO";
		}
		fail_fn(android::base::StringPrintf("Unsupported st_mode for FD %d:  %d(%s)", fd, f_stat.st_mode, mode.c_str()));
		return {};
	}
	std::string file_path;
	const std::string fd_path = android::base::StringPrintf("/proc/self/fd/%d", fd);
	if (!android::base::Readlink(fd_path, &file_path)) {
		fail_fn(android::base::StringPrintf("Could not read fd link %s: %s",
											fd_path.c_str(),
											strerror(errno)));
		return {};
	}
	// File descriptor flags : currently on FD_CLOEXEC. We can set these
	// using F_SETFD - we're single threaded at this point of execution so
	// there won't be any races.
	const int fd_flags = TEMP_FAILURE_RETRY(fcntl(fd, F_GETFD));
	if (fd_flags == -1) {
		fail_fn(android::base::StringPrintf("Failed fcntl(%d, F_GETFD) (%s): %s",
											fd,
											file_path.c_str(),
											strerror(errno)));
		return {};
	}
	// File status flags :
	// - File access mode : (O_RDONLY, O_WRONLY...) we'll pass these through
	//   to the open() call.
	//
	// - File creation flags : (O_CREAT, O_EXCL...) - there's not much we can
	//   do about these, since the file has already been created. We shall ignore
	//   them here.
	//
	// - Other flags : We'll have to set these via F_SETFL. On linux, F_SETFL
	//   can only set O_APPEND, O_ASYNC, O_DIRECT, O_NOATIME, and O_NONBLOCK.
	//   In particular, it can't set O_SYNC and O_DSYNC. We'll have to test for
	//   their presence and pass them in to open().
	int fs_flags = TEMP_FAILURE_RETRY(fcntl(fd, F_GETFL));
	if (fs_flags == -1) {
		fail_fn(android::base::StringPrintf("Failed fcntl(%d, F_GETFL) (%s): %s",
											fd,
											file_path.c_str(),
											strerror(errno)));
		return {};
	}
	// File offset : Ignore the offset for non seekable files.
	const off_t offset = TEMP_FAILURE_RETRY(lseek64(fd, 0, SEEK_CUR));
	// We pass the flags that open accepts to open, and use F_SETFL for
	// the rest of them.
	static const int kOpenFlags = (O_RDONLY | O_WRONLY | O_RDWR | O_DSYNC | O_SYNC);
	int open_flags = fs_flags & (kOpenFlags);
	fs_flags = fs_flags & (~(kOpenFlags));
	return std::unique_ptr<FileDescriptorInfo>(
			new FileDescriptorInfo(f_stat, file_path, fd, open_flags, fd_flags, fs_flags, offset));
}

bool FileDescriptorInfo::RefersToSameFile() const {
	struct stat f_stat;
	if (TEMP_FAILURE_RETRY(fstat(fd, &f_stat)) == -1) {
		return false;
	}
	return f_stat.st_ino == stat.st_ino && f_stat.st_dev == stat.st_dev;
}

void FileDescriptorInfo::Detach(fail_fn_t fail_fn) const {
    const int dev_null_fd = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR | O_CLOEXEC));
    if (dev_null_fd < 0) {
        fail_fn(android::base::StringPrintf("Failed to open /dev/null: %s", strerror(errno)));
        return;
    }

    if (TEMP_FAILURE_RETRY(dup3(dev_null_fd, fd, O_CLOEXEC)) == -1) {
        fail_fn(android::base::StringPrintf("Failed dup3 on descriptor %d to /dev/null: %s",
                                            fd,
                                            strerror(errno)));
        // close(dev_null_fd) should still be attempted
    }

    if (TEMP_FAILURE_RETRY(close(dev_null_fd)) == -1) {
        fail_fn(android::base::StringPrintf("Failed close(/dev/null temp fd %d): %s", dev_null_fd, strerror(errno)));
    }
}

void FileDescriptorInfo::ReopenOrDetach(fail_fn_t fail_fn, bool prefer_detach_to_dev_null) const {
    if (is_sock) {
        // Sockets are always "detached" by replacing their FD with /dev/null.
        return Detach(fail_fn);
    }

    // For non-sockets:
    if (prefer_detach_to_dev_null) {
        return Detach(fail_fn);
    }

    // Original logic for reopening regular files if not detaching.
	// NOTE: This might happen if the file was unlinked after being opened.
	// It's a common pattern in the case of temporary files and the like but
	// we should not allow such usage from the zygote.
	const int new_fd = TEMP_FAILURE_RETRY(open(file_path.c_str(), open_flags));
	if (new_fd == -1) {
		fail_fn(android::base::StringPrintf("Failed open(%s, %i): %s",
											file_path.c_str(),
											open_flags,
											strerror(errno)));
		return;
	}
	if (TEMP_FAILURE_RETRY(fcntl(new_fd, F_SETFD, fd_flags)) == -1) {
		close(new_fd);
		fail_fn(android::base::StringPrintf("Failed fcntl(%d, F_SETFD, %d) (%s): %s",
											new_fd,
											fd_flags,
											file_path.c_str(),
											strerror(errno)));
		return;
	}
	if (TEMP_FAILURE_RETRY(fcntl(new_fd, F_SETFL, fs_flags)) == -1) {
		close(new_fd);
		fail_fn(android::base::StringPrintf("Failed fcntl(%d, F_SETFL, %d) (%s): %s",
											new_fd,
											fs_flags,
											file_path.c_str(),
											strerror(errno)));
		return;
	}
	if (offset != -1 && TEMP_FAILURE_RETRY(lseek64(new_fd, offset, SEEK_SET)) == -1) {
		close(new_fd);
		fail_fn(android::base::StringPrintf("Failed lseek64(%d, %jd, SEEK_SET) (%s): %s",
											new_fd,
                                            (intmax_t)offset,
											file_path.c_str(),
											strerror(errno)));
		return;
	}
	int dup_flags = (fd_flags & FD_CLOEXEC) ? O_CLOEXEC : 0;
	if (TEMP_FAILURE_RETRY(dup3(new_fd, fd, dup_flags)) == -1) {
		close(new_fd);
		fail_fn(android::base::StringPrintf("Failed dup3(%d, %d, %d) (%s): %s",
											new_fd, // Corrected order: new_fd, fd
											fd,
											dup_flags,
											file_path.c_str(),
											strerror(errno)));
		return;
	}
	close(new_fd);
}

FileDescriptorInfo::FileDescriptorInfo(int fd) :
		fd(fd),
		stat(),
		open_flags(0),
		fd_flags(0),
		fs_flags(0),
		offset(0),
		is_sock(true) {
}
FileDescriptorInfo::FileDescriptorInfo(struct stat stat, const std::string& file_path,
									   int fd, int open_flags, int fd_flags, int fs_flags,
									   off_t offset) :
		fd(fd),
		stat(stat),
		file_path(file_path),
		open_flags(open_flags),
		fd_flags(fd_flags),
		fs_flags(fs_flags),
		offset(offset),
		is_sock(false) {
}

bool FileDescriptorInfo::GetSocketName(std::string* result) {
	sockaddr_storage ss;
	sockaddr* addr = reinterpret_cast<sockaddr*>(&ss);
	socklen_t addr_len = sizeof(ss);
	if (TEMP_FAILURE_RETRY(getsockname(fd, addr, &addr_len)) == -1) {
		return false;
	}
	if (addr->sa_family != AF_UNIX) {
		return false;
	}
	const sockaddr_un* unix_addr = reinterpret_cast<const sockaddr_un*>(&ss);
	size_t path_len = addr_len - offsetof(struct sockaddr_un, sun_path);
	// This is an unnamed local socket, we do not accept it.
	if (path_len == 0) {
		return false;
	}
	// This is a local socket with an abstract address. Remove the leading NUL byte and
	// add a human-readable "ABSTRACT/" prefix.
	if (unix_addr->sun_path[0] == '\0') {
		*result = "ABSTRACT/";
		result->append(&unix_addr->sun_path[1], path_len - 1);
		return true;
	}
	// If we're here, sun_path must refer to a null terminated filesystem
	// pathname (man 7 unix). Remove the terminator before assigning it to an
	// std::string.
	if (unix_addr->sun_path[path_len - 1] ==  '\0') {
		--path_len;
	}
	result->assign(unix_addr->sun_path, path_len);
	return true;
}

// TODO: Move the definitions here and eliminate the forward declarations. They
// temporarily help making code reviews easier.
static int ParseFd(dirent* dir_entry, int dir_fd);

std::unique_ptr<std::set<int>> GetOpenFds(fail_fn_t fail_fn) {
	DIR* proc_fd_dir = opendir(kFdPath);
	if (proc_fd_dir == nullptr) {
		fail_fn(android::base::StringPrintf("Unable to open directory %s: %s",
											kFdPath,
											strerror(errno)));
        return nullptr; // Return nullptr on error
	}
	auto result = std::make_unique<std::set<int>>();
	int dir_fd = dirfd(proc_fd_dir);
	dirent* dir_entry;
	while ((dir_entry = readdir(proc_fd_dir)) != nullptr) {
		const int fd = ParseFd(dir_entry, dir_fd);
		if (fd == -1) {
			continue;
		}

		result->insert(fd);
	}
	if (closedir(proc_fd_dir) == -1) {
		fail_fn(android::base::StringPrintf("Unable to close directory: %s", strerror(errno)));
        	}
	return result;
}

static int ParseFd(dirent* dir_entry, int dir_fd) {
	char* end;
	const int fd = strtol(dir_entry->d_name, &end, 10);
	if ((*end) != '\0') {
		return -1;
	}
	// Don't bother with the standard input/output/error, they're handled
	// specially post-fork anyway.
	if (fd <= STDERR_FILENO || fd == dir_fd) {
		return -1;
	}
	return fd;
}
