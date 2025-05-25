#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <iostream>
#include <iomanip>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <vector>
#include <tuple>
#include <cstdint>
#include <sys/mman.h>
#include <link.h>
#include <sys/stat.h>

std::pair<dev_t, ino_t> devinobymap(const std::string& lib, bool useFind = false, unsigned int *ln = nullptr) {
	std::ifstream maps("/proc/self/maps");
	unsigned int index = 0;
	std::string line;
	std::string needle = "/" + lib;
	while (std::getline(maps, line)) {
		if (ln && index < *ln) {
			index++;
			continue;
		}
		if (line.size() >= needle.size() && ((useFind && line.find(needle) != std::string::npos) ||
			line.compare(line.size() - needle.size(), needle.size(), needle) == 0)) {
			std::istringstream iss(line);
			std::string addr, perms, offset, dev, inode_str;
			iss >> addr >> perms >> offset >> dev >> inode_str;
			std::istringstream devsplit(dev);
			std::string major_hex, minor_hex;
			if (std::getline(devsplit, major_hex, ':') &&
				std::getline(devsplit, minor_hex)) {
				int major = std::stoi(major_hex, nullptr, 16);
				int minor = std::stoi(minor_hex, nullptr, 16);
				dev_t devnum = makedev(major, minor);
				ino_t inode = std::stoul(inode_str);
				if (ln)
					*ln = index;
				return {devnum, inode};
			}
		}
		index++;
	}
	if (ln)
		*ln = -1;
	return {dev_t(0), ino_t(0)};
}

std::optional<std::pair<dev_t, ino_t>> devinoby(const char* lib) {
	struct State {
		const char* needle;
		std::optional<std::pair<dev_t, ino_t>> result;
	} state = { lib };

	dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
		auto* s = static_cast<State*>(data);
		if (info->dlpi_name && strstr(info->dlpi_name, s->needle)) {
			struct stat st{};
			if (stat(info->dlpi_name, &st) == 0) {
				s->result = std::make_pair(st.st_dev, st.st_ino);
				return 1; // Stop iteration
			}
		}
		return 0; // Continue
	}, &state);

	return state.result;
}

int forkcall(const std::function<int()> &lambda)
{
	pid_t pid = fork();
	if (pid == -1)
		return -1;
	if (pid == 0) {
		exit(lambda());
	} else {
		int status = -1;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		}
	}
	return -1;
}

static inline int seccomp(int op, int fd, void *arg) {
	return syscall(SYS_seccomp, op, fd, arg);
}

static int pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(SYS_pidfd_open, pid, flags);
}

static ssize_t process_vm_readv(pid_t pid,
								 const struct iovec *local_iov,
								 unsigned long liovcnt,
								 const struct iovec *remote_iov,
								 unsigned long riovcnt,
								 unsigned long flags)
{
	return syscall(SYS_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

static ssize_t process_vm_writev(pid_t pid,
								 const struct iovec *local_iov,
								 unsigned long liovcnt,
								 const struct iovec *remote_iov,
								 unsigned long riovcnt,
								 unsigned long flags)
{
	return syscall(SYS_process_vm_writev, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
}

bool switchnsto(pid_t pid) {
	int fd = pidfd_open(pid, 0);
	if (fd != -1) {
		int res = setns(fd, CLONE_NEWNS);
		close(fd);
		if (!res)
			return true;
		else {
			goto fallback;
		}
	}
	fallback:
	std::string path = "/proc/" + std::to_string(pid) + "/ns/mnt";
	fd = open(path.c_str(), O_RDONLY);
	if (fd != -1) {
		int res = setns(fd, CLONE_NEWNS);
		close(fd);
		return res == 0;
	}
	return false;
}

bool isuserapp(int uid) {
	int appid = uid % AID_USER_OFFSET;
	if (appid >= AID_APP_START && appid <= AID_APP_END)
		return true;
	if (appid >= AID_ISOLATED_START && appid <= AID_ISOLATED_END)
		return true;
	return false;
}

static int sendfd(int sockfd, int fd) {
	int data;
	struct iovec iov{};
	struct msghdr msgh{};
	struct cmsghdr *cmsgp;

	/* Allocate a char array of suitable size to hold the ancillary data.
	   However, since this buffer is in reality a 'struct cmsghdr', use a
	   union to ensure that it is suitably aligned. */
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		/* Space large enough to hold an 'int' */
		struct cmsghdr align;
	} controlMsg{};

	/* The 'msg_name' field can be used to specify the address of the
	   destination socket when sending a datagram. However, we do not
	   need to use this field because 'sockfd' is a connected socket. */

	msgh.msg_name = nullptr;
	msgh.msg_namelen = 0;

	/* On Linux, we must transmit at least one byte of real data in
	   order to send ancillary data. We transmit an arbitrary integer
	   whose value is ignored by recvfd(). */

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	iov.iov_base = &data;
	iov.iov_len = sizeof(int);
	data = 12345;

	/* Set 'msghdr' fields that describe ancillary data */

	msgh.msg_control = controlMsg.buf;
	msgh.msg_controllen = sizeof(controlMsg.buf);

	/* Set up ancillary data describing file descriptor to send */

	cmsgp = reinterpret_cast<cmsghdr *>(msgh.msg_control);
	cmsgp->cmsg_level = SOL_SOCKET;
	cmsgp->cmsg_type = SCM_RIGHTS;
	cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsgp), &fd, sizeof(int));

	/* Send real plus ancillary data */

	if (sendmsg(sockfd, &msgh, 0) == -1) return -1;

	return 0;
}

static int recvfd(int sockfd) {
	int data, fd;
	ssize_t nr;
	struct iovec iov{};
	struct msghdr msgh{};

	/* Allocate a char buffer for the ancillary data. See the comments
	   in sendfd() */
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} controlMsg{};
	struct cmsghdr *cmsgp;

	/* The 'msg_name' field can be used to obtain the address of the
	   sending socket. However, we do not need this information. */

	msgh.msg_name = nullptr;
	msgh.msg_namelen = 0;

	/* Specify buffer for receiving real data */

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	iov.iov_base = &data; /* Real data is an 'int' */
	iov.iov_len = sizeof(int);

	/* Set 'msghdr' fields that describe ancillary data */

	msgh.msg_control = controlMsg.buf;
	msgh.msg_controllen = sizeof(controlMsg.buf);

	/* Receive real plus ancillary data; real data is ignored */

	nr = recvmsg(sockfd, &msgh, 0);
	if (nr == -1) return -1;

	cmsgp = CMSG_FIRSTHDR(&msgh);

	/* Check the validity of the 'cmsghdr' */

	if (cmsgp == nullptr || cmsgp->cmsg_len != CMSG_LEN(sizeof(int)) ||
		cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type != SCM_RIGHTS) {
		errno = EINVAL;
		return -1;
	}

	/* Return the received file descriptor to our caller */

	memcpy(&fd, CMSG_DATA(cmsgp), sizeof(int));
	return fd;
}