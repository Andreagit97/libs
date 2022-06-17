#pragma once

#include <helpers/base/maps_getters.h>
#include <helpers/base/read_from_task.h>
#include <ppm_flag_helpers.h>

/* Used to convert from page number to KB. */
#define DO_PAGE_SHIFT(x) (x) << (IOC_PAGE_SHIFT - 10)

/* Macro defined by us to simply capabilities extraction. */
#define EXTRACT_CAP_INHERITABLE 0
#define EXTRACT_CAP_PERMITTED 1
#define EXTRACT_CAP_EFFECTIVE 2

/* All the functions that are called in bpf to extract parameters
 * start with the `extract` prefix.
 */

/////////////////////////
// GENERIC EXTRACTION
////////////////////////

/**
 * @brief Extract `len_to_read` bytes from the pointer.
 *
 * The `dest` pointer usually is the stack or the auxmap.
 * If it is the auxmap we don't have to increment the payload_pos
 * since we are using the map as a scratch space!
 *
 * Please note: in case of failure the content of `dest` is not
 * changed so we don't have to manage the return value, we have only
 * to pass an empty value by default
 *
 * @param dest pointer to the destination buffer.
 * @param len_to_read number of bytes to be read.
 * @param src pointer to the source buffer.
 * @return return code of `bpf_probe_read`
 */
static __always_inline int extract__bytebuf_from_pointer(void *dest, unsigned long len_to_read, void *src)
{
	return bpf_probe_read(dest, SAFE_ACCESS(len_to_read), src);
}

///////////////////////////
// ENCODE DEVICE NUMBER
///////////////////////////

/**
 * @brief Encode device number with `MAJOR` and `MINOR` MACRO.
 *
 * Please note: **Used only inside this file**.
 *
 * @param dev device number extracted directly from the kernel.
 * @return unsigned long encoded device number.
 */
static __always_inline unsigned long encode_dev(dev_t dev)
{
	unsigned int major = MAJOR(dev);
	unsigned int minor = MINOR(dev);

	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

///////////////////////////
// FILE EXTRACION
///////////////////////////

/**
 * @brief Return `file` struct from a file descriptor.
 *
 * @param file_descriptor generic file descriptor.
 * @return struct file* pointer to the`struct file` associated with the
 * file descriptor. Return a NULL pointer in case of failure.
 */
static __always_inline struct file *extract__file_struct_from_fd(int file_descriptor)
{
	struct file *f = NULL;
	if(file_descriptor > 0)
	{
		struct file **fds;
		struct task_struct *task = get_current_task();
		READ_TASK_FIELD_INTO(&fds, task, files, fdt, fd);
		bpf_probe_read_kernel(&f, sizeof(struct file *), &fds[file_descriptor]);
	}
	return f;
}

/**
 * @brief Extract the fd rlimit
 *
 * @param task pointer ot the task struct.
 * @param fdlimit return value passed by reference.
 */
static __always_inline void extract__fdlimit(struct task_struct *task, unsigned long *fdlimit)
{
	READ_TASK_FIELD_INTO(fdlimit, task, signal, rlim[RLIMIT_NOFILE].rlim_cur);
}

/**
 * \brief Extract the device number from a file descriptor.
 *
 * @param fd generic file descriptor.
 * @return Return the device numbr encoded as an unsigned long.
 */
static __always_inline unsigned long extract__dev_from_fd(s32 fd)
{
	dev_t kdev = 0;
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f)
	{
		return 0;
	}
	BPF_CORE_READ_INTO(&kdev, f, f_inode, i_sb, s_dev);
	return encode_dev(kdev);
}

/**
 * \brief Extract the inode number from a file descriptor.
 *
 * @param fd generic file descriptor.
 * @return Return the inode as a 64 unsigned int.
 */
static __always_inline u64 extract__ino_from_fd(s32 fd)
{
	u64 ino = 0;
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f)
	{
		return 0;
	}

	BPF_CORE_READ_INTO(&ino, f, f_inode, i_ino);
	return ino;
}

///////////////////////////
// CHARBUF EXTRACION
///////////////////////////

/**
 * @brief Extract a specif charbuf pointer from an array of charbuf pointers
 * using `index`.
 *
 * Please note: Here we don't care about the result of `bpf_probe_read()`
 * if we obtain a not-valid pointer we will manage it in the caller
 * functions.
 *
 * @param array charbuf pointers array.
 * @param index index at which we want to extract the charbuf pointer.
 * @return unsigned long return the extracted charbuf pointer or an invalid pointer in
 * case of failure.
 */
static __always_inline unsigned long extract__charbuf_pointer_from_array(unsigned long array, u16 index)
{
	char **charbuf_array = (char **)array;
	char *charbuf_pointer = NULL;
	bpf_probe_read(&charbuf_pointer, sizeof(charbuf_pointer), &charbuf_array[index]);
	return (unsigned long)charbuf_pointer;
}

/////////////////////////
// SYSCALL ARGUMENTS EXTRACION
////////////////////////

/**
 * @brief Extact a specific syscall argument
 *
 * @param regs pointer to the strcut where we find the arguments
 * @param idx index of the argument to extract
 * @return generic unsigned long value that can be a pointer to the arg
 * or directly the value, it depends on the type of arg.
 */
static __always_inline unsigned long extract__syscall_argument(struct pt_regs *regs, int idx)
{
	unsigned long arg;
	switch(idx)
	{
	case 0:
		arg = PT_REGS_PARM1_CORE_SYSCALL(regs);
		break;
	case 1:
		arg = PT_REGS_PARM2_CORE_SYSCALL(regs);
		break;
	case 2:
		arg = PT_REGS_PARM3_CORE_SYSCALL(regs);
		break;
	case 3:
		arg = PT_REGS_PARM4_CORE_SYSCALL(regs);
		break;
	case 4:
		arg = PT_REGS_PARM5_CORE_SYSCALL(regs);
		break;
	case 5:
		/* Not defined in libbpf, look at `definitions_helpers.h` */
		arg = PT_REGS_PARM6_CORE_SYSCALL(regs);
		break;
	default:
		arg = 0;
	}

	return arg;
}

/////////////////////////
// PIDS EXTRACION
////////////////////////

/**
 * @brief Return the pid struct according to the pid type chosen.
 *
 * @param task pointer to the task struct.
 * @param type pid type.
 * @return struct pid * pointer to the right pid struct.
 */
static __always_inline struct pid *extract__task_pid_struct(struct task_struct *task, enum pid_type type)
{
	struct pid *task_pid;
	switch(type)
	{
	/* we cannot take this info from signal struct. */
	case PIDTYPE_PID:
		READ_TASK_FIELD_INTO(&task_pid, task, thread_pid);
		break;
	default:
		READ_TASK_FIELD_INTO(&task_pid, task, signal, pids[type]);
		break;
	}
	return task_pid;
}

/**
 * @brief Returns the pid namespace in which the specified pid was allocated.
 *
 * @param pid pointer to the task pid struct.
 * @return struct pid_namespace* in which the specified pid was allocated.
 */
static __always_inline struct pid_namespace *extract__namespace_of_pid(struct pid *pid)
{
	u32 level;
	struct pid_namespace *ns = NULL;
	if(pid)
	{
		BPF_CORE_READ_INTO(&level, pid, level);
		BPF_CORE_READ_INTO(&ns, pid, numbers[level].ns);
	}
	return ns;
}

/**
 * @brief extract the xid (where x can be 'pid', 'tgid', ...) according to the
 * two structures passed as parameters.
 *
 *
 * @param pid pointer to the pid struct.
 * @param ns pointer to the namespace struct.
 * @return pid_t id seen from the pid namespace 'ns'.
 */
static __always_inline pid_t extract__xid_nr_seen_by_namespace(struct pid *pid, struct pid_namespace *ns)
{
	struct upid upid;
	pid_t nr = 0;
	unsigned int pid_level;
	unsigned int ns_level;
	BPF_CORE_READ_INTO(&pid_level, pid, level);
	BPF_CORE_READ_INTO(&ns_level, ns, level);

	if(pid && ns_level <= pid_level)
	{
		BPF_CORE_READ_INTO(&upid, pid, numbers[ns_level]);
		if(upid.ns == ns)
		{
			nr = upid.nr;
		}
	}
	return nr;
}

/*
 * Definitions taken from `/include/linux/sched.h`.
 *
 * the helpers to get the task's different pids as they are seen
 * from various namespaces. In all these methods 'nr' stands for 'numeric'.
 *
 * extract_task_(X)id_nr()     : global id, i.e. the id seen from the init namespace;
 * extract_task_(X)id_vnr()    : virtual id, i.e. the id seen from the pid namespace of current.
 *
 */

/**
 * @brief Return the xid (where x can be `pid`, `tgid`, `ppid` ...) seen from the
 *  init namespace.
 *
 * @param task pointer to task struct.
 * @param type pid type.
 * @return pid_t xid seen from the init namespace.
 */
static __always_inline pid_t extract__task_xid_nr(struct task_struct *task, enum pid_type type)
{
	switch(type)
	{
	case PIDTYPE_PID:
		return READ_TASK_FIELD(task, pid);

	case PIDTYPE_TGID:
		return READ_TASK_FIELD(task, tgid);

	case PIDTYPE_PGID:
		return READ_TASK_FIELD(task, real_parent, pid);

	default:
		return 0;
	}
}

/**
 * @brief Return the xid (where x can be `pid`, `tgid`, `ppid` ...) seen from the
 *  pid namespace of current
 *
 * @param task pointer to task struct.
 * @param type pid type.
 * @return pid_t xid seen from the current task pid namespace.
 */
static __always_inline pid_t extract__task_xid_vnr(struct task_struct *task, enum pid_type type)
{
	struct pid *pid_struct = extract__task_pid_struct(task, type);
	struct pid_namespace *pid_namespace_struct = extract__namespace_of_pid(pid_struct);
	return extract__xid_nr_seen_by_namespace(pid_struct, pid_namespace_struct);
}

/////////////////////////
// PAGE INFO EXTRACION
////////////////////////

/**
 * @brief Extract major page fault number
 *
 * @param task pointer to task struct.
 * @param pgft_maj return value passed by reference.
 */
static __always_inline void extract__pgft_maj(struct task_struct *task, unsigned long *pgft_maj)
{
	READ_TASK_FIELD_INTO(pgft_maj, task, maj_flt);
}

/**
 * @brief Extract minor page fault number
 *
 * @param task pointer to task struct.
 * @param pgft_min return value passed by reference.
 */
static __always_inline void extract__pgft_min(struct task_struct *task, unsigned long *pgft_min)
{
	READ_TASK_FIELD_INTO(pgft_min, task, min_flt);
}

/**
 * @brief Extract total page size
 *
 * @param mm pointer to mm_struct.
 * @return number in KB
 */
static __always_inline unsigned long extract__vm_size(struct mm_struct *mm)
{
	unsigned long vm_pages = 0;
	BPF_CORE_READ_INTO(&vm_pages, mm, total_vm);
	return DO_PAGE_SHIFT(vm_pages);
}

/**
 * @brief Extract resident page size
 *
 * @param mm pointer to mm_struct.
 * @return number in KB
 */
static __always_inline unsigned long extract__vm_rss(struct mm_struct *mm)
{
	unsigned long file_pages = 0;
	unsigned long anon_pages = 0;
	unsigned long shmem_pages = 0;
	BPF_CORE_READ_INTO(&file_pages, mm, rss_stat.count[MM_FILEPAGES].counter);
	BPF_CORE_READ_INTO(&anon_pages, mm, rss_stat.count[MM_ANONPAGES].counter);
	BPF_CORE_READ_INTO(&shmem_pages, mm, rss_stat.count[MM_SHMEMPAGES].counter);
	return DO_PAGE_SHIFT(file_pages + anon_pages + shmem_pages);
}

/**
 * @brief Extract swap page size
 *
 * @param mm pointer to mm_struct.
 * @return number in KB
 */
static __always_inline unsigned long extract__vm_swap(struct mm_struct *mm)
{
	unsigned long swap_entries = 0;
	BPF_CORE_READ_INTO(&swap_entries, mm, rss_stat.count[MM_SWAPENTS].counter);
	return DO_PAGE_SHIFT(swap_entries);
}

/////////////////////////
// TTY EXTRACTION
////////////////////////

/**
 * @brief Extract encoded tty
 *
 * @param task pointer to task_struct.
 * @return encoded tty number
 */
static __always_inline u32 exctract__tty(struct task_struct *task)
{
	int index;
	int major;
	int minor_start;
	READ_TASK_FIELD_INTO(&index, task, signal, tty, index);
	READ_TASK_FIELD_INTO(&major, task, signal, tty, driver, major);
	READ_TASK_FIELD_INTO(&minor_start, task, signal, tty, driver, minor_start);
	return encode_dev(MKDEV(major, minor_start) + index);
}

/////////////////////////
// LOGINUID EXTRACTION
////////////////////////

/**
 * @brief Extract loginuid
 *
 * @param task pointer to task struct
 * @param loginuid return value by reference
 */
static __always_inline void extract__loginuid(struct task_struct *task, u32 *loginuid)
{
	READ_TASK_FIELD_INTO(loginuid, task, loginuid.val);
}

/////////////////////////
// CAPABILITIES EXTRACTION
////////////////////////

/**
 * @brief Extract capabilities
 *
 * Right now we support only 3 types of capabilities:
 * - cap_inheritable
 * - cap_permitted
 * - cap_effective
 *
 * To extract the specific capabilities use the macro defined by us
 * at the beginning of this file:
 * - EXTRACT_CAP_INHERITABLE
 * - EXTRACT_CAP_PERMITTED
 * - EXTRACT_CAP_EFFECTIVE
 *
 * @param task pointer to task struct
 * @param capability_type macro defined by us
 * @return capability value
 */
static __always_inline unsigned long extract__capability(struct task_struct *task, int capability_type)
{
	kernel_cap_t cap_struct;
	unsigned long capability;
	switch(capability_type)
	{
	case EXTRACT_CAP_INHERITABLE:
		READ_TASK_FIELD_INTO(&cap_struct, task, cred, cap_inheritable);
		break;
	case EXTRACT_CAP_PERMITTED:
		READ_TASK_FIELD_INTO(&cap_struct, task, cred, cap_permitted);
		break;
	case EXTRACT_CAP_EFFECTIVE:
		READ_TASK_FIELD_INTO(&cap_struct, task, cred, cap_effective);
		break;
	default:
		return 0;
		break;
	}

	/// TODO: capabilities_to_scap(((unsigned long)cap_struct.cap[1] << 32) | cap_struct.cap[0]);
	/// We need to return this instead of 0.
	return 0;
}

/////////////////////////
// EXTRACT CLONE FLAGS
////////////////////////

/**
 * @brief To extract clone flags we need to read some info in the kernel
 *
 * @param task pointer to the task struct.
 * @param flags internal flag representation.
 * @return scap flag representation.
 */
static __always_inline unsigned long extract__clone_flags(struct task_struct *task, unsigned long flags)
{
	unsigned long ppm_flags = clone_flags_to_scap(flags);
	struct pid *pid = extract__task_pid_struct(task, PIDTYPE_PID);
	struct pid_namespace *ns = extract__namespace_of_pid(pid);
	unsigned int ns_level;
	BPF_CORE_READ_INTO(&ns_level, ns, level);

	if(ns_level != 0)
	{
		flags |= PPM_CL_CHILD_IN_PIDNS;
	}
	else
	{
		struct pid_namespace *ns_children;
		READ_TASK_FIELD_INTO(&ns_children, task, nsproxy, pid_ns_for_children);

		if(ns_children != ns)
		{
			flags |= PPM_CL_CHILD_IN_PIDNS;
		}
	}
	return ppm_flags;
}

/////////////////////////
// UID EXTRACTION
////////////////////////

/**
 * @brief Extract euid
 *
 * @param task pointer to task struct
 * @param euid return value by reference
 */
static __always_inline void extract__euid(struct task_struct *task, u32 *euid)
{
	READ_TASK_FIELD_INTO(euid, task, cred, euid.val);
}

/**
 * @brief Extract egid
 *
 * @param task pointer to task struct
 * @param euid return value by reference
 */
static __always_inline void extract__egid(struct task_struct *task, u32 *egid)
{
	READ_TASK_FIELD_INTO(egid, task, cred, egid.val);
}
