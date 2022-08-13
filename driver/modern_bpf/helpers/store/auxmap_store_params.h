/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#pragma once

#include <helpers/base/push_data.h>
#include <helpers/extract/extract_from_kernel.h>

/* Right now a cgroup pathname can have at most 6 components. */
#define MAX_CGROUP_PATH_POINTERS 6

/* Right now a file path extracted from a file descriptor can
 * have at most `MAX_PATH_POINTERS` components.
 */
#define MAX_PATH_POINTERS 8

/* Maximum number of charbuf pointers that we assume an array can have. */
#define MAX_CHARBUF_POINTERS 16

/* Concept of auxamp (auxiliary map):
 *
 * For variable size events we cannot directly reserve space into the ringbuf,
 * we need to use a bpf map as a temporary buffer to save our events. So every cpu
 * can use this temporary space when it receives a variable size event.
 *
 * This temporary space is represented as an `auxiliary map struct`. In
 * addition to the raw space (`data`) where we will save our event, there
 * are 2 integers placeholders that help us to understand in which part of
 * the buffer we are writing.
 *
 * struct auxiliary_map
 * {
 *	  u8 data[AUXILIARY_MAP_SIZE]; // raw space to save our variable-size event.
 *	  uint64_t payload_pos;	         // position of the first empty byte in the `data` buf.
 *	  uint8_t lengths_pos;	         // position the first empty slot into the lengths array of the event.
 * };
 *
 * To better understand the two indexes `payload_pos` and `lengths_pos`
 * please see the description of the event format in
 * `helpers/base/push_data.h`
 *
 * Please note: The auxiliary map can contain events of at most 64 KB,
 * but the `AUXILIARY_MAP_SIZE` is 128 KB. We have chosen this
 * size to make the verifier understand that there will always be
 * 64 KB free for a new event parameter. This allow us to easily
 * write data into the map without many extra checks.
 *
 * Look at the macro `SAFE_ACCESS(x)` defined in `helpers/base/push_data.h`.
 * If `payload_pos` is lower than `MAX_PARAM_SIZE` we use this index to write
 * new bytes, otherwise we use `payload_pos & MAX_PARAM_SIZE` as index. So
 * the index will be always lower than `MAX_PARAM_SIZE`!
 *
 * Please note that in this last case we are actually overwriting our event!
 * Using `payload_pos & MAX_PARAM_SIZE` as index means that we have already
 * written at least `MAX_PARAM_SIZE` so we are overwriting our data. This is
 * not an issue! If we have already written more than `MAX_PARAM_SIZE`, the
 * event size will be surely greather than 64 KB, so at the end of the collection
 * phase the entire event will be discarded!
 */

/////////////////////////////////
// GET AUXILIARY MAP
////////////////////////////////

/**
 * @brief Get the auxiliary map pointer for the current CPU.
 *
 * @return pointer to the auxmap
 */
static __always_inline struct auxiliary_map *auxmap__get()
{
	return maps__get_auxiliary_map();
}

/////////////////////////////////
// STORE EVENT HEADER INTO THE AUXILIARY MAP
////////////////////////////////

/**
 * @brief Push the event header inside the auxiliary map.
 *
 * Please note: we call this method `preload` since we cannot completely fill the
 * event header. When we call this method we don't know yet the overall size of
 * the event, we discover it only at the end of the collection phase. We have
 * to use the `auxmap__finalize_event_header` to "finalize" the header, inserting
 * also the total event length.
 *
 * @param auxmap pointer to the auxmap in which we are writing our event header.
 * @param event_type This is the type of the event that we are writing into the map.
 */
static __always_inline void auxmap__preload_event_header(struct auxiliary_map *auxmap, u16 event_type)
{
	struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)auxmap->data;
	u8 nparams = maps__get_event_num_params(event_type);
	hdr->ts = maps__get_boot_time() + bpf_ktime_get_boot_ns();
	hdr->tid = bpf_get_current_pid_tgid() & 0xffffffff;
	hdr->type = event_type;
	hdr->nparams = nparams;
	auxmap->payload_pos = sizeof(struct ppm_evt_hdr) + nparams * sizeof(u16);
	auxmap->lengths_pos = sizeof(struct ppm_evt_hdr);
}

/**
 * @brief Finalize the header writing the overall event len.
 *
 * @param auxmap pointer to the auxmap in which we are writing our event header.
 */
static __always_inline void auxmap__finalize_event_header(struct auxiliary_map *auxmap)
{
	struct ppm_evt_hdr *hdr = (struct ppm_evt_hdr *)auxmap->data;
	hdr->len = auxmap->payload_pos;
}

/////////////////////////////////
// COPY EVENT FROM AUXMAP TO RINGBUF
////////////////////////////////

/**
 * @brief Copy the entire event from the auxiliary map to bpf ringbuf.
 * If the event is correctly copied in the ringbuf we increments the number
 * of events sent to userspace, otherwise we increment the dropped events.
 *
 * @param auxmap pointer to the auxmap in which we have already written the entire event.
 */
static __always_inline void auxmap__submit_event(struct auxiliary_map *auxmap)
{

	struct ringbuf_map *rb = maps__get_ringbuf_map();
	if(!rb)
	{
		return;
	}

	struct counter_map *counter = maps__get_counter_map();
	if(!counter)
	{
		return;
	}

	if(auxmap->payload_pos > MAX_EVENT_SIZE)
	{
		counter->n_drops_max_event_size++;
		return;
	}

	/* `BPF_RB_NO_WAKEUP` means that we don't send to userspace a notification
	 *  when a new event is in the buffer.
	 */
	int err = bpf_ringbuf_output(rb, auxmap->data, auxmap->payload_pos, BPF_RB_NO_WAKEUP);
	if(err)
	{
		counter->n_drops_buffer++;
	}
	else
	{
		counter->n_evts++;
	}
}

/////////////////////////////////
// STORE EVENT PARAMS INTO THE AUXILIARY MAP
////////////////////////////////

/* All these `auxmap__store_(x)_param` helpers have the task
 * to store a particular param inside the bpf auxiliary map.
 * Note: `push__` functions store only some bytes into the map
 * and increment the payload pos. To store an entire param
 * we could need one or more `push__` helpers and one final `push__param_len`
 * to save the overall param len into the `lengths_array` seen into
 * `helpers/base/push_data.h` file.
 */

/**
 * @brief This function must be used when we are not able to correctly
 * collect the param. We simply put the param length to 0 into the
 * `lengths_array` of the event, so the userspace can easely understand
 * that the param is empty.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 */
static __always_inline void auxmap__store_empty_param(struct auxiliary_map *auxmap)
{
	push__param_len(auxmap->data, &auxmap->lengths_pos, 0);
}

/**
 * @brief This helper should be used to store signed 32 bit params.
 * The following types are compatible with this helper:
 * - PT_INT32
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_s32_param(struct auxiliary_map *auxmap, s32 param)
{
	push__s32(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(s32));
}

/**
 * @brief This helper should be used to store signed 64 bit params.
 * The following types are compatible with this helper:
 * - PT_INT64
 * - PT_ERRNO
 * - PT_PID
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_s64_param(struct auxiliary_map *auxmap, s64 param)
{
	push__s64(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(s64));
}

/**
 * @brief This helper should be used to store unsigned 8 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT8
 * - PT_SIGTYPE
 * - PT_FLAGS8
 * - PT_ENUMFLAGS8
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_u8_param(struct auxiliary_map *auxmap, u8 param)
{
	push__u8(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u8));
}

/**
 * @brief This helper should be used to store unsigned 32 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT32
 * - PT_UID
 * - PT_GID
 * - PT_SIGSET
 * - PT_MODE
 * - PT_FLAGS32
 * - PT_ENUMFLAGS32
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_u32_param(struct auxiliary_map *auxmap, u32 param)
{
	push__u32(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u32));
}

/**
 * @brief This helper should be used to store unsigned 64 bit params.
 * The following types are compatible with this helper:
 * - PT_UINT64
 * - PT_RELTIME
 * - PT_ABSTIME
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param param param to store
 */
static __always_inline void auxmap__store_u64_param(struct auxiliary_map *auxmap, u64 param)
{
	push__u64(auxmap->data, &auxmap->payload_pos, param);
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u64));
}

/**
 * @brief This helper stores the charbuf pointed by `charbuf_pointer`
 * into the auxmap. The charbuf can have a maximum length
 * of `MAX_PARAM_SIZE`. For more details, look at the underlying
 * `push__charbuf` method
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param charbuf_pointer pointer to the charbuf to store.
 * @param mem from which memory we need to read: user-space or kernel-space.
 * @return number of bytes read.
 */
static __always_inline u16 auxmap__store_charbuf_param(struct auxiliary_map *auxmap, unsigned long charbuf_pointer, enum read_memory mem)
{
	u16 charbuf_len = push__charbuf(auxmap->data, &auxmap->payload_pos, charbuf_pointer, MAX_PARAM_SIZE, mem);
	/* If we are not able to push anything with `push__charbuf`
	 * `charbuf_len` will be equal to `0` so we will send an
	 * empty param to userspace.
	 */
	push__param_len(auxmap->data, &auxmap->lengths_pos, charbuf_len);
	return charbuf_len;
}

/**
 * @brief This helper stores the bytebuf pointed by `bytebuf_pointer`
 * into the auxmap. The bytebuf has a fixed len `len_to_read`. If we
 * are not able to read exactly `len_to_read` bytes we will push an
 * empty param in the map, so param_len=0.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param bytebuf_pointer pointer to the bytebuf to store.
 * @param len_to_read number of bytes to read.
 * @param mem from which memory we need to read: user-space or kernel-space.
 * @return number of bytes read.
 */
static __always_inline u16 auxmap__store_bytebuf_param(struct auxiliary_map *auxmap, unsigned long bytebuf_pointer, unsigned long len_to_read, enum read_memory mem)
{
	u16 bytebuf_len = push__bytebuf(auxmap->data, &auxmap->payload_pos, bytebuf_pointer, len_to_read, mem);
	/* If we are not able to push anything with `push__bytebuf`
	 * `bytebuf_len` will be equal to `0` so we will send an
	 * empty param to userspace.
	 */
	push__param_len(auxmap->data, &auxmap->lengths_pos, bytebuf_len);
	return bytebuf_len;
}

/**
 * @brief Use `auxmap__store_single_charbuf_param_from_array` when
 * you have to store a charbuf from a charbuf pointer array.
 * You have to provide the index of the charbuf pointer inside the
 * array. Indexes start from '0' as usual.
 * Once we obtain the pointer with `extract__charbuf_pointer_from_array`,
 * we can store the charbuf with `auxmap__store_charbuf_param`.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param array charbuf pointer array.
 * @param index position at which we want to extract our charbuf.
 * @param mem from which memory we need to read: user-space or kernel-space.
 */
static __always_inline void auxmap__store_single_charbuf_param_from_array(struct auxiliary_map *auxmap, unsigned long array, u16 index, enum read_memory mem)
{
	unsigned long charbuf_pointer = extract__charbuf_pointer_from_array(array, index, mem);
	auxmap__store_charbuf_param(auxmap, charbuf_pointer, mem);
}

/**
 * @brief Use `auxmap__store_multiple_charbufs_param_from_array` when
 * you have to store multiple charbufs from a charbuf pointer
 * array. You have to provide an index that states where to start
 * the charbuf collection. If you want to store all the charbufs
 * pointed in the array, you can use '0' as 'index'.
 *
 * Please note: right now we assume that our arrays have no more
 * than `MAX_CHARBUF_POINTERS`
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param array charbuf pointer array
 * @param index position at which we start to collect our charbufs.
 * @param mem from which memory we need to read: user-space or kernel-space.
 */
static __always_inline void auxmap__store_multiple_charbufs_param_from_array(struct auxiliary_map *auxmap, unsigned long array, u16 index, enum read_memory mem)
{
	unsigned long charbuf_pointer;
	u16 charbuf_len = 0;
	u16 total_len = 0;
	/* We push in the auxmap all the charbufs that we find.
	 * We push the overall length only at the end of the
	 * for loop with `push__param_len`.
	 */
	for(; index < MAX_CHARBUF_POINTERS; ++index)
	{
		charbuf_pointer = extract__charbuf_pointer_from_array(array, index, mem);
		charbuf_len = push__charbuf(auxmap->data, &auxmap->payload_pos, charbuf_pointer, MAX_PARAM_SIZE, mem);
		if(!charbuf_len)
		{
			break;
		}
		total_len += charbuf_len;
	}
	push__param_len(auxmap->data, &auxmap->lengths_pos, total_len);
}

/**
 * @brief This helper stores the file path extracted from the `fd`.
 *
 * Please note: Kernel 5.10 introduced a new bpf_helper called `bpf_d_path`
 * to extract a file path starting from a file descriptor but it can be used only
 * with specific hooks:
 *
 * https://github.com/torvalds/linux/blob/e0dccc3b76fb35bb257b4118367a883073d7390e/kernel/trace/bpf_trace.c#L915-L929.
 *
 * So we need to do it by hand and this cause a limit in the max
 * path component that we can retrieve (MAX_PATH_POINTERS).
 *
 * This version of `auxmap__store_path_from_fd` works smooth on all
 * supported architectures: `s390x`, `ARM64`, `x86_64`.
 * The drawback is that due to its complexity we can catch at most
 * `MAX_PATH_POINTERS==8`.
 *
 * The previous version of this method was able to correctly catch paths
 * under different mount points, but not on `s390x` architecture, where
 * the userspace test `open_by_handle_atX_success_mp` failed.
 *
 * #@Andreagit97: reduce the complexity of this helper to allow the capture
 * of more path components, or enable only this version of the helper on `s390x`,
 * leaving the previous working version on `x86` and `aarch64` architectures.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param fd file descriptor from which we want to retrieve the file path.
 */
static __always_inline void auxmap__store_path_from_fd(struct auxiliary_map *auxmap, s32 fd)
{
	u16 total_size = 0;
	u8 path_components = 0;
	unsigned long path_pointers[MAX_PATH_POINTERS] = {0};
	struct file *f = extract__file_struct_from_fd(fd);
	if(!f)
	{
		push__param_len(auxmap->data, &auxmap->lengths_pos, total_size);
	}

	struct task_struct *t = get_current_task();
	struct dentry *file_dentry = BPF_CORE_READ(f, f_path.dentry);
	struct dentry *root_dentry = READ_TASK_FIELD(t, fs, root.dentry);
	struct vfsmount *original_mount = BPF_CORE_READ(f, f_path.mnt);
	struct mount *mnt = container_of(original_mount, struct mount, mnt);
	struct dentry *mount_dentry = BPF_CORE_READ(mnt, mnt.mnt_root);
	struct dentry *file_dentry_parent = NULL;
	struct mount *parent_mount = NULL;

	/* Here we store all the pointers, note that we don't take the pointer
	 * to the root so we will add it manually if it is necessary!
	 */
	for(int k = 0; k < MAX_PATH_POINTERS; ++k)
	{
		if(file_dentry == root_dentry)
		{
			break;
		}

		if(file_dentry == mount_dentry)
		{
			BPF_CORE_READ_INTO(&parent_mount, mnt, mnt_parent);
			BPF_CORE_READ_INTO(&file_dentry, mnt, mnt_mountpoint);
			mnt = parent_mount;
			BPF_CORE_READ_INTO(&mount_dentry, mnt, mnt.mnt_root);
			continue;
		}

		path_components++;
		BPF_CORE_READ_INTO(&path_pointers[k], file_dentry, d_name.name);
		BPF_CORE_READ_INTO(&file_dentry_parent, file_dentry, d_parent);
		file_dentry = file_dentry_parent;
	}

	/* Reconstruct the path in reverse, using previously collected pointers.
	 *
	 * 1. As a first thing, we have to add the root `/`.
	 *
	 * 2. When we read the string in BPF with `bpf_probe_read_str()` we always
	 * add the `\0` terminator. In this way, we will obtain something like this:
	 *
	 * - "path_1\0"
	 * - "path_2\0"
	 * - "file\0"
	 *
	 * So putting it all together:
	 *
	 * 	"/path_1\0path_2\0file\0"
	 *
	 * (Note that we added `/` manually so there is no `\0`)
	 *
	 * But we want to obtain something like this:
	 *
	 * 	"/path_1/path_2/file\0"
	 *
	 * To obtain it we can replace all `\0` with `/`, but in this way we
	 * obtain:
	 *
	 * 	"/path_1/path_2/file/"
	 *
	 * So we need to replace the last `/` with `\0`.
	 */

	/* 1. Push the root `/` */
	push__new_character(auxmap->data, &auxmap->payload_pos, '/');
	total_size += 1;

	for(int k = MAX_PATH_POINTERS - 1; k >= 0; --k)
	{
		if(path_pointers[k])
		{
			total_size += push__charbuf(auxmap->data, &auxmap->payload_pos, path_pointers[k], MAX_PARAM_SIZE, KERNEL);
			push__previous_character(auxmap->data, &auxmap->payload_pos, '/');
		}
	}

	/* Different cases:
	 * - `path_components==0` we have to add the last `\0`.
	 * - `path_components==1` we need to replace the last `/` with a `\0`.
	 * - `path_components>1` we need to replace the last `/` with a `\0`.
	 */
	if(path_components >= 1)
	{
		push__previous_character(auxmap->data, &auxmap->payload_pos, '\0');
	}
	else
	{
		push__new_character(auxmap->data, &auxmap->payload_pos, '\0');
		total_size += 1;
	}

	push__param_len(auxmap->data, &auxmap->lengths_pos, total_size);
}

/**
 * @brief Store ptrace addr param. This helper is used by ptrace syscall.
 *  This param is of type `PT_DYN` and it is composed of:
 * - 1 byte: a scap code that indicates how the ptrace addr param is sent to userspace.
 *   As in the old probe we send only params of type `PPM_PTRACE_IDX_UINT64`.
 * - 8 byte: the ptrace addr value sent as a `PT_UINT64`.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param ret return value to understand which action we have to perform.
 * @param addr_pointer pointer to the `addr` param taken from syscall registers.
 */
static __always_inline void auxmap__store_ptrace_addr_param(struct auxiliary_map *auxmap, long ret, u64 addr_pointer)
{
	push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);

	/* The syscall is failed. */
	if(ret < 0)
	{
		/* We push `0` in case of failure. */
		push__u64(auxmap->data, &auxmap->payload_pos, 0);
	}
	else
	{
		/* We send the addr pointer as a uint64_t */
		push__u64(auxmap->data, &auxmap->payload_pos, addr_pointer);
	}
	push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u8) + sizeof(u64));
}

/**
 * @brief Store ptrace data param. This helper is used by ptrace syscall.
 *  This param is of type `PT_DYN` and it is composed of:
 * - 1 byte: a scap code that indicates how the ptrace data param is sent to userspace.
 * - a variable size part according to the `ptrace_req`
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param ret return value to understand which action we have to perform.
 * @param ptrace_req ptrace request converted in the scap format.
 * @param data_pointer pointer to the `data` param taken from syscall registers.
 */
static __always_inline void auxmap__store_ptrace_data_param(struct auxiliary_map *auxmap, long ret, u16 ptrace_req, u64 data_pointer)
{
	/* The syscall is failed. */
	if(ret < 0)
	{
		/* We push `0` in case of failure. */
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);
		push__u64(auxmap->data, &auxmap->payload_pos, 0);
		push__param_len(auxmap->data, &auxmap->lengths_pos, sizeof(u8) + sizeof(u64));
		return;
	}

	u64 dest = 0;
	u16 total_size_to_push = sizeof(u8); /* 1 byte for the PPM type. */
	switch(ptrace_req)
	{
	case PPM_PTRACE_PEEKTEXT:
	case PPM_PTRACE_PEEKDATA:
	case PPM_PTRACE_PEEKUSR:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);
		bpf_probe_read_user((void *)&dest, sizeof(dest), (void *)data_pointer);
		push__u64(auxmap->data, &auxmap->payload_pos, dest);
		total_size_to_push += sizeof(u64);
		break;

	case PPM_PTRACE_CONT:
	case PPM_PTRACE_SINGLESTEP:
	case PPM_PTRACE_DETACH:
	case PPM_PTRACE_SYSCALL:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_SIGTYPE);
		push__u8(auxmap->data, &auxmap->payload_pos, data_pointer);
		total_size_to_push += sizeof(u8);
		break;

	case PPM_PTRACE_ATTACH:
	case PPM_PTRACE_TRACEME:
	case PPM_PTRACE_POKETEXT:
	case PPM_PTRACE_POKEDATA:
	case PPM_PTRACE_POKEUSR:
	default:
		push__u8(auxmap->data, &auxmap->payload_pos, PPM_PTRACE_IDX_UINT64);
		push__u64(auxmap->data, &auxmap->payload_pos, data_pointer);
		total_size_to_push += sizeof(u64);
		break;
	}
	push__param_len(auxmap->data, &auxmap->lengths_pos, total_size_to_push);
}

/**
 * @brief Store in the auxamp all data relative to a particular
 * `cgroup` subsystem. Data are stored in the following format:
 *
 * `cgroup_subsys_name=cgroup_path`
 *
 * Please note: This function is used only internally by `auxmap__store_cgroups_param`.
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param task pointer to the current task struct.
 * @param cgrp_sub_id enum taken from vmlinux `cgroup_subsys_id`.
 * @return total len written in the aux map for this `cgroup` subsystem.
 */
static __always_inline u16 store_cgroup_subsys(struct auxiliary_map *auxmap, struct task_struct *task, enum cgroup_subsys_id cgrp_sub_id)
{
	u16 total_size = 0;

	/* Write cgroup subsystem name + '=' into the aux map (example "cpuset="). */
	const char *cgroup_subsys_name_ptr;
	BPF_CORE_READ_INTO(&cgroup_subsys_name_ptr, task, cgroups, subsys[cgrp_sub_id], ss, name);
	/* This could be 0.*/
	total_size += push__charbuf(auxmap->data, &auxmap->payload_pos, (unsigned long)cgroup_subsys_name_ptr, MAX_PARAM_SIZE, KERNEL);
	if(!total_size)
	{
		return 0;
	}
	/* In BPF all strings are ended with `\0` so here we overwrite the
	 * `\0` at the end of the `cgroup` name with `=`.
	 */
	push__previous_character(auxmap->data, &auxmap->payload_pos, '=');

	/* Read all pointers to the path components. */
	struct kernfs_node *kn;
	BPF_CORE_READ_INTO(&kn, task, cgroups, subsys[cgrp_sub_id], cgroup, kn);
	unsigned long cgroup_path_pointers[MAX_CGROUP_PATH_POINTERS] = {0};
	u8 path_components = 0;

	for(int k = 0; k < MAX_CGROUP_PATH_POINTERS; ++k)
	{
		if(!kn)
		{
			break;
		}
		path_components++;
		BPF_CORE_READ_INTO(&cgroup_path_pointers[k], kn, name);
		BPF_CORE_READ_INTO(&kn, kn, parent);
	}

	/* Reconstruct the path in reverse, using previously collected pointers.
	 * The first component we face must be the root "/". Unfortunately,
	 * when we read the root component from `struct kernfs_node` we
	 * obtain only "\0" instead of "/\0" (NOTE: \0 is always present
	 * at the end of the string, reading with `bpf_probe_read_str()`).
	 *
	 * The rationale here is to replace the string terminator '\0'
	 * with the '/' for every path compotent, excluding the last.
	 *
	 * Starting from what we have already inserted ("cpuset="),
	 * we want to obtain as a final result:
	 *
	 *  cpuset=/path_part1/path_part2\0
	 *
	 * Without replacing with '/', we would obtain this:
	 *
	 *  cpuset=\0path_part1\0path_part2\0
	 *
	 * Replacing all '\0' with '/':
	 *
	 *  cpuset=/path_part1/path_part2/
	 *
	 * As a last step we want to replace the last `/` with
	 * again the string terminator `\0`, finally obtaining:
	 *
	 *  cpuset=/path_part1/path_part2\0
	 */
	for(int k = MAX_CGROUP_PATH_POINTERS - 1; k >= 0; --k)
	{
		if(cgroup_path_pointers[k])
		{
			total_size += push__charbuf(auxmap->data, &auxmap->payload_pos, cgroup_path_pointers[k], MAX_PARAM_SIZE, KERNEL);
			push__previous_character(auxmap->data, &auxmap->payload_pos, '/');
		}
	}

	/* As a result of this for loop we can have three cases:
	 *
	 *  1. cpuset=/path_part1/path_part2/
	 *
	 *  2. cpuset=/ (please note: the '/' is correct but we miss the final '\0')
	 *
	 *  3. cpuset= (path_components=0)
	 *
	 * So according to the case we have to perform different actions:
	 *
	 *  1. cpuset=/path_part1/path_part2\0 (overwrite last '/' with '\0').
	 *
	 *  2. cpuset=/\0 (add the terminator char).
	 *
	 *  3. cpuset=\0 (add the terminator char)
	 *
	 * We can treat the `2` and the `3` in the same way, adding a char terminator at the end.
	 */
	if(path_components <= 1)
	{
		push__new_character(auxmap->data, &auxmap->payload_pos, '\0');
		total_size += 1;
	}
	else
	{
		push__previous_character(auxmap->data, &auxmap->payload_pos, '\0');
	}

	return total_size;
}

/**
 * @brief Store in the auxamp all the `cgroup` subsystems currently supported:
 * - cpuset_cgrp_id
 * - cpu_cgrp_id
 * - cpuacct_cgrp_id
 * - io_cgrp_id
 * - memory_cgrp_id
 *
 * @param auxmap pointer to the auxmap in which we are storing the param.
 * @param task pointer to the current task struct.
 */
static __always_inline void auxmap__store_cgroups_param(struct auxiliary_map *auxmap, struct task_struct *task)
{
	uint16_t total_croups_len = 0;
	total_croups_len += store_cgroup_subsys(auxmap, task, cpuset_cgrp_id);
	total_croups_len += store_cgroup_subsys(auxmap, task, cpu_cgrp_id);
	total_croups_len += store_cgroup_subsys(auxmap, task, cpuacct_cgrp_id);
	total_croups_len += store_cgroup_subsys(auxmap, task, io_cgrp_id);
	total_croups_len += store_cgroup_subsys(auxmap, task, memory_cgrp_id);
	push__param_len(auxmap->data, &auxmap->lengths_pos, total_croups_len);
}
