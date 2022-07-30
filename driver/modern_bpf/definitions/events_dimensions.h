/*
 * Copyright (C) 2022 The Falco Authors.
 *
 * This file is dual licensed under either the MIT or GPL 2. See MIT.txt
 * or GPL2.txt for full copies of the license.
 */

#ifndef __EVENT_DIMENSIONS_H__
#define __EVENT_DIMENSIONS_H__

#include "vmlinux.h"

/* Here we have all the dimensions for fixed-size events.
 */

#define PARAM_LEN 2
#define HEADER_LEN sizeof(struct ppm_evt_hdr)

/// TODO: We have to move these in the event_table.c. Right now we don't
/// want to touch scap tables.
#define MKDIR_E_SIZE HEADER_LEN + sizeof(uint32_t) + PARAM_LEN
#define OPEN_BY_HANDLE_AT_E_SIZE HEADER_LEN
#define EVENTFD_E_SIZE HEADER_LEN + sizeof(uint64_t) + sizeof(uint32_t) + PARAM_LEN * 2
#define EVENTFD_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define INOTIFY_INIT_E_SIZE HEADER_LEN + sizeof(uint8_t) + PARAM_LEN
#define INOTIFY_INIT_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define TIMERFD_CREATE_E_SIZE HEADER_LEN + sizeof(uint8_t) * 2 + PARAM_LEN * 2
#define TIMERFD_CREATE_X_SIZE HEADER_LEN + sizeof(int64_t) + PARAM_LEN
#define USERFAULTFD_E_SIZE HEADER_LEN
#define USERFAULTFD_X_SIZE HEADER_LEN + sizeof(int64_t) + sizeof(uint32_t) + PARAM_LEN * 2

#endif /* __EVENT_DIMENSIONS_H__ */
