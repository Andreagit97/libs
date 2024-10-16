// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif  // _WIN32

#include <libscap/scap.h>
#include <libscap/scap-int.h>

#include <libscap/strl.h>

//
// Get the event info table
//
const struct ppm_event_info *scap_get_event_info_table() {
	return g_event_info;
}

enum ppm_event_category scap_get_syscall_category_from_event(ppm_event_code ev) {
	ASSERT(ev < PPM_EVENT_MAX);
	return g_event_info[ev].category & (EC_SYSCALL - 1);
}

enum ppm_event_category scap_get_event_category_from_event(ppm_event_code ev) {
	ASSERT(ev < PPM_EVENT_MAX);
	return g_event_info[ev].category & ~(EC_SYSCALL - 1);
}

uint32_t scap_event_getlen(scap_evt *e) {
	return e->len;
}

uint64_t scap_event_get_num(scap_t *handle) {
	return handle->m_evtcnt;
}

uint64_t scap_event_get_ts(scap_evt *e) {
	return e->ts;
}

#ifdef PPM_ENABLE_SENTINEL
uint32_t scap_event_get_sentinel_begin(scap_evt *e) {
	return e->sentinel_begin;
}
#endif

const struct ppm_event_info *scap_event_getinfo(const scap_evt *e) {
	return &(g_event_info[e->type]);
}

uint32_t scap_event_has_large_payload(const scap_evt *e) {
	return (g_event_info[e->type].flags & EF_LARGE_PAYLOAD) != 0;
}

uint32_t scap_event_decode_params(const scap_evt *e, struct scap_sized_buffer *params) {
	char *len_buf = (char *)e + sizeof(struct ppm_evt_hdr);
	char *param_buf = len_buf;
	uint32_t is_large = scap_event_has_large_payload(e);
	uint32_t param_size_32;
	uint16_t param_size_16;

	const struct ppm_event_info *event_info = &(g_event_info[e->type]);

	// If we're reading a capture created with a newer version, it may contain
	// new parameters. If instead we're reading an older version, the current
	// event table entry may contain new parameters.
	// Use the minimum between the two values.
	uint32_t n = event_info->nparams < e->nparams ? event_info->nparams : e->nparams;

	if(is_large) {
		param_buf += sizeof(uint32_t) * e->nparams;
	} else {
		param_buf += sizeof(uint16_t) * e->nparams;
	}

	for(size_t i = 0; i < n; i++) {
		if(is_large) {
			memcpy(&param_size_32, len_buf, sizeof(uint32_t));
			params[i].size = param_size_32;
			len_buf += sizeof(uint32_t);
		} else {
			memcpy(&param_size_16, len_buf, sizeof(uint16_t));
			params[i].size = param_size_16;
			len_buf += sizeof(uint16_t);
		}

		params[i].buf = param_buf;
		param_buf += params[i].size;
	}

	return n;
}

void scap_event_set_param_length_regular(scap_evt *event, uint32_t n, uint16_t len) {
	memcpy((char *)event + sizeof(struct ppm_evt_hdr) + sizeof(uint16_t) * n,
	       &len,
	       sizeof(uint16_t));
}

void scap_event_set_param_length_large(scap_evt *event, uint32_t n, uint32_t len) {
	memcpy((char *)event + sizeof(struct ppm_evt_hdr) + sizeof(uint32_t) * n,
	       &len,
	       sizeof(uint32_t));
}

static inline int32_t scap_buffer_can_fit(struct scap_sized_buffer buf, size_t len) {
	return (buf.size >= len);
}

int32_t scap_event_encode_params(struct scap_sized_buffer event_buf,
                                 size_t *event_size,
                                 char *error,
                                 ppm_event_code event_type,
                                 uint32_t n,
                                 ...) {
	va_list args;
	va_start(args, n);
	int32_t ret = scap_event_encode_params_v(event_buf, event_size, error, event_type, n, args);
	va_end(args);

	return ret;
}

int32_t scap_event_encode_params_v(const struct scap_sized_buffer event_buf,
                                   size_t *event_size,
                                   char *error,
                                   ppm_event_code event_type,
                                   uint32_t n,
                                   va_list args) {
	scap_evt *event = NULL;

	const struct ppm_event_info *event_info = &g_event_info[event_type];

	// len_size is the size in bytes of an entry of the parameter length array
	size_t len_size = sizeof(uint16_t);
	if((event_info->flags & EF_LARGE_PAYLOAD) != 0) {
		len_size = sizeof(uint32_t);
	}

	n = event_info->nparams < n ? event_info->nparams : n;

	size_t len = sizeof(struct ppm_evt_hdr) + len_size * n;

	// every buffer write access needs to be guarded by a scap_buffer_can_fit call to check if it's
	// large enough
	if(scap_buffer_can_fit(event_buf, len)) {
		event = event_buf.buf;
		event->type = event_type;
		event->nparams = n;
		event->len = len;
	}

	for(int i = 0; i < n; i++) {
		const struct ppm_param_info *pi = &event_info->params[i];
		struct scap_const_sized_buffer param = {0};

		uint8_t u8_arg;
		uint16_t u16_arg;
		uint32_t u32_arg;
		uint64_t u64_arg;

		switch(pi->type) {
		case PT_INT8:
		case PT_UINT8:
		case PT_FLAGS8:
		case PT_SIGTYPE:
		case PT_L4PROTO:
		case PT_SOCKFAMILY:
		case PT_ENUMFLAGS8:
			u8_arg = (uint8_t)(va_arg(args, int) & 0xff);
			param.buf = &u8_arg;
			param.size = sizeof(uint8_t);
			break;

		case PT_INT16:
		case PT_UINT16:
		case PT_SYSCALLID:
		case PT_PORT:
		case PT_FLAGS16:
		case PT_ENUMFLAGS16:
			u16_arg = (uint16_t)(va_arg(args, int) & 0xffff);
			param.buf = &u16_arg;
			param.size = sizeof(uint16_t);
			break;

		case PT_INT32:
		case PT_UINT32:
		case PT_BOOL:
		case PT_IPV4ADDR:
		case PT_UID:
		case PT_GID:
		case PT_FLAGS32:
		case PT_SIGSET:
		case PT_MODE:
		case PT_ENUMFLAGS32:
		case PT_FD32:
			u32_arg = va_arg(args, uint32_t);
			param.buf = &u32_arg;
			param.size = sizeof(uint32_t);
			break;

		case PT_INT64:
		case PT_UINT64:
		case PT_ERRNO:
		case PT_FD:
		case PT_PID:
		case PT_RELTIME:
		case PT_ABSTIME:
		case PT_DOUBLE:
			u64_arg = va_arg(args, uint64_t);
			param.buf = &u64_arg;
			param.size = sizeof(uint64_t);
			break;

		case PT_CHARBUF:
		case PT_FSPATH:
		case PT_FSRELPATH:
			param.buf = va_arg(args, char *);
			if(param.buf == NULL) {
				param.size = 0;
			} else {
				param.size = strlen(param.buf) + 1;
			}
			break;

		case PT_BYTEBUF:      /* A raw buffer of bytes not suitable for printing */
		case PT_SOCKTUPLE:    /* A sockaddr tuple,1byte family + 12byte data + 12byte data */
		case PT_FDLIST:       /* A list of fds, 16bit count + count * (64bit fd + 16bit flags) */
		case PT_DYN:          /* Type can vary depending on the context. Used for filter fields like
		                         evt.rawarg. */
		case PT_CHARBUFARRAY: /* Pointer to an array of strings, exported by the user events
		                         decoder. 64bit. For internal use only. */
		case PT_CHARBUF_PAIR_ARRAY: /* Pointer to an array of string pairs, exported by the user
		                               events decoder. 64bit. For internal use only. */
		case PT_IPV4NET:            /* An IPv4 network. */
		case PT_IPV6ADDR:           /* A 16 byte raw IPv6 address. */
		case PT_IPV6NET:            /* An IPv6 network. */
		case PT_IPADDR: /* Either an IPv4 or IPv6 address. The length indicates which one it is. */
		case PT_IPNET:  /* Either an IPv4 or IPv6 network. The length indicates which one it is. */
		case PT_SOCKADDR:
			param = va_arg(args, struct scap_const_sized_buffer);
			break;

		case PT_NONE:
		case PT_MAX:
			break;  // Nothing to do
		default:    // Unsupported event
			ASSERT(false);
			snprintf(error,
			         SCAP_LASTERR_SIZE,
			         "event param %d (param type %d) is unsupported",
			         i,
			         pi->type);
			return SCAP_FAILURE;
		}

		uint16_t param_size_16;
		uint32_t param_size_32;

		switch(len_size) {
		case sizeof(uint16_t):
			param_size_16 = (uint16_t)(param.size & 0xffff);
			if(param_size_16 != param.size) {
				snprintf(
				        error,
				        SCAP_LASTERR_SIZE,
				        "could not fit event param %d size %zu for event with type %d in %zu bytes",
				        i,
				        param.size,
				        event->type,
				        len_size);
				return SCAP_FAILURE;
			}
			if(scap_buffer_can_fit(event_buf, len)) {
				scap_event_set_param_length_regular(event, i, param_size_16);
			}
			break;
		case sizeof(uint32_t):
			param_size_32 = (uint32_t)(param.size & 0xffffffff);
			if(param_size_32 != param.size) {
				snprintf(
				        error,
				        SCAP_LASTERR_SIZE,
				        "could not fit event param %d size %zu for event with type %d in %zu bytes",
				        i,
				        param.size,
				        event->type,
				        len_size);
				return SCAP_FAILURE;
			}
			if(scap_buffer_can_fit(event_buf, len)) {
				scap_event_set_param_length_large(event, i, param_size_32);
			}
			break;
		default:
			snprintf(error,
			         SCAP_LASTERR_SIZE,
			         "unexpected param %d length %zu for event with type %d",
			         i,
			         len_size,
			         event->type);
			return SCAP_FAILURE;
		}

		if(scap_buffer_can_fit(event_buf, len + param.size) && param.size != 0) {
			memcpy(((char *)event_buf.buf + len), param.buf, param.size);
		}
		len = len + param.size;
	}

#ifdef PPM_ENABLE_SENTINEL
	if(scap_buffer_can_fit(event_buf, len + sizeof(uint32_t))) {
		event->sentinel_begin = 0x01020304;
		memcpy(((char *)event_buf.buf + len), &event->sentinel_begin, sizeof(uint32_t));
	}
	len = len + sizeof(uint32_t);
#endif

	if(event_size != NULL) {
		*event_size = len;
	}

	// we were not able to write the event to the buffer
	if(!scap_buffer_can_fit(event_buf, len)) {
		snprintf(error,
		         SCAP_LASTERR_SIZE,
		         "Could not encode event of size %zu into supplied buffer sized %zu.",
		         len,
		         event_buf.size);
		return SCAP_INPUT_TOO_SMALL;
	}

	event->len = len;

	return SCAP_SUCCESS;
}

uint8_t scap_get_size_bytes_from_type(enum ppm_param_type t) {
	switch(t) {
	case PT_INT8:
	case PT_UINT8:
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
		return 1;

	case PT_INT16:
	case PT_UINT16:
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
	case PT_SYSCALLID:
		return 2;

	case PT_INT32:
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_UID:
	case PT_GID:
	case PT_MODE:
	case PT_FD32:
		return 4;

	case PT_INT64:
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		return 8;

	case PT_BYTEBUF:
	case PT_CHARBUF:
	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	case PT_CHARBUFARRAY:
	case PT_CHARBUF_PAIR_ARRAY:
	case PT_FSRELPATH:
	case PT_DYN:
		return 0;

	default:
		// We forgot to handle something
		ASSERT(false);
		break;
	}
	return 0;
}

/*=============================== PRINT EVENT PARAMS ===========================*/

// void print_ipv4(int starting_index) {
// 	char ipv4_string[50];
// 	uint8_t *ipv4 = (uint8_t *)(valptr + starting_index);
// 	snprintf(ipv4_string, sizeof(ipv4_string), "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
// 	printf("- ipv4: %s\n", ipv4_string);
// }

// void print_ipv6(int starting_index) {
// 	uint32_t ipv6[4] = {0, 0, 0, 0};
// 	ipv6[0] = *(uint32_t *)(valptr + starting_index);
// 	ipv6[1] = *(uint32_t *)(valptr + starting_index + 4);
// 	ipv6[2] = *(uint32_t *)(valptr + starting_index + 8);
// 	ipv6[3] = *(uint32_t *)(valptr + starting_index + 12);

// 	char ipv6_string[150];
// 	inet_ntop(AF_INET6, ipv6, ipv6_string, 150);
// 	printf("- ipv6: %s\n", ipv6_string);
// }

// void print_unix_path(int starting_index) {
// 	printf("- unix path: %s\n", (char *)(valptr + starting_index));
// }

// void print_port(int starting_index) {
// 	printf("- port: %d\n", *(uint16_t *)(valptr + starting_index));
// }

void print_parameter(int16_t num_param, scap_evt *ev) {
	uint16_t *lens16 = (uint16_t *)((char *)ev + sizeof(struct ppm_evt_hdr));
	char *valptr = (char *)lens16 + ev->nparams * sizeof(uint16_t);

	int16_t len = lens16[num_param];

	if(len == 0) {
		printf("PARAM %d: is empty\n", num_param);
		return;
	}

	switch(g_event_info[ev->type].params[num_param].type) {
	case PT_FLAGS8:
		printf("PARAM %d: %X\n", num_param, *(uint8_t *)(valptr));
		break;

	case PT_FLAGS16:
		printf("PARAM %d: %X\n", num_param, *(uint16_t *)(valptr));
		break;

	case PT_FLAGS32:
		printf("PARAM %d: %X\n", num_param, *(uint32_t *)(valptr));
		break;

	case PT_INT8:
		printf("PARAM %d: %d\n", num_param, *(int8_t *)(valptr));
		break;

	case PT_INT16:
		printf("PARAM %d: %d\n", num_param, *(int16_t *)(valptr));
		break;

	case PT_INT32:
		printf("PARAM %d: %d\n", num_param, *(int32_t *)(valptr));
		break;

	case PT_INT64:
	case PT_ERRNO:
	case PT_PID:
		printf("PARAM %d: %ld\n", num_param, *(int64_t *)(valptr));
		break;

	case PT_UINT8:
	case PT_SIGTYPE:
	case PT_ENUMFLAGS8:
		printf("PARAM %d: %d\n", num_param, *(uint8_t *)(valptr));
		break;

	case PT_UINT16:
	case PT_SYSCALLID:
	case PT_ENUMFLAGS16:
		printf("PARAM %d: %d\n", num_param, *(uint16_t *)(valptr));
		break;

	case PT_UINT32:
	case PT_UID:
	case PT_GID:
	case PT_SIGSET:
	case PT_MODE:
	case PT_ENUMFLAGS32:
		printf("PARAM %d: %d\n", num_param, *(uint32_t *)(valptr));
		break;

	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
		printf("PARAM %d: %lu\n", num_param, *(uint64_t *)(valptr));
		break;

	case PT_FD:
		printf("PARAM %d: %d\n", num_param, *(int32_t *)(valptr));
		break;

		// case PT_SOCKADDR: {
		// 	printf("PARAM %d:\n", num_param);
		// 	uint8_t sock_family = *(uint8_t *)(valptr);
		// 	printf("- sock_family: %d\n", sock_family);
		// 	switch(sock_family) {
		// 	case PPM_AF_INET:
		// 		/* ipv4 dest. */
		// 		print_ipv4(1);

		// 		/* port dest. */
		// 		print_port(5);
		// 		break;

		// 	case PPM_AF_INET6:
		// 		/* ipv6 dest. */
		// 		print_ipv6(1);

		// 		/* port dest. */
		// 		print_port(17);
		// 		break;

		// 	case PPM_AF_UNIX:
		// 		/* unix_path. */
		// 		print_unix_path(1);
		// 		break;

		// 	default:
		// 		printf("-  error\n");
		// 		break;
		// 	}
		// 	break;
		// }

		// case PT_SOCKTUPLE: {
		// 	printf("PARAM %d:\n", num_param);
		// 	uint8_t sock_family = *(uint8_t *)(valptr);
		// 	printf("- sock_family: %d\n", sock_family);
		// 	switch(sock_family) {
		// 	case PPM_AF_INET:
		// 		/* ipv4 src. */
		// 		print_ipv4(1);

		// 		/* ipv4 dest. */
		// 		print_ipv4(5);

		// 		/* port src. */
		// 		print_port(9);

		// 		/* port dest. */
		// 		print_port(11);
		// 		break;

		// 	case PPM_AF_INET6:
		// 		/* ipv6 src. */
		// 		print_ipv6(1);

		// 		/* ipv6 dest. */
		// 		print_ipv6(17);

		// 		/* port src. */
		// 		print_port(33);

		// 		/* port dest. */
		// 		print_port(35);
		// 		break;

		// 	case PPM_AF_UNIX:
		// 		/* Here there are also some kernel pointers but right
		// 		 * now we are not interested in catching them.
		// 		 * 8 + 8 = 16 bytes
		// 		 */

		// 		/* unix_path. */
		// 		print_unix_path(17);
		// 		break;

		// 	default:
		// 		printf("-  error\n");
		// 		break;
		// 	}
		// 	break;
		// }

	case PT_CHARBUF:
	case PT_BYTEBUF:
	case PT_FSPATH:
	case PT_CHARBUFARRAY:
	case PT_FSRELPATH:
		printf("PARAM %d: ", num_param);
		for(int j = 0; j < len; j++) {
			printf("%c", *(char *)(valptr + j));
		}
		printf("\n");
		break;

	default:
		printf("PARAM %d: TYPE NOT KNOWN\n", num_param);
		break;
	}
	valptr += len;
}

void scap_print_event(scap_evt *ev) {
	printf("------ HEADER\n");
	printf("timestamp: %lu\n", ev->ts);
	printf("tid: %lu\n", ev->tid);
	printf("len: %d\n", ev->len);
	printf("type: %d\n", ev->type);
	printf("num params: %d\n", ev->nparams);
	printf("------\n");

	printf("------ LEN ARRAY\n");
	uint16_t *lens16 = (uint16_t *)((char *)ev + sizeof(struct ppm_evt_hdr));
	for(int i = 0; i < ev->nparams; i++) {
		printf("param %d len: %d\n", i, lens16[i]);
	}
	if(ev->nparams == 0) {
		printf("- This event has no parameter\n");
	}
	printf("------\n");

	printf("------ PARAMS\n");
	for(int i = 0; i < ev->nparams; i++) {
		print_parameter(i, ev);
	}
	if(ev->nparams == 0) {
		printf("- This event has no parameter\n");
	}
	printf("------\n");
	printf("------------------\n");
}

/*=============================== PRINT EVENT PARAMS ===========================*/

static char *get_event_name(ppm_event_code event_type) {
	return (&g_event_info[event_type])->name;
}

static char get_direction_char(ppm_event_code event_type) {
	if(event_type > PPME_SYSCALL_OPEN) {
		return ' ';
	}

	if(PPME_IS_ENTER(event_type)) {
		return 'E';
	} else {
		return 'X';
	}
}

char *scap_get_default_value_from_type(enum ppm_param_type t) {
	static uint8_t default_uint8 = 0;
	static uint16_t default_uint16 = 0;
	static uint32_t default_uint32 = 0;
	static uint64_t default_uint64 = 0;

	switch(t) {
	case PT_INT8:
	case PT_UINT8:
	case PT_FLAGS8:
	case PT_ENUMFLAGS8:
		return (char *)&default_uint8;

	case PT_INT16:
	case PT_UINT16:
	case PT_FLAGS16:
	case PT_ENUMFLAGS16:
	case PT_SYSCALLID:
		return (char *)&default_uint16;

	case PT_INT32:
	case PT_UINT32:
	case PT_FLAGS32:
	case PT_ENUMFLAGS32:
	case PT_UID:
	case PT_GID:
	case PT_MODE:
	case PT_FD32:
		return (char *)&default_uint32;

	case PT_INT64:
	case PT_UINT64:
	case PT_RELTIME:
	case PT_ABSTIME:
	case PT_ERRNO:
	case PT_FD:
	case PT_PID:
		return (char *)&default_uint64;

	// Should be ok to return NULL since the len will be 0
	case PT_BYTEBUF:
	case PT_CHARBUF:
	case PT_SOCKADDR:
	case PT_SOCKTUPLE:
	case PT_FDLIST:
	case PT_FSPATH:
	case PT_CHARBUFARRAY:
	case PT_CHARBUF_PAIR_ARRAY:
	case PT_FSRELPATH:
	case PT_DYN:
		return NULL;

	default:
		// We forgot to handle something
		ASSERT(false);
		break;
	}
	return 0;
}

// This should be only used for testing purposes in production we should use directly `memcmp` for
// the whole event
bool scap_compare_events(scap_evt *curr, scap_evt *expected, char *error) {
	//////////////////////////////
	// Start comparing the header
	//////////////////////////////

	// `NO_TIMESTAMP_COMPARISON` can be used to skip the comparison
	if(expected->ts != NO_TIMESTAMP_COMPARISON && curr->ts != expected->ts) {
		snprintf(error,
		         SCAP_LASTERR_SIZE,
		         "Event timestamp mismatch. Current (%ld) != expected (%ld)",
		         curr->ts,
		         expected->ts);
		return false;
	}

	if(curr->tid != expected->tid) {
		snprintf(error,
		         SCAP_LASTERR_SIZE,
		         "Event tid mismatch. Current (%ld) != expected (%ld)",
		         curr->tid,
		         expected->tid);
		return false;
	}

	if(curr->type != expected->type) {
		snprintf(error,
		         SCAP_LASTERR_SIZE,
		         "Event type mismatch. Current (%d) != expected (%d)",
		         curr->type,
		         expected->type);
		return false;
	}

	if(curr->nparams != expected->nparams) {
		snprintf(error,
		         SCAP_LASTERR_SIZE,
		         "Event nparams mismatch. Current (%d) != expected (%d)",
		         curr->nparams,
		         expected->nparams);
		return false;
	}

	if(curr->len != expected->len) {
		snprintf(error,
		         SCAP_LASTERR_SIZE,
		         "Event len mismatch. Current (%d) != expected (%d)",
		         curr->len,
		         expected->len);
		return false;
	}

	//////////////////////////////
	// Comparing the length of the parameters
	//////////////////////////////

	for(int i = 0; i < curr->nparams; i++) {
		uint16_t curr_param_len = 0;
		uint16_t expected_param_len = 0;

		memcpy(&curr_param_len,
		       (char *)curr + sizeof(struct ppm_evt_hdr) + sizeof(uint16_t) * i,
		       sizeof(uint16_t));
		memcpy(&expected_param_len,
		       (char *)expected + sizeof(struct ppm_evt_hdr) + sizeof(uint16_t) * i,
		       sizeof(uint16_t));

		if(curr_param_len != expected_param_len) {
			snprintf(error,
			         SCAP_LASTERR_SIZE,
			         "Param %d length mismatch. Current (%d) != expected (%d)",
			         i,
			         curr_param_len,
			         expected_param_len);
			return false;
		}
	}

	//////////////////////////////
	// Comparing each parameter
	//////////////////////////////

	char *curr_pos = (char *)curr + sizeof(struct ppm_evt_hdr) + sizeof(uint16_t) * curr->nparams;
	char *expected_pos =
	        (char *)expected + sizeof(struct ppm_evt_hdr) + sizeof(uint16_t) * curr->nparams;
	for(int i = 0; i < curr->nparams; i++) {
		uint16_t curr_param_len = 0;
		memcpy(&curr_param_len,
		       (char *)curr + sizeof(struct ppm_evt_hdr) + sizeof(uint16_t) * i,
		       sizeof(uint16_t));

		// todo!: we can improve this by printing the parameter for the specific type.
		if(memcmp(curr_pos, expected_pos, curr_param_len) != 0) {
			snprintf(error, SCAP_LASTERR_SIZE, "Param %d mismatch. Current != expected", i);
			return false;
		}
		curr_pos += curr_param_len;
		expected_pos += curr_param_len;
	}

	return true;
}

static void change_param_len_from_s64_to_s32(scap_evt *e, uint8_t param_idx) {
	uint16_t off_len = sizeof(scap_evt);
	uint16_t tot_len = 0;

	for(int i = 0; i < param_idx; i++) {
		uint16_t len = 0;
		memcpy(&len, &e[off_len], sizeof(uint16_t));
		off_len += sizeof(uint16_t);
		tot_len += len;
	}

	// 16 bits are enough, see MAX_EVENT_SIZE
	uint16_t param_offset = sizeof(scap_evt) + sizeof(uint16_t) * e->nparams + tot_len;

	int64_t old_param = 0;
	memcpy(&old_param, &e[param_offset], sizeof(int64_t));

	int32_t new_param = (int32_t)old_param;
	memcpy(&e[param_offset], &new_param, sizeof(int32_t));

	memmove(&e[param_offset + sizeof(int32_t)],
	        &e[param_offset + sizeof(int64_t)],
	        e->len - (param_offset + sizeof(int64_t)));

	// Store the new param len
	static uint16_t new_len = 4;
	memcpy(&e[off_len], &new_len, sizeof(uint16_t));

	// Store the new event len
	e->len -= sizeof(int32_t);
}

// Debugging Macros
#define CONVERSION_DEBUGGING 1

#if CONVERSION_DEBUGGING
#define DBG_PRINT(...) printf("-- DBG: " __VA_ARGS__)
#else
#define DBG_PRINT(...)
#endif

conversion_result scap_convert_event(scap_evt *new_evt, scap_evt *evt_to_convert, char *error) {
	switch(evt_to_convert->type) {
	// todo!: maybe we could store the event and use it in the exit to handle the old TOCTOU fix but
	// it seems a little bit an overkill for scap-files. At the moment we skip it
	case PPME_SYSCALL_OPEN_E:
		return CONVERSION_SKIP;

	case PPME_SYSCALL_OPEN_X:

		// Known event versions
		// todo!: this could be come an helper function or a macro, since we need it for all events.
		if((evt_to_convert->nparams != 4) && (evt_to_convert->nparams != 6)) {
			snprintf(error,
			         SCAP_LASTERR_SIZE,
			         "Unknown number of parametes '%d' for event '%s_%c(num: %d)'.",
			         evt_to_convert->nparams,
			         get_event_name(evt_to_convert->type),
			         get_direction_char(evt_to_convert->type),
			         evt_to_convert->type);
			return CONVERSION_ERROR;
		}

		if(evt_to_convert->nparams == 4) {
			// - Num params: 4
			// - param(0): fd, param(1): name, param(2): flags, param(3): mode
			// We want to convert it to the new event with 6 parameters.

			// todo!: we need to create some helpers methods

			// We keep the header and the first 4 parameters: fd, name, flags, mode.
			int offset = sizeof(scap_evt) + sizeof(uint16_t) * 4;
			memcpy(new_evt, evt_to_convert, offset);

			// But we need to add 2 new parameters
			const struct ppm_event_info *event_info = &(g_event_info[evt_to_convert->type]);

			// Add the last 2 parameters len
			uint16_t len = scap_get_size_bytes_from_type(event_info->params[4].type);
			DBG_PRINT("push len (%d) for param (%d, type: %d) at offest (%d)\n",
			          len,
			          4,
			          event_info->params[4].type,
			          offset);
			memcpy(&new_evt[offset], &len, sizeof(uint16_t));
			DBG_PRINT("pushed: %d\n", *((uint16_t *)&new_evt[offset]));
			offset += sizeof(uint16_t);

			len = scap_get_size_bytes_from_type(event_info->params[5].type);
			DBG_PRINT("push len (%d) for param (%d, type: %d) at offest (%d)\n",
			          len,
			          5,
			          event_info->params[5].type,
			          offset);
			memcpy(&new_evt[offset], &len, sizeof(uint16_t));
			offset += sizeof(uint16_t);

			// Copy the rest of the event to convert.
			memcpy(&new_evt[offset],
			       evt_to_convert + sizeof(scap_evt) + sizeof(uint16_t) * 4,
			       evt_to_convert->len - (sizeof(scap_evt) + sizeof(uint16_t) * 4));
			DBG_PRINT("copy the rest of the event (len: %d) at offest (%d)\n",
			          evt_to_convert->len - (sizeof(scap_evt) + sizeof(uint16_t) * 4),
			          offset);
			offset += (evt_to_convert->len - (sizeof(scap_evt) + sizeof(uint16_t) * 4));

			// Add the last 2 parameters
			char *value = scap_get_default_value_from_type(event_info->params[4].type);
			DBG_PRINT("push param (%d, type: %d) at offest (%d)\n",
			          4,
			          event_info->params[4].type,
			          offset);
			memcpy(&new_evt[offset],
			       value,
			       scap_get_size_bytes_from_type(event_info->params[4].type));
			offset += scap_get_size_bytes_from_type(event_info->params[4].type);

			value = scap_get_default_value_from_type(event_info->params[5].type);
			DBG_PRINT("push param (%d, type: %d) at offest (%d)\n",
			          5,
			          event_info->params[5].type,
			          offset);
			memcpy(&new_evt[offset],
			       value,
			       scap_get_size_bytes_from_type(event_info->params[5].type));
			offset += scap_get_size_bytes_from_type(event_info->params[5].type);

			// Adjust the number of parameters
			new_evt->nparams = 6;

			// We need to adapt the new event len
			new_evt->len = offset;

			return CONVERSION_CONTINUE;
		}

		if(evt_to_convert->nparams == 6) {
			// - Num params: 6
			// - param(0): fd, param(1): name, param(2): flags, param(3): mode, param(4): dev,
			// param(5): ino

			// Copy the old event in the new one
			memcpy(new_evt, evt_to_convert, evt_to_convert->len);

			// Change the dimension of a parameter
			change_param_len_from_s64_to_s32(new_evt, 0);

			// Change the event type
			new_evt->type = PPME_SYSCALL_OPEN;
			return CONVERSION_COMPLETED;
		}
		// This should never happen
		snprintf(error, SCAP_LASTERR_SIZE, "Reached unkown state for event '%d'.", new_evt->type);
		return CONVERSION_ERROR;

	default:
		// For all the event we still need to support
		memcpy(new_evt, evt_to_convert, evt_to_convert->len);
		return CONVERSION_COMPLETED;
		break;
	}

	snprintf(error,
	         SCAP_LASTERR_SIZE,
	         "Reached unkown state for event '%d'.",
	         evt_to_convert->type);
	return CONVERSION_ERROR;
}
