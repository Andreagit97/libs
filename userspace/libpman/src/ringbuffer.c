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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <driver/ppm_events_public.h>

#include "ringbuffer_definitions.h"

#ifndef likely
#define likely(X) __builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
#define unlikely(X) __builtin_expect(!!(X), 0)
#endif

/* Utility functions object loading */

/* This must be done to please the verifier! At load-time, the verifier must know the
 * size of a map inside the array.
 */
static int ringbuf_array_set_inner_map()
{
	int err = 0;
	int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, g_state.buffer_bytes_dim, NULL);
	if(inner_map_fd < 0)
	{
		pman_print_error("failed to create the dummy inner map");
		return errno;
	}

	/* Set the inner map file descriptor into the outer map. */
	err = bpf_map__set_inner_map_fd(g_state.skel->maps.ringbuf_maps, inner_map_fd);
	if(err)
	{
		pman_print_error("failed to set the dummy inner map inside the ringbuf array");
		close(inner_map_fd);
		return errno;
	}

	/* Save to close it after the loading phase. */
	g_state.inner_ringbuf_map_fd = inner_map_fd;
	return 0;
}

static int ringbuf_array_set_max_entries()
{
	/* We always allocate a number of entries equal to the available CPUs.
	 * This doesn't mean that we allocate a ring buffer for every available CPU,
	 * it means only that every CPU will have an associated entry.
	 */
	if(bpf_map__set_max_entries(g_state.skel->maps.ringbuf_maps, g_state.n_possible_cpus))
	{
		pman_print_error("unable to set max entries for the ringbuf_array");
		return errno;
	}
	return 0;
}

static int allocate_consumer_producer_positions()
{
	g_state.ringbuf_pos = 0;
	g_state.cons_pos = (unsigned long *)calloc(g_state.n_required_buffers, sizeof(unsigned long));
	g_state.prod_pos = (unsigned long *)calloc(g_state.n_required_buffers, sizeof(unsigned long));
	if(g_state.cons_pos == NULL || g_state.prod_pos == NULL)
	{
		pman_print_error("failed to alloc memory for cons_pos and prod_pos");
		return errno;
	}
	return 0;
}

/* Before loading */
int pman_prepare_ringbuf_array_before_loading()
{
	int err;
	err = ringbuf_array_set_inner_map();
	err = err ?: ringbuf_array_set_max_entries();
	/* Allocate consumer positions and producer positions for the ringbuffer. */
	err = err ?: allocate_consumer_producer_positions();
	return err;
}

static bool is_cpu_online(uint16_t cpu_id)
{
	/* CPU 0 is always online */
	if(cpu_id == 0)
	{
		return true;
	}

	char filename[FILENAME_MAX];
	int online = 0;
	snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", cpu_id);
	FILE *fp = fopen(filename, "r");
	if(fp == NULL)
	{
		/* When missing NUMA properties, CPUs do not expose online information.
		 * Fallback at considering them online if we can at least reach their folder.
		 * This is useful for example for raspPi devices.
		 * See: https://github.com/kubernetes/kubernetes/issues/95039
		 */
		snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/", cpu_id);
		if(access(filename, F_OK) == 0)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	if(fscanf(fp, "%d", &online) != 1)
	{
		online = 0;
	}
	fclose(fp);
	return online == 1;
}

/* After loading */
int pman_finalize_ringbuf_array_after_loading()
{
	int ringubuf_array_fd = -1;
	char error_message[MAX_ERROR_MESSAGE_LEN];
	int *ringbufs_fds = (int *)calloc(g_state.n_required_buffers, sizeof(int));
	if(ringbufs_fds == NULL)
	{
		pman_print_error("failed to allocate the ringubufs_fds array");
		return errno;
	}
	bool success = false;

	/* We don't need anymore the inner map, close it. */
	close(g_state.inner_ringbuf_map_fd);

	/* Create ring buffer maps. */
	for(int i = 0; i < g_state.n_required_buffers; i++)
	{
		ringbufs_fds[i] = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, g_state.buffer_bytes_dim, NULL);
		if(ringbufs_fds[i] <= 0)
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN,
				 "failed to create the ringbuf map for CPU '%d'. (If you get memory allocation errors "
				 "try to reduce the buffer dimension)",
				 i);
			pman_print_error((const char *)error_message);
			goto clean_percpu_ring_buffers;
		}
	}

	/* Create the ringbuf manager */
	g_state.rb_manager = ring_buffer__new(ringbufs_fds[0], NULL, NULL, NULL);
	if(!g_state.rb_manager)
	{
		pman_print_error("failed to instantiate the ringbuf manager.");
		goto clean_percpu_ring_buffers;
	}

	/* Add all remaining buffers into the manager.
	 * We start from 1 because the first one is
	 * used to instantiate the manager.
	 */
	for(int i = 1; i < g_state.n_required_buffers; i++)
	{
		if(ring_buffer__add(g_state.rb_manager, ringbufs_fds[i], NULL, NULL))
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN,
				 "failed to add the ringbuf map for CPU %d into the manager", i);
			pman_print_error((const char *)error_message);
			goto clean_percpu_ring_buffers;
		}
	}

	/* `ringbuf_array` is a maps array, every map inside it is a `BPF_MAP_TYPE_RINGBUF`. */
	ringubuf_array_fd = bpf_map__fd(g_state.skel->maps.ringbuf_maps);
	if(ringubuf_array_fd <= 0)
	{
		pman_print_error("failed to get the ringubuf_array");
		return errno;
	}

	/* We need to associate every CPU to the right ring buffer */
	int ringbuf_id = 0;
	int reached = 0;
	for(int i = 0; i < g_state.n_possible_cpus; i++)
	{
		/* If we want to allocate only buffers for online CPUs and the CPU is online, fill its
		 * ring buffer array entry, otherwise we can go on with the next online CPU
		 */
		if(g_state.allocate_online_only && !is_cpu_online(i))
		{
			continue;
		}

		if(ringbuf_id >= g_state.n_required_buffers)
		{
			/* If we arrive here it means that we have too many CPUs for our allocated ring buffers
			 * so probably we faced a CPU hotplug.
			 */
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN,
				 "the actual system configuration requires more than '%d' ring buffers",
				 g_state.n_required_buffers);
			pman_print_error((const char *)error_message);
			goto clean_percpu_ring_buffers;
		}

		if(bpf_map_update_elem(ringubuf_array_fd, &i, &ringbufs_fds[ringbuf_id], BPF_ANY))
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN,
				 "failed to add the ringbuf map for CPU '%d' to ringbuf '%d'", i, ringbuf_id);
			pman_print_error((const char *)error_message);
			goto clean_percpu_ring_buffers;
		}

		if(++reached == g_state.cpus_for_each_buffer)
		{
			/* we need to switch to the next buffer */
			reached = 0;
			ringbuf_id++;
		}
	}
	success = true;

clean_percpu_ring_buffers:
	for(int i = 0; i < g_state.n_required_buffers; i++)
	{
		if(ringbufs_fds[i])
		{
			close(ringbufs_fds[i]);
		}
	}
	free(ringbufs_fds);

	if(success)
	{
		return 0;
	}

	close(ringubuf_array_fd);
	if(g_state.rb_manager)
	{
		ring_buffer__free(g_state.rb_manager);
	}
	return errno;
}

////////////////////////
// RINGBUF LOGIC
////////////////////////

/* We return NULL only in case there is no new data to consume */
static inline void *ringbuf_get_first_event(struct ring *r, size_t *cons_update)
{
	unsigned long cons_pos = smp_load_acquire(r->consumer_pos);

restart:
	if(cons_pos >= smp_load_acquire(r->producer_pos))
	{
		return NULL;
	}

	int *len_ptr = r->data + (cons_pos & r->mask);
	int len = smp_load_acquire(len_ptr);

	/* sample not committed yet, bail out for now */
	if(len & BPF_RINGBUF_BUSY_BIT)
	{
		return NULL;
	}

	/* We can also remove it if we are sure we will never discard an event kernel side */
	if((len & BPF_RINGBUF_DISCARD_BIT) != 0)
	{
		cons_pos += roundup_len(len);
		smp_store_release(r->consumer_pos, cons_pos);
		goto restart;
	}
	*cons_update = roundup_len(len);
	return (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
}

static inline void *ringbuf__get_first_ring_event(struct ring *r, int pos)
{
	int *len_ptr = NULL;
	int len = 0;

	/* If the consumer reaches the producer update the producer position to
	 * get the newly collected events.
	 */
	if(g_state.cons_pos[pos] >= g_state.prod_pos[pos])
	{
		g_state.prod_pos[pos] = smp_load_acquire(r->producer_pos);
		return NULL;
	}

	len_ptr = r->data + (g_state.cons_pos[pos] & r->mask);
	len = smp_load_acquire(len_ptr);

	/* The actual event is not yet committed */
	if(len & BPF_RINGBUF_BUSY_BIT)
	{
		return NULL;
	}

	/* the sample is not discarded kernel side. */
	if((len & BPF_RINGBUF_DISCARD_BIT) == 0)
	{
		/* Save the size of the event if we need to increment the consumer */
		g_state.last_event_size = roundup_len(len);
		return (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
	}
	else
	{
		/* Discard the event kernel side and update the consumer position */
		g_state.cons_pos[pos] += roundup_len(len);
		smp_store_release(r->consumer_pos, g_state.cons_pos[pos]);
		return NULL;
	}
}

static void ringbuf__standard(struct ring_buffer *rb, struct ppm_evt_hdr **event_ptr, int16_t *buffer_id)
{
	uint64_t min_ts = 0xffffffffffffffffLL;
	struct ppm_evt_hdr *tmp_pointer = NULL;
	int tmp_ring = -1;
	unsigned long tmp_cons_increment = 0;

	/* If the last consume operation was successful we can push the consumer position */
	if(g_state.last_ring_read != -1)
	{
		struct ring *r = rb->rings[g_state.last_ring_read];
		g_state.cons_pos[g_state.last_ring_read] += g_state.last_event_size;
		smp_store_release(r->consumer_pos, g_state.cons_pos[g_state.last_ring_read]);
	}

	for(uint16_t pos = 0; pos < rb->ring_cnt; pos++)
	{
		*event_ptr = ringbuf__get_first_ring_event(rb->rings[pos], pos);

		/* if NULL search for events in another buffer */
		if(*event_ptr == NULL)
		{
			continue;
		}

		if((*event_ptr)->ts < min_ts)
		{
			min_ts = (*event_ptr)->ts;
			tmp_pointer = *event_ptr;
			tmp_ring = pos;
			tmp_cons_increment = g_state.last_event_size;
		}
	}

	*event_ptr = tmp_pointer;
	*buffer_id = tmp_ring;
	g_state.last_ring_read = tmp_ring;
	g_state.last_event_size = tmp_cons_increment;
}

// This is not thread-safe just one thread should call it
// todo!: we always start the scraping from the first ring, but we should start from the last ring we read from.
void *ring_buffer__consume_sequential(struct ring_buffer *rb)
{
	static struct ringbuf_evt_storage storage = {.cons_update = 0, .evt_data = NULL, .ring_num = -1};

	if(storage.ring_num != -1)
	{
		// We update the consumer position
		smp_store_release(rb->rings[storage.ring_num]->consumer_pos,
				  *rb->rings[storage.ring_num]->consumer_pos + storage.cons_update);
	}

	// We read from the last buffer
	for(u_int8_t i = 0; i < rb->ring_cnt; i++)
	{
		storage.ring_num = ((storage.ring_num + 1) % rb->ring_cnt);
		storage.evt_data = ringbuf_get_first_event(rb->rings[storage.ring_num], &storage.cons_update);
		if(storage.evt_data == NULL)
		{
			continue;
		}
		return storage.evt_data;
	}

	storage.cons_update = 0;
	storage.ring_num = -1;
	return NULL;
}

static void ring_buffer__consume_first_event(struct ring_buffer *rb, struct ppm_evt_hdr **event_ptr)
{
	/* If the last consume operation was successful we can push the consumer position */
	if(g_state.last_ring_read != -1)
	{
		// saving the consumer position in the state seems a great optimization since we don't have to get it each time we read the buffers
		struct ring *r = rb->rings[g_state.last_ring_read];
		g_state.cons_pos[g_state.last_ring_read] += g_state.last_event_size;
		smp_store_release(r->consumer_pos, g_state.cons_pos[g_state.last_ring_read]);
	}

	for(uint8_t pos = 0; pos < rb->ring_cnt; pos++)
	{
		*event_ptr = ringbuf__get_first_ring_event(rb->rings[pos], pos);

		/* this if condition is ok in this way, if we try != NULL we lose in perf*/
		if(*event_ptr == NULL)
		{
			continue;
		}
		g_state.last_ring_read = pos;
		return;
	}

	g_state.last_ring_read = -1;
}

/* Consume */
void pman_consume_event(void **event_ptr, int16_t *buffer_id)
{
	switch(g_state.policy)
	{
	case POLICY_STANDARD:
		ringbuf__standard(g_state.rb_manager, (struct ppm_evt_hdr **)event_ptr, buffer_id);
		break;

	case POLICY_FIRST_EVENT:
		*buffer_id = 0;
		ring_buffer__consume_first_event(g_state.rb_manager, (struct ppm_evt_hdr **)event_ptr);
		break;

	case POLICY_SEQUENTIAL_EVENT:
		*buffer_id = 0;
		*event_ptr = ring_buffer__consume_sequential(g_state.rb_manager);
		break;

	default:
		*buffer_id = 0;
		*event_ptr = NULL;
		break;
	}
}
