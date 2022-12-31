/*
Copyright (C) 2022 The Falco Authors.

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
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <ppm_events_public.h>

#include "ringbuffer_definitions.h"

/*
 * Utility functions before object loading 
 */

/* This must be done to please the verifier! At load-time, the verifier must know the
 * size of a map inside the array.
 */
static int ringbuf_array_set_inner_map(unsigned long ringbuf_dim)
{
	int err = 0;
	int inner_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, ringbuf_dim, NULL);
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

static int ringbuf_array_set_max_entries(int16_t max_entries)
{
	if(bpf_map__set_max_entries(g_state.skel->maps.ringbuf_maps, max_entries))
	{
		pman_print_error("unable to set max entries for the ringbuf_array");
		return errno;
	}
	return 0;
}

static int allocate_consumer_producer_positions()
{
	g_state.ringbuf_pos = 0;
	g_state.cons_pos = (unsigned long *)calloc(g_state.n_allocated_buffers, sizeof(unsigned long));
	g_state.prod_pos = (unsigned long *)calloc(g_state.n_allocated_buffers, sizeof(unsigned long));
	if(g_state.cons_pos == NULL || g_state.prod_pos == NULL)
	{
		pman_print_error("failed to alloc memory for cons_pos and prod_pos");
		return errno;
	}
	return 0;
}

/*
 * Before loading functions for the 3 different modes
 */

int pman_prepare_percpu_ringbuf_before_loading()
{
	/* Here we want a ring buffer for every CPU, the size of each buffer
	 * is the one chosen by users: `g_state.buffer_bytes_dim` 
	 */
	g_state.skel->rodata->ring_buffer_mode = BPF_PER_CPU_BUFFER;
	g_state.n_allocated_buffers = g_state.n_cpus;
	int err = 0;
	err = ringbuf_array_set_inner_map(g_state.buffer_bytes_dim);
	err = err ?: ringbuf_array_set_max_entries(g_state.n_cpus);
	/* We need a consumer and a producer for every ring buffer so in this case
	 * we need `n_cpus` producers/consumers.
	 */
	err = err ?: allocate_consumer_producer_positions();
	return err;
}

int pman_prepare_paired_ringbuf_before_loading()
{
	/* Here we want a ring buffer for every CPU pair, the size of each buffer
	 * is the one chosen by users: `g_state.buffer_bytes_dim`
     *
	 * CPU 0 \
	 * 		  > RING BUFFER 0 (g_state.buffer_bytes_dim)
	 * CPU 1 /
	 *
	 * CPU 2 \
	 * 		  > RING BUFFER 1 (g_state.buffer_bytes_dim)
	 * CPU 3 /
	 *
	 * As in the `percpu` approach we allocate a ring buffer even if the CPU is not 
	 * available at that moment, in this case, we can easily manage CPU hot plugs cases.
	 * This should be a corner case but we can change the behavior in case of issues
	 */
	g_state.skel->rodata->ring_buffer_mode = BPF_PAIRED_BUFFER;
	g_state.n_allocated_buffers = g_state.n_cpus / 2 + g_state.n_cpus % 2;

	int err = 0;
	err = ringbuf_array_set_inner_map(g_state.buffer_bytes_dim);
	/* Please note: here we always need `n_cpus` entries, even if 
	 * we don't have `n_cpus` different buffers, this is because
	 * 2 consecutive CPUs will point to the same ring buffer.
	 */
	err = err ?: ringbuf_array_set_max_entries(g_state.n_cpus);
	/* We need a consumer and a producer for every ring buffer so in this case
	 * we need `g_state.n_allocated_buffers` producers/consumers.
	 * Adding the division rest should allow us to manage odd CPUs numbers.
	 */
	err = err ?: allocate_consumer_producer_positions();
	return err;
}

int pman_prepare_single_ringbuf_before_loading()
{
	/* Here we want a unique shared ring buffer for all the CPUs, with the dimension
	 * chosen by users: `g_state.buffer_bytes_dim`.
	 */
	g_state.skel->rodata->ring_buffer_mode = BPF_SINGLE_BUFFER;
	g_state.n_allocated_buffers = 1;

	int err = 0;
	/* We need to set an inner map inside the array even if we won't use it with this approach */
	err = ringbuf_array_set_inner_map(MIN_SINGLE_BUFFER_DIM);
	err = err ?: ringbuf_array_set_max_entries(1);
	/* Here we set the dimension of the single shared ring buffer */
	err = err ?: bpf_map__set_max_entries(g_state.skel->maps.single_ringbuffer, g_state.buffer_bytes_dim);
	/* We need just one consumer and producer position since we have only one ring buffer. */
	err = err ?: allocate_consumer_producer_positions();
	return err;
}

/* After loading */

/* Create all the ringbuffer maps inside the ringbuffer_array and assign
 * them to the manager. Note, the first ringbuffer map is separated from
 * the others because we first need to create the ringbuffer manager with
 * just one map `ring_buffer__new`. After having instanciating the manager
 * we can add to it all the other maps with `ring_buffer__add`.
 */
int pman_finalize_percpu_ringbuf_after_loading()
{
	int ringubuf_array_fd = -1;
	int ringbuf_map_fd = -1;
	int index = 0;
	char error_message[MAX_ERROR_MESSAGE_LEN];

	/* We don't need the single ring buffer map in userspace, by the way
	 * this map won't be destroyed because is referenced by BPF programs.
	 */
	int single_ringbuf_fd = bpf_map__fd(g_state.skel->maps.single_ringbuffer);
	close(single_ringbuf_fd);

	/* We don't need anymore the inner map, close it. */
	close(g_state.inner_ringbuf_map_fd);

	/* `ringbuf_array` is a maps array, every map inside it is a `BPF_MAP_TYPE_RINGBUF`. */
	ringubuf_array_fd = bpf_map__fd(g_state.skel->maps.ringbuf_maps);
	if(ringubuf_array_fd <= 0)
	{
		pman_print_error("failed to get the ringubuf_array");
		return errno;
	}

	/* create the first ringbuf map. */
	ringbuf_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, g_state.buffer_bytes_dim, NULL);
	if(ringbuf_map_fd <= 0)
	{
		pman_print_error("failed to create the first ringbuf map");
		goto clean_ring_buffers;
	}

	/* add the first ringbuf map into the array. */
	if(bpf_map_update_elem(ringubuf_array_fd, &index, &ringbuf_map_fd, BPF_ANY))
	{
		pman_print_error("failed to add the first ringbuf map into the array");
		goto clean_ring_buffers;
	}

	/* create the ringbuf manager */
	g_state.rb_manager = ring_buffer__new(ringbuf_map_fd, NULL, NULL, NULL);
	if(!g_state.rb_manager)
	{
		pman_print_error("failed to instantiate the ringbuf manager. (If you get memory allocation errors try to reduce the buffer dimension)");
		goto clean_ring_buffers;
	}
	close(ringbuf_map_fd);

	/* for all CPUs add the rinugbuf map into the array and add it also
	 * into the ringbuf manager. Please note: we have already initialized the
	 * the ringbuf_array and the manager with the map for the CPU `0`.
	 */
	for(index = 1; index < g_state.n_cpus; index++)
	{
		ringbuf_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, g_state.buffer_bytes_dim, NULL);
		if(ringbuf_map_fd <= 0)
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "failed to create the ringbuf map for CPU %d", index);
			pman_print_error((const char *)error_message);
			goto clean_ring_buffers;
		}

		if(bpf_map_update_elem(ringubuf_array_fd, &index, &ringbuf_map_fd, BPF_ANY))
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "failed to add the ringbuf map for CPU %d into the array", index);
			pman_print_error((const char *)error_message);
			goto clean_ring_buffers;
		}

		/* add the new ringbuf map into the manager. */
		if(ring_buffer__add(g_state.rb_manager, ringbuf_map_fd, NULL, NULL))
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "failed to add the ringbuf map for CPU %d into the manager", index);
			pman_print_error((const char *)error_message);
			goto clean_ring_buffers;
		}
		close(ringbuf_map_fd);
	}
	return 0;

clean_ring_buffers:
	close(ringbuf_map_fd);
	close(ringubuf_array_fd);
	if(!g_state.rb_manager)
	{
		ring_buffer__free(g_state.rb_manager);
	}
	return errno;
}

int pman_finalize_paired_ringbuf_after_loading()
{
	int ringubuf_array_fd = -1;
	int ringbuf_map_fd = -1;
	int index = 0;
	char error_message[MAX_ERROR_MESSAGE_LEN];

	/* We don't need the single ring buffer map in userspace, by the way
	 * this map won't be destroyed because is referenced by BPF programs.
	 */
	int single_ringbuf_fd = bpf_map__fd(g_state.skel->maps.single_ringbuffer);
	close(single_ringbuf_fd);


	/* We don't need anymore the inner map, close it. */
	close(g_state.inner_ringbuf_map_fd);

	/* `ringbuf_array` is a maps array, every map inside it is a `BPF_MAP_TYPE_RINGBUF`. */
	ringubuf_array_fd = bpf_map__fd(g_state.skel->maps.ringbuf_maps);
	if(ringubuf_array_fd <= 0)
	{
		pman_print_error("failed to get the ringubuf_array");
		return errno;
	}

	/* create the first ringbuf map. */
	ringbuf_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, g_state.buffer_bytes_dim, NULL);
	if(ringbuf_map_fd <= 0)
	{
		pman_print_error("failed to create the first ringbuf map");
		goto clean_ring_buffers;
	}

	/* add the first ringbuf map into the array. */
	if(bpf_map_update_elem(ringubuf_array_fd, &index, &ringbuf_map_fd, BPF_ANY))
	{
		pman_print_error("failed to add the first ringbuf map into the array");
		goto clean_ring_buffers;
	}

	/* if we have a CPU 1 we need to map the same ring buffer of CPU 0 to it */
	if(g_state.n_cpus > 1)
	{
		index++;
		if(bpf_map_update_elem(ringubuf_array_fd, &index, &ringbuf_map_fd, BPF_ANY))
		{
			pman_print_error("failed to add the first ringbuf map for the CPU 1");
			goto clean_ring_buffers;
		}
	}

	/* create the ringbuf manager */
	g_state.rb_manager = ring_buffer__new(ringbuf_map_fd, NULL, NULL, NULL);
	if(!g_state.rb_manager)
	{
		pman_print_error("failed to instantiate the ringbuf manager. (If you get memory allocation errors try to reduce the buffer dimension)");
		goto clean_ring_buffers;
	}

	for(index = 2; index < g_state.n_cpus; index++)
	{
		if(index % 2 != 0)
		{
			if(bpf_map_update_elem(ringubuf_array_fd, &index, &ringbuf_map_fd, BPF_ANY))
			{
				snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "failed to add the ringbuf map for CPU %d into the array", index);
				pman_print_error((const char *)error_message);
				goto clean_ring_buffers;
			}
			continue;
		}

		close(ringbuf_map_fd);

		ringbuf_map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, g_state.buffer_bytes_dim, NULL);
		if(ringbuf_map_fd <= 0)
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "failed to create the ringbuf map for CPU %d", index);
			pman_print_error((const char *)error_message);
			goto clean_ring_buffers;
		}

		if(bpf_map_update_elem(ringubuf_array_fd, &index, &ringbuf_map_fd, BPF_ANY))
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "failed to add the ringbuf map for CPU %d into the array", index);
			pman_print_error((const char *)error_message);
			goto clean_ring_buffers;
		}

		/* add the new ringbuf map into the manager. */
		if(ring_buffer__add(g_state.rb_manager, ringbuf_map_fd, NULL, NULL))
		{
			snprintf(error_message, MAX_ERROR_MESSAGE_LEN, "failed to add the ringbuf map for CPU %d into the manager", index);
			pman_print_error((const char *)error_message);
			goto clean_ring_buffers;
		}
	}
	return 0;

clean_ring_buffers:
	close(ringbuf_map_fd);
	close(ringubuf_array_fd);
	if(!g_state.rb_manager)
	{
		ring_buffer__free(g_state.rb_manager);
	}
	return errno;
}

int pman_finalize_single_ringbuf_after_loading()
{
	/* We don't need the ring buffer array map in userspace, by the way
	 * this map won't be destroyed because is referenced by BPF programs.
	 */
	int ringubuf_array_fd = bpf_map__fd(g_state.skel->maps.ringbuf_maps);
	close(ringubuf_array_fd);


	g_state.rb_manager = ring_buffer__new(bpf_map__fd(g_state.skel->maps.single_ringbuffer), NULL, NULL, NULL);
	if(!g_state.rb_manager)
	{
		pman_print_error("failed to instantiate the ringbuf manager. (If you get memory allocation errors try to reduce the buffer dimension)");
		return errno;
	}
	return 0;
}

static inline void *ringbuf__get_first_ring_event(struct ring *r, int pos)
{
	int *len_ptr = NULL;
	int len = 0;
	void *sample = NULL;

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

	/* Save the size of the event if we need to increment the consumer */
	g_state.last_event_size = roundup_len(len);

	/* the sample is not discarded kernel side. */
	if((len & BPF_RINGBUF_DISCARD_BIT) == 0)
	{
		sample = (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
	}

	return sample;
}

static inline void *ringbuf_process_one_from_ring(struct ring *r)
{
	int *len_ptr, len;
	void *sample = NULL;

	smp_store_release(r->consumer_pos, g_state.cons_pos[0]);

	if(g_state.cons_pos[0] >= g_state.prod_pos[0])
	{
		g_state.prod_pos[0] = smp_load_acquire(r->producer_pos);
		if(g_state.cons_pos[0] >= g_state.prod_pos[0])
		{
			return NULL;
		}
	}

	len_ptr = r->data + (g_state.cons_pos[0] & r->mask);
	len = smp_load_acquire(len_ptr);

	/* Check in the header if the bit is active, sample not committed yet, bail out for now */
	if(len & BPF_RINGBUF_BUSY_BIT)
	{
		goto done;
	}

	g_state.cons_pos[0] += roundup_len(len);

	/* the sample is discarded kernel side. */
	if((len & BPF_RINGBUF_DISCARD_BIT) == 0)
	{
		sample = (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
	}

done:
	return sample;
}

static void ringbuf__consume_first_event_from_multiple_bufs(struct ring_buffer *rb, struct ppm_evt_hdr **event_ptr, int16_t *buffer_id)
{
	uint64_t min_ts = 0xffffffffffffffffLL;
	struct ppm_evt_hdr *tmp_pointer = NULL;
	int tmp_ring = -1;
	unsigned long tmp_cons_increment = 0;

	/* If the last consume operation was successful we can push the consumer position */
	if(g_state.last_ring_read != -1)
	{
		struct ring *r = &(rb->rings[g_state.last_ring_read]);
		g_state.cons_pos[g_state.last_ring_read] += g_state.last_event_size;
		smp_store_release(r->consumer_pos, g_state.cons_pos[g_state.last_ring_read]);
	}

	for(uint16_t pos = 0; pos < rb->ring_cnt; pos++)
	{
		*event_ptr = ringbuf__get_first_ring_event(&rb->rings[pos], pos);

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

static void ringbuf__consume_first_event_from_single_buf(struct ring_buffer *rb, struct ppm_evt_hdr **event_ptr, int16_t *buffer_id)
{
	struct ring *ring = &rb->rings[0];
	/* We need to check the return in the caller */
	*event_ptr = ringbuf_process_one_from_ring(ring);
}

/* Consume */

/* This API must be used if we want to get the first event according to its timestamp */
void pman_consume_first_from_multiple_buffers(void **event_ptr, int16_t *buffer_id)
{
	ringbuf__consume_first_event_from_multiple_bufs(g_state.rb_manager, (struct ppm_evt_hdr **)event_ptr, buffer_id);
}

void pman_consume_first_from_single_buffer(void **event_ptr, int16_t *buffer_id)
{
	ringbuf__consume_first_event_from_single_buf(g_state.rb_manager, (struct ppm_evt_hdr **)event_ptr, buffer_id);
}

#ifdef TEST_HELPERS

/* The buffer is full if the remaining size is less than the dimension
 * of the event we want to push, this helper can be used when the dimension
 * of the event pushed is always the same.
 */
static bool pman_is_ringbuffer_full(int ring_num, unsigned long threshold)
{
	if(ring_num < 0 || ring_num >= g_state.n_cpus)
	{
		return -1;
	}

	struct ring_buffer *rb = g_state.rb_manager;
	struct ring *ring = &rb->rings[ring_num];
	unsigned long p = 0;
	unsigned long c = 0;
	p = smp_load_acquire(ring->producer_pos);
	c = smp_load_acquire(ring->consumer_pos);
	unsigned long dim = ring->mask;
	unsigned long reserved = (p >= c) ? p - c : dim - c + p;
	unsigned long free = dim - reserved;
	/* We need this print otherwise the test won't work! */
	printf("Ring (%d): producer %ld, consumer: %ld, reserved: %ld\n", ring_num, p, c, reserved);
	return free < threshold;
}

bool pman_are_all_ringbuffers_full(unsigned long threshold)
{
	int pos = 0;
	int attempt = 0;

	/* Performs 3 attempts just to be sure that all the buffers are empty. */
	while(pos < g_state.n_cpus)
	{
		if(!pman_is_ringbuffer_full(pos, threshold))
		{
			return false;
		}

		pos++;

		if(pos == g_state.n_cpus && attempt != 2)
		{
			printf("Stable, attempt %d\n", attempt);
			pos = 0;
			attempt++;
		}
	}
	return true;
}

unsigned long pman_get_producer_pos(int ring_num)
{
	struct ring_buffer *rb = g_state.rb_manager;
	struct ring *ring = &rb->rings[ring_num];
	return smp_load_acquire(ring->producer_pos);
}

static inline void *ringbuf__search_one_from_ring(struct ring *r, int ring_cnt)
{
	int *len_ptr = NULL;
	int len = 0;
	void *sample = NULL;
	int actual_pos = g_state.ringbuf_pos;

	/* If we enter here again we have read the previous event on this buffer so we can move
	 * the consumer position.
	 */
	smp_store_release(r->consumer_pos, g_state.cons_pos[actual_pos]);

	/* If the consumer reaches the producer update its position. */
	if(g_state.cons_pos[actual_pos] >= g_state.prod_pos[actual_pos])
	{
		g_state.prod_pos[actual_pos] = smp_load_acquire(r->producer_pos);
	}
	else
	{
		len_ptr = r->data + (g_state.cons_pos[actual_pos] & r->mask);

		/* These are the first 4 bytes of the ring buffer record header:
		 *
		 * struct bpf_ringbuf_hdr {
		 *		u32 len;
		 *		u32 pg_off;
		 *	};
		 *
		 * So the event can have at maximum this dimension: `(UINT_MAX/4)` since
		 * the 2 top bits are reserved for `BPF_RINGBUF_BUSY_BIT` and `BPF_RINGBUF_DISCARD_BIT`.
		 *
		 * These 2 operations allow us to remove the 2 top bits obtaining the real size of our event:
		 * len <<= 2;
		 * len >>= 2;
		 */
		len = smp_load_acquire(len_ptr);

		/* Check in the header if the bit is active, sample not committed yet, bailout for now */
		if(len & BPF_RINGBUF_BUSY_BIT)
		{
			goto done;
		}

		g_state.cons_pos[actual_pos] += roundup_len(len);

		/* the sample is not discarded kernel side. */
		if((len & BPF_RINGBUF_DISCARD_BIT) == 0)
		{
			sample = (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
		}
	}

done:
	/* We change the buffer after every event we catch */
	g_state.ringbuf_pos = (actual_pos + 1) % ring_cnt;
	return sample;
}

/* return 0 if a valid event is found, otherwise -1. */
static int ringbuf__consume_one_event(struct ring_buffer *rb, void **event_ptr, uint16_t *cpu_id)
{
	int ringbuf_pos = g_state.ringbuf_pos;
	int attempts = 0;

	while(true)
	{
		struct ring *ring = &rb->rings[g_state.ringbuf_pos];
		*event_ptr = ringbuf__search_one_from_ring(ring, rb->ring_cnt);
		if(*event_ptr != NULL)
		{
			*cpu_id = g_state.ringbuf_pos;
			return 0;
		}
		if(ringbuf_pos == g_state.ringbuf_pos)
		{
			attempts++;
			/* To be sure that all buffers are empty we have to check two times.
			 * In the worst case, the first time we have to update all producers
			 * positions. If also the second time we don't find any event we are
			 * sure that ring buffers are all empty.
			 */
			if(attempts == 2)
			{
				break;
			}
		}
	}
	*cpu_id = -1;
	return -1;
}

/* This API must be used if we want to get just one event from the buffer and we don't care about
 * the timestamp of the event.
 */
int pman_consume_one_from_buffers(void **event_ptr, uint16_t *cpu_id)
{
	return ringbuf__consume_one_event(g_state.rb_manager, event_ptr, cpu_id);
}

#endif
