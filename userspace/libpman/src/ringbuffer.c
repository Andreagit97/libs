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

int pman_prepare_ringbuf_array_before_loading()
{
	 if(bpf_map__set_max_entries(g_state.skel->maps.single_ringbuffer, g_state.buffer_bytes_dim)<0)
	 {
		pman_print_error("Unable to get single ring");
		return errno;
	 }
	return 0;
}

/* Create all the ringbuffer maps inside the ringbuffer_array and assign
 * them to the manager. Note, the first ringbuffer map is separated from
 * the others because we first need to create the ringbuffer manager with
 * just one map `ring_buffer__new`. After having instanciating the manager
 * we can add to it all the other maps with `ring_buffer__add`.
 */
int pman_finalize_ringbuf_array_after_loading()
{
	g_state.rb_manager = ring_buffer__new(bpf_map__fd(g_state.skel->maps.single_ringbuffer), NULL, NULL, NULL);
	if(!g_state.rb_manager)
	{
		pman_print_error("failed to instantiate the ringbuf manager. (If you get memory allocation errors try to reduce the buffer dimension)");
		return errno;
	}
	return 0;
}



static void *ringbuf_process_one_from_ring(struct ring *r)
{
	int *len_ptr, len;
	void *sample = NULL;

	smp_store_release(r->consumer_pos, g_state.cons_pos);

	if(g_state.cons_pos >= g_state.prod_pos)
	{
		g_state.prod_pos = smp_load_acquire(r->producer_pos);
		if(g_state.cons_pos >= g_state.prod_pos)
		{
			return NULL;
		}
	}

	len_ptr = r->data + (g_state.cons_pos & r->mask);
	len = smp_load_acquire(len_ptr);

	/* Check in the header if the bit is active, sample not committed yet, bail out for now */
	if(len & BPF_RINGBUF_BUSY_BIT)
	{
		goto done;
	}

	g_state.cons_pos += roundup_len(len);

	/* the sample is discarded kernel side. */
	if((len & BPF_RINGBUF_DISCARD_BIT) == 0)
	{
		sample = (void *)len_ptr + BPF_RINGBUF_HDR_SZ;
	}

done:
	return sample;
}

static void ringbuf__consume_first_event(struct ring_buffer *rb, struct ppm_evt_hdr **event_ptr, int16_t *cpu_id)
{
	struct ring *ring = &rb->rings[0];
	/* We need to check the return in the caller */
	*event_ptr = ringbuf_process_one_from_ring(ring);
}

/* This API must be used if we want to get the first event according to its timestamp */
void pman_consume_first_from_buffers(void **event_ptr, int16_t *cpu_id)
{
	ringbuf__consume_first_event(g_state.rb_manager, (struct ppm_evt_hdr **)event_ptr, cpu_id);
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
