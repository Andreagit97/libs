/*
Copyright (C) 2021 The Falco Authors.

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

#ifndef _SCAP_BPF_H
#define _SCAP_BPF_H

#include "compat/perf_event.h"

// un campione di evento
struct perf_event_sample {
	struct perf_event_header header;
	uint32_t size;
	char data[];
};

struct perf_lost_sample {
	struct perf_event_header header;
	uint64_t id;
	uint64_t lost;
};

int32_t scap_bpf_load(scap_t *handle, const char *bpf_probe);
int32_t scap_bpf_start_capture(scap_t *handle);
int32_t scap_bpf_stop_capture(scap_t *handle);
int32_t scap_bpf_close(scap_t *handle);
int32_t scap_bpf_set_snaplen(scap_t* handle, uint32_t snaplen);
int32_t scap_bpf_set_fullcapture_port_range(scap_t* handle, uint16_t range_start, uint16_t range_end);
int32_t scap_bpf_set_statsd_port(scap_t* handle, uint16_t port);
int32_t scap_bpf_enable_dynamic_snaplen(scap_t* handle);
int32_t scap_bpf_disable_dynamic_snaplen(scap_t* handle);
int32_t scap_bpf_enable_page_faults(scap_t* handle);
int32_t scap_bpf_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio);
int32_t scap_bpf_stop_dropping_mode(scap_t* handle);
int32_t scap_bpf_enable_tracers_capture(scap_t* handle);
int32_t scap_bpf_get_stats(scap_t* handle, OUT scap_stats* stats);
int32_t scap_bpf_get_n_tracepoint_hit(scap_t* handle, long* ret);












// ritorna il puntatore all'header seguito poi da tutti dati
// dentro data c'è un header prima di tutti i dati. quindi dal puntatore evt non prendo tutti i dati dall'inizio, controllo dei dati nell'header esterno e poi ritorno alla cattura soltanto il campo `data` di tipo scap_evt.

/// NOTA: mi sa che ci sono due header per l'evento:

// perf_event_sample che contiene un:
// - header
// - len
// - i dati -> che a loro volta sono costituiti da un hreader + 16 bit per ogni parametro + i byte dei parametri effettivamente



static inline scap_evt *scap_bpf_evt_from_perf_sample(void *evt)
{
	struct perf_event_sample *perf_evt = (struct perf_event_sample *) evt;
	ASSERT(perf_evt->header.type == PERF_RECORD_SAMPLE);
	return (scap_evt *) perf_evt->data;
}















static inline void scap_bpf_get_buf_pointers(char *buf, uint64_t *phead, uint64_t *ptail, uint64_t *pread_size)
{
	struct perf_event_mmap_page *header;
	uint64_t begin;
	uint64_t end;

	header = (struct perf_event_mmap_page *) buf;

	// chi sposta questi due puntatori a data_head e data_tail
	*phead = header->data_head;
	*ptail = header->data_tail;

	// clang-format off
	asm volatile("" ::: "memory");
	// clang-format on

	begin = *ptail % header->data_size;
	end = *phead % header->data_size;

    // la size è la differenza tra head e tail.
	if(begin > end)
	{
		*pread_size = header->data_size - begin + end;
	}
	else
	{
		*pread_size = end - begin;
	}
}














// Questa len sono i numero di byte disponibili nel buffer cur_evt
static inline int32_t scap_bpf_advance_to_evt(scap_t *handle, uint16_t cpuid, bool skip_current,
					      char *cur_evt, char **next_evt, uint32_t *len)
{
	struct scap_device *dev;
	void *base;
	void *begin;

	dev = &handle->m_devs[cpuid];

    // questo dovrebbe essere l'inizio della memoria memory mapped, la prima pagina che dovrebbe contenere un header
	// header + 2*ring_size
	struct perf_event_mmap_page *header = (struct perf_event_mmap_page *) dev->m_buffer;

	// questa dovrebbe essere la base dove inizia il vero buffer senza l'header.
	base = ((char *) header) + header->data_offset;
	// il puntatore all'evento che devo leggere
	begin = cur_evt;




	// finchè non ho lunghezza zero.
	while(*len)
	{
		// questa `e` è un puntatore a dove sono arrivato ora.
		/// NOTA: questo header lato bpf non c'è 
		struct perf_event_header *e = begin;

		// in len c'è tutta la lunghezza del buffer quando ho letto l'ultima volta
		ASSERT(*len >= sizeof(*e));
		ASSERT(*len >= e->size);
		if(e->type == PERF_RECORD_SAMPLE)
		{
#ifdef _DEBUG
			struct perf_event_sample *sample = (struct perf_event_sample *) e;
#endif
			ASSERT(*len >= sizeof(*sample));
			ASSERT(*len >= sample->size);
			ASSERT(e->size == sizeof(*e) + sizeof(sample->size) + sample->size);
			ASSERT(((scap_evt *) sample->data)->len <= sample->size);

			if(skip_current)
			{
				skip_current = false;
			}
			else
			{
				*next_evt = (char *) e;
				break;
			}
		}
		else if(e->type == PERF_RECORD_LOST)
		{
			struct perf_lost_sample *lost = (struct perf_lost_sample *) e;
			ASSERT(*len >= sizeof(*lost));
			dev->m_evt_lost += lost->lost;
		}
		else
		{
			printf("Unknown event type=%d size=%d\n",
			       e->type, e->size);
			ASSERT(false);
		}



		// riposiziono begin in base a dove sono arrivato a leggere
		
		// se ho superato la lunghezza del ring buffer
		if(begin + e->size > base + header->data_size)
		{
			begin = begin + e->size - header->data_size;
		}
		else if(begin + e->size == base + header->data_size)
		{
			begin = base;
		}
		else
		{
			begin += e->size;
		}

		// tutto quello che ho letto
		*len -= e->size;
	}

	return SCAP_SUCCESS;
}











/////////// IMPORTANTISSIMO: inizialmente mi ero segnato tutto un blocco di buffer da leggere, quando finisco di leggerlo completamente mando avanti la testa, quindi non dopo ogni evento letto, ma solo dopo un blocco. 
static inline void scap_bpf_advance_tail(scap_t *handle, uint32_t cpuid)
{
	struct perf_event_mmap_page *header;
	struct scap_device *dev;

	dev = &handle->m_devs[cpuid];
	header = (struct perf_event_mmap_page *)dev->m_buffer;

	// clang-format off
	asm volatile("" ::: "memory");
	// clang-format on

	ASSERT(dev->m_lastreadsize > 0);
	// la tail la sposto io dicendo che ho letto tutto quello che era necessario, la head la sposterà il producer, (ovvero bpf in questo caso, quando viene aggiunto qualcosa)
	header->data_tail += dev->m_lastreadsize;
	dev->m_lastreadsize = 0;
}


















static inline int32_t scap_bpf_readbuf(scap_t *handle, uint32_t cpuid, char **buf, uint32_t *len)
{
	// questo è l'header che c'è all'inzio della memoria mappata
	struct perf_event_mmap_page *header;
	struct scap_device *dev;
	uint64_t tail;
	uint64_t head;
	uint64_t read_size;
	char *p;

	dev = &handle->m_devs[cpuid];
	// inizio della memoria mappata.
	header = (struct perf_event_mmap_page *) dev->m_buffer;

	ASSERT(dev->m_lastreadsize == 0);

	scap_bpf_get_buf_pointers((char *) header, &head, &tail, &read_size);

	// viene inizializzato a tutta la differenza che c'è tra head e tail
	dev->m_lastreadsize = read_size;
	// dove leggerò il prossimo evento
	p = ((char *) header) + header->data_offset + tail % header->data_size;
	*len = read_size;

	return scap_bpf_advance_to_evt(handle, cpuid, false, p, buf, len);
}

#endif
