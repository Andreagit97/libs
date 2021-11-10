/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __RING_HELPERS_H
#define __RING_HELPERS_H





static __always_inline void write_evt_hdr(struct filler_data *data)
{
	// questo è l'inizio di tutto l'evento che verrà tirato su in userspace
	struct ppm_evt_hdr *evt_hdr = (struct ppm_evt_hdr *)data->buf;

	evt_hdr->ts = data->state->tail_ctx.ts;
	// sto prendendo i 32 bit bassi, in realtà tgid e pid sono uguali, tutti i thread di quel gruppo hanno quel pid
	evt_hdr->tid = bpf_get_current_pid_tgid() & 0xffffffff;
	evt_hdr->type = data->state->tail_ctx.evt_type;
	evt_hdr->nparams = data->evt->nparams;

	// + 16 bit per ogni parametro.
	data->state->tail_ctx.curoff = sizeof(struct ppm_evt_hdr) +
				       sizeof(u16) * data->evt->nparams;

	data->state->tail_ctx.len = data->state->tail_ctx.curoff;
}











// sistemo nell'header all'inizio dell'evento la lunghezza finale
static __always_inline void fixup_evt_len(char *p, unsigned long len)
{
	struct ppm_evt_hdr *evt_hdr = (struct ppm_evt_hdr *)p;

	evt_hdr->len = len;
}




static __always_inline void fixup_evt_arg_len(char *p,
					      unsigned int argnum,
					      unsigned int arglen)
{
	if (argnum > PPM_MAX_EVENT_PARAMS)
	{
		return;
	}
	// probabilmente il verifier qui gli ha rotto.
	volatile unsigned int argnumv = argnum;
	// dico che sono puntatore a 16 bit e aggiungo quindi  il numero di argomenti che ho già passato in modo da posizionare nel posto giusto la lunghezza del parametro.
	*((u16 *)&p[sizeof(struct ppm_evt_hdr)] + (argnumv & (PPM_MAX_EVENT_PARAMS - 1))) = arglen;
}










// questa funzione scrive l'evento  nel perf buffer che ha aperto scap, che è quel file che è stato mappato in memoria.
static __always_inline int push_evt_frame(void *ctx,
					  struct filler_data *data)
{
	// significa che non ho inserito tutti gli eventi necessari
	if (data->state->tail_ctx.curarg != data->evt->nparams) {
		bpf_printk("corrupted filler for event type %d (added %u args, should have added %u)\n",
			   data->state->tail_ctx.evt_type,
			   data->state->tail_ctx.curarg,
			   data->evt->nparams);
		return PPM_FAILURE_BUG;
	}

	if (data->state->tail_ctx.len > PERF_EVENT_MAX_SIZE)
		return PPM_FAILURE_BUFFER_FULL;

	fixup_evt_len(data->buf, data->state->tail_ctx.len);

#ifdef BPF_FORBIDS_ZERO_ACCESS
	int res = bpf_perf_event_output(ctx,
					&perf_map,
					BPF_F_CURRENT_CPU,
					data->buf,
					((data->state->tail_ctx.len - 1) & SCRATCH_SIZE_MAX) + 1);
#else
	// dice quanta roba metterci nel file perf
	int res = bpf_perf_event_output(ctx,
					&perf_map,
					BPF_F_CURRENT_CPU,
					data->buf,
					data->state->tail_ctx.len & SCRATCH_SIZE_MAX);
#endif
	if (res == -ENOENT || res == -EOPNOTSUPP) {
		/*
		 * ENOENT = likely a new CPU is online that wasn't
		 *          opened in userspace
		 *
		 * EOPNOTSUPP = likely a perf channel has been closed
		 *              because a CPU went offline
		 *
		 * Schedule a hotplug event on CPU 0
		 */
		struct sysdig_bpf_per_cpu_state *state = get_local_state(0);

		if (!state)
			return PPM_FAILURE_BUG;

		state->hotplug_cpu = bpf_get_smp_processor_id();
		bpf_printk("detected hotplug event, cpu=%d\n", state->hotplug_cpu);
	} else if (res) {
		bpf_printk("bpf_perf_event_output failed, res=%d\n", res);
		return PPM_FAILURE_BUG;
	}

	return PPM_SUCCESS;
}

#endif
