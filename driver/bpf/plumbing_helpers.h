/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __PLUMBING_HELPERS_H
#define __PLUMBING_HELPERS_H

#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/fdtable.h>

#include "types.h"
#include "builtins.h"

#define _READ(P) ({ typeof(P) _val;				\
		    memset(&_val, 0, sizeof(_val));		\
		    bpf_probe_read(&_val, sizeof(_val), &P);	\
		    _val;					\
		 })


// devo definire questa quando faccio il debug almeno mi stampa tutt facilmente in quel file di cui faccio il cat !!!
#ifdef BPF_DEBUG
#define bpf_printk(fmt, ...)					\
	do {							\
		char s[] = fmt;					\
		bpf_trace_printk(s, sizeof(s), ##__VA_ARGS__);	\
	} while (0)
#else
#define bpf_printk(fmt, ...)
#endif

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS



















////////////////////////////////
//  STASH AND UNSTASH SYSCALL ARGUMENT
/////////////////////////////


// qualcuno mette gli argomenti per quel pid in una mappa
static __always_inline int __stash_args(unsigned long long id,
					unsigned long *args)
{
	int ret = bpf_map_update_elem(&stash_map, &id, args, BPF_ANY);

	if (ret)
		bpf_printk("error stashing arguments for %d:%d\n", id, ret);

	return ret;
}

static __always_inline int stash_args(unsigned long *args)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	return __stash_args(id, args);
}



// dato quell pid più tid si prendono una entry in una mappa stash che non so dove sia.
static __always_inline unsigned long *__unstash_args(unsigned long long id)
{
	struct sys_stash_args *args;

	// prendo gli argomenti in base al pid con cui la sto chimando, non però chi ce li ha messi gli argomenti.!!!
	args = bpf_map_lookup_elem(&stash_map, &id);
	if (!args)
		return NULL;

	return args->args;
}


// prende pid e basta solo i 32 bassi
static __always_inline unsigned long *unstash_args(void)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	return __unstash_args(id);
}

static __always_inline void delete_args(void)
{
	unsigned long long id = bpf_get_current_pid_tgid() & 0xffffffff;

	bpf_map_delete_elem(&stash_map, &id);
}
#endif

































/* Can be called just from an exit event
 */
static __always_inline long bpf_syscall_get_retval(void *ctx)
{
	struct sys_exit_args *args = (struct sys_exit_args *)ctx;

	return args->ret;
}








/* Can be called from both enter and exit event, id is at the same
 * offset in both struct sys_enter_args and struct sys_exit_args
 */
// Ritorna id della syscall
static __always_inline long bpf_syscall_get_nr(void *ctx)
{
	struct sys_enter_args *args = (struct sys_enter_args *)ctx;
	// perchè non lo hanno preso come parametro direttamente della struct (?)
	// perchè nella struct per un tracepoint di uscita non c'è tra i due parametri immediati, solo in quello in ingresso c'è.
	long id;

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	struct pt_regs *regs = (struct pt_regs *)args->regs;

	id = _READ(regs->orig_ax);
#else
	id = args->id;
#endif

	return id;
}

#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
static __always_inline unsigned long bpf_syscall_get_argument_from_args(unsigned long *args,
									int idx)
{
	unsigned long arg;

	if (idx <= 5)
		arg = args[idx];
	else
		arg = 0;

	return arg;
}
#endif










static __always_inline unsigned long bpf_syscall_get_argument_from_ctx(void *ctx,
								       int idx)
{
	unsigned long arg;

#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	struct sys_enter_args *args = (struct sys_enter_args *)ctx;
	struct pt_regs *regs = (struct pt_regs *)args->regs;

	switch (idx) {
	case 0:
		arg = _READ(regs->di);
		break;
	case 1:
		arg = _READ(regs->si);
		break;
	case 2:
		arg = _READ(regs->dx);
		break;
	case 3:
		arg = _READ(regs->r10);
		break;
	case 4:
		arg = _READ(regs->r8);
		break;
	case 5:
		arg = _READ(regs->r9);
		break;
	default:
		arg = 0;
	}
#else
	unsigned long *args = unstash_args();

	if (args)
		arg = bpf_syscall_get_argument_from_args(args, idx);
	else
		arg = 0;
#endif

	return arg;
}

static __always_inline unsigned long bpf_syscall_get_argument(struct filler_data *data,
							      int idx)
{
#ifdef BPF_SUPPORTS_RAW_TRACEPOINTS
	return bpf_syscall_get_argument_from_ctx(data->ctx, idx);
#else
	return bpf_syscall_get_argument_from_args(data->args, idx);
#endif
}

static __always_inline char *get_frame_scratch_area(unsigned int cpu)
{
	char *scratchp;

    // questo buffer in cui inserisco la roba è ottenuto tramite una mappa bpf, a ogni cpu corrisponde un buffer.
	// quindi è un area allocata da qualcuno devo ancora capire allocata come !! non sembra esserci in scap un punto che lo fa.
	scratchp = bpf_map_lookup_elem(&frame_scratch_map, &cpu);
	if (!scratchp)
		bpf_printk("frame scratch NULL\n");

	return scratchp;
}


// come area di passaggio
static __always_inline char *get_tmp_scratch_area(unsigned int cpu)
{
	char *scratchp;

	scratchp = bpf_map_lookup_elem(&tmp_scratch_map, &cpu);
	if (!scratchp)
		bpf_printk("tmp scratch NULL\n");

	return scratchp;
}

// si ha un lookup con quella mappa che lega la syscall a eventi di ingresso e di uscita, e quindi si torna una syscall_evt_pair 
static __always_inline const struct syscall_evt_pair *get_syscall_info(int id)
{
	const struct syscall_evt_pair *p =
			bpf_map_lookup_elem(&syscall_table, &id);

	if (!p)
		bpf_printk("no syscall_info for %d\n", id);

	return p;
}

static __always_inline const struct ppm_event_info *get_event_info(enum ppm_event_type event_type)
{
	const struct ppm_event_info *e =
		bpf_map_lookup_elem(&event_info_table, &event_type);

	if (!e)
		bpf_printk("no event info for %d\n", event_type);

	return e;
}

static __always_inline const struct ppm_event_entry *get_event_filler_info(enum ppm_event_type event_type)
{
	const struct ppm_event_entry *e;

	e = bpf_map_lookup_elem(&fillers_table, &event_type);
	if (!e)
		bpf_printk("no filler info for %d\n", event_type);

	return e;
}

static __always_inline struct sysdig_bpf_settings *get_bpf_settings(void)
{
	struct sysdig_bpf_settings *settings;
	int id = 0;

	settings = bpf_map_lookup_elem(&settings_map, &id);
	if (!settings)
		bpf_printk("settings NULL\n");

	return settings;
}

static __always_inline struct sysdig_bpf_per_cpu_state *get_local_state(unsigned int cpu)
{
	struct sysdig_bpf_per_cpu_state *state;

	// prendo uno stato della cpu ma non mi sembra venga riempita questa mappa da scap
	state = bpf_map_lookup_elem(&local_state_map, &cpu);
	if (!state)
		bpf_printk("state NULL\n");

	return state;
}


// da chi ne faccio il lock (?) se ci sono io sulla cpu?
static __always_inline bool acquire_local_state(struct sysdig_bpf_per_cpu_state *state)
{
	if (state->in_use) {
		bpf_printk("acquire_local_state: already in use\n");
		return false;
	}

	state->in_use = true;
	return true;
}

static __always_inline bool release_local_state(struct sysdig_bpf_per_cpu_state *state)
{
	if (!state->in_use) {
		bpf_printk("release_local_state: already not in use\n");
		return false;
	}

	state->in_use = false;
	return true;
}

// funzione molto utile che inizializza il data_filler usato nei filler
static __always_inline int init_filler_data(void *ctx,
					    struct filler_data *data,
					    bool is_syscall)
{
	unsigned int cpu;

    // contiene i registri e i parametri come visto per il tracepoint originale.
	data->ctx = ctx;

	data->settings = get_bpf_settings();
	if (!data->settings)
		return PPM_FAILURE_BUG;

	cpu = bpf_get_smp_processor_id();

	// non è chiaro chi mi alloca questo spazio nelle mappe
	data->buf = get_frame_scratch_area(cpu);
	if (!data->buf)
		return PPM_FAILURE_BUG;

	data->state = get_local_state(cpu);
	if (!data->state)
		return PPM_FAILURE_BUG;
	
	// non è chiaro chi mi alloca questo spazio nelle mappe
	data->tmp_scratch = get_tmp_scratch_area(cpu);
	if (!data->tmp_scratch)
		return PPM_FAILURE_BUG;

	data->evt = get_event_info(data->state->tail_ctx.evt_type);
	if (!data->evt)
		return PPM_FAILURE_BUG;

	data->filler_info = get_event_filler_info(data->state->tail_ctx.evt_type);
	if (!data->filler_info)
		return PPM_FAILURE_BUG;

// è un ifndef a me non interessa !!!
#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
	if (is_syscall) {
		data->args = unstash_args();
		if (!data->args)
			return PPM_SKIP_EVENT;
	}
#endif

	data->curarg_already_on_frame = false;
	data->fd = -1;

	return PPM_SUCCESS;
}

static __always_inline int bpf_test_bit(int nr, unsigned long *addr)
{
	return 1UL & (_READ(addr[BIT_WORD(nr)]) >> (nr & (BITS_PER_LONG - 1)));
}





















static __always_inline bool drop_event(void *ctx,
				       struct sysdig_bpf_per_cpu_state *state,
				       enum ppm_event_type evt_type,
				       struct sysdig_bpf_settings *settings,
				       enum syscall_flags drop_flags)
{
	///NOTA: il drop avviene a due livelli da un lato dentro la setting map settata da scap deve esserci il flag che dice di droppare
	// e inoltre l'evento deve avere tra i suoi flag l'opzione per essere droppato.
	if (!settings->dropping_mode)
		return false;

	// per alcune syscall droppo solo in alcuni casi
	switch (evt_type) {
	// qui droppo solo se è fallita la syscall		
	case PPME_SYSCALL_CLOSE_X:
	case PPME_SOCKET_BIND_X: {
		long ret = bpf_syscall_get_retval(ctx);

		if (ret < 0)
			return true;

		break;
	}
	case PPME_SYSCALL_CLOSE_E: {
		struct sys_enter_args *args;
		struct files_struct *files;
		struct task_struct *task;
		unsigned long *open_fds;
		struct fdtable *fdt;
		int close_fd;
		int max_fds;

		close_fd = bpf_syscall_get_argument_from_ctx(ctx, 0);
		if (close_fd < 0)
			return true;

		task = (struct task_struct *)bpf_get_current_task();
		if (!task)
			break;

		files = _READ(task->files);
		if (!files)
			break;

		fdt = _READ(files->fdt);
		if (!fdt)
			break;

		max_fds = _READ(fdt->max_fds);
		if (close_fd >= max_fds)
			return true;

		open_fds = _READ(fdt->open_fds);
		if (!open_fds)
			break;

		if (!bpf_test_bit(close_fd, open_fds))
			return true;

		break;
	}
	case PPME_SYSCALL_FCNTL_E:
	case PPME_SYSCALL_FCNTL_X: {
		long cmd = bpf_syscall_get_argument_from_ctx(ctx, 1);

		if (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC)
			return true;

		break;
	}
	default:
		break;
	}

	if (drop_flags & UF_NEVER_DROP)
		return false;

	/// IMPORTANTE: su tutte le nostre syscall ne droppiamo 42 
	if (drop_flags & UF_ALWAYS_DROP)
		return true;

	// una logica sul drop con dei tempi 
	if (state->tail_ctx.ts % 1000000000 >= 1000000000 / settings->sampling_ratio) {
		if (!settings->is_dropping) {
			settings->is_dropping = true;
			state->tail_ctx.evt_type = PPME_DROP_E;
			return false;
		}

		return true;
	}

	if (settings->is_dropping) {
		settings->is_dropping = false;
		state->tail_ctx.evt_type = PPME_DROP_X;
		return false;
	}

	return false;
}
































// tail context penso che sia quello che poi passeremo al filler.
static __always_inline void reset_tail_ctx(struct sysdig_bpf_per_cpu_state *state,
					   enum ppm_event_type evt_type,
					   unsigned long long ts)
{
	state->tail_ctx.evt_type = evt_type;
	state->tail_ctx.ts = ts;
	state->tail_ctx.curarg = 0;
	state->tail_ctx.curoff = 0;
	state->tail_ctx.len = 0;
	state->tail_ctx.prev_res = 0;
}

























// preambolo prima di chimare il filler
static __always_inline void call_filler(void *ctx,
					void *stack_ctx,
					enum ppm_event_type evt_type,
					struct sysdig_bpf_settings *settings,
					enum syscall_flags drop_flags)
{
	const struct ppm_event_entry *filler_info;
	struct sysdig_bpf_per_cpu_state *state;
	unsigned long long pid;
	unsigned long long ts;
	unsigned int cpu;

	// mi segno l'id della cpu dalla quale ho preso il controllo in questo programma bpf
	cpu = bpf_get_smp_processor_id();

	// mappa che ha una entry per ogni cpu con questa struttura.
	state = get_local_state(cpu);
	if (!state)
		return;

	// avrebbe senso solo se più filler prendessero il controllo della stessa cpu nello stesso momento. ma un filler bpf non può essere interrotto.
	if (!acquire_local_state(state))
		return;

	if (cpu == 0 && state->hotplug_cpu != 0) {
		evt_type = PPME_CPU_HOTPLUG_E;
		drop_flags = UF_NEVER_DROP;
	}

	// tempo di adesso
	ts = settings->boot_time + bpf_ktime_get_ns();
	reset_tail_ctx(state, evt_type, ts);

	/* drop_event can change state->tail_ctx.evt_type */
	/// IL DROP VA SPOSTATO A PRIMA APPENA PARTE IL FILLER E SE POSSIBILE DEVE ESSERE RINFORZATO:, poche syscall vengono droppate.
	// non ha troppo senso tenerlo qui se l'evento viene droppato
	if (drop_event(stack_ctx, state, evt_type, settings, drop_flags))
		goto cleanup;

	// incremento eventi totali visti dalla cpu. Nota gli eventi droppati non vengono salvati
	++state->n_evts;

	filler_info = get_event_filler_info(state->tail_ctx.evt_type);
	if (!filler_info)
		goto cleanup;


	/// NOTA: questo helper serve per chiamare un altro programma bpf,
	// dal filler id nella mappa mi sono segnato il flile descriptor del giusot programma bpf da chaimare.
	// questa funzione ritorna solo in caso di errore.
	bpf_tail_call(ctx, &tail_map, filler_info->filler_id);
	bpf_printk("Can't tail call filler evt=%d, filler=%d\n",
		   state->tail_ctx.evt_type,
		   filler_info->filler_id);

// se la bpf_tail_call non torna in caso di successo chi mette a posto il flag nella mappa dello stato?
/// IMPORTANTE: viene rilasciato poi dal terminte filler.
cleanup:
	release_local_state(state);
}

#endif
