/*

Copyright (C) 2021 The Falco Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __MAPS_H
#define __MAPS_H

// Dentro l'elf BPF sembra esserci una lista di mappe, non è chiaro il perchè
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
};


/// NOTA: max entry qui sono zero, poi sarà il loader a dare una entry per ogni cpu, quando legge le info dall'elf, io ovviamente nell'elf del probe non so quante cpu avrà il sistema su cui andrà a girare.

// Nell'elf vengono scritte queste info che poi vengono collezionate in una struttura come quella sopra `bpf_map_def`.
#ifdef __KERNEL__




/// CONTENUTO: ogni cpu ha una entry, in questa mappa, la chiave è il numero della cpu mentre il valore è il fd di questo perf buffer aoerto
struct bpf_map_def __bpf_section("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 0,
};






/// READONLY:
/// CONTENUTO: questa contiene come chiave l'id del filler e come valore il fd del bpf programm corrispondente a quel filler.
struct bpf_map_def __bpf_section("maps") tail_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = PPM_FILLER_MAX,
};





/// READONLY:
/// CONTENUTO: ha come chiave ho il codice di sistema della syscall, come valore ho il codice PPM_ stabilito dalla nostra rappresentazione interna. 
struct bpf_map_def __bpf_section("maps") syscall_code_routing_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = SYSCALL_TABLE_SIZE,
};




/// READONLY:
/// CONTENUTO: ha come chiave ho il codice di sistema della syscall, come valore i due eventi di entry e di exit associati alla syscall.
struct bpf_map_def __bpf_section("maps") syscall_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct syscall_evt_pair),
	.max_entries = SYSCALL_TABLE_SIZE,
};




/// READONLY:
/// CONTENUTO: scontato. 
struct bpf_map_def __bpf_section("maps") event_info_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct ppm_event_info),
	.max_entries = PPM_EVENT_MAX,
};





/// READONLY:
/// CONTENUTO: scontato.
struct bpf_map_def __bpf_section("maps") fillers_table = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct ppm_event_entry),
	.max_entries = PPM_EVENT_MAX,
};




struct bpf_map_def __bpf_section("maps") frame_scratch_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = SCRATCH_SIZE,
	.max_entries = 0,
};


struct bpf_map_def __bpf_section("maps") tmp_scratch_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = SCRATCH_SIZE,
	.max_entries = 0,
};


/// READONLY:
/// CONTENT: un unica struct con alcune informazioni messe da scap
// ha una sola entry, viene ritoccata da diverse funzioni in scap ma al momento non troppo rilevante.
struct bpf_map_def __bpf_section("maps") settings_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sysdig_bpf_settings),
	.max_entries = 1,
};


/// CONTENT: si ha una entry per ogni cpu
struct bpf_map_def __bpf_section("maps") local_state_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sysdig_bpf_per_cpu_state),
	.max_entries = 0,
};





















#ifndef BPF_SUPPORTS_RAW_TRACEPOINTS
struct bpf_map_def __bpf_section("maps") stash_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(struct sys_stash_args),
	.max_entries = 65535,
};
#endif

#endif // __KERNEL__

#endif
