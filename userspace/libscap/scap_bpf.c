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

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#ifndef MINIMAL_BUILD
#include <gelf.h>
#endif // MINIMAL_BUILD
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <dirent.h>

#include "scap.h"
#include "scap-int.h"
#include "scap_bpf.h"
#include "driver_config.h"
#include "../../driver/bpf/types.h"
#include "../../driver/bpf/maps.h"
#include "compat/misc.h"
#include "compat/bpf.h"

//
// Some of this code is taken from the kernel samples under samples/bpf,
// namely the parsing of the ELF objects, which is very tedious and not
// worth reinventing from scratch. The code has been readapted and simplified
// to tailor our use case. In the future, a full switch to libbpf
// is possible, but at the moment is not very worth the effort considering the
// subset of features needed.
//


// si sono importati parecchio codice per fare il loader bpf


// struttura che contiene tutte le info della mappa
struct bpf_map_data {
	int fd; // il fd non viene riempito assieme agli altri due campi
	size_t elf_offset;
	struct bpf_map_def def;
};

static const int BUF_SIZE_PAGES = 2048;

static const int BPF_LOG_SIZE = 1 << 18;

static char* license;

#define FILLER_NAME_FN(x) #x,
static const char *g_filler_names[PPM_FILLER_MAX] = {
	FILLER_LIST_MAPPER(FILLER_NAME_FN)
};
#undef FILLER_NAME_FN

// questa è la chiamata alla syscall bpf.
static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int sys_perf_event_open(struct perf_event_attr *attr,
			       pid_t pid, int cpu, int group_fd,
			       unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}


// dato il nome del filler che si ottiene da `raw_tracepoint/filler/sys_chmod_x`, ovvero il nome della sezione 
static int32_t lookup_filler_id(const char *filler_name)
{
	int j;

	for(j = 0; j < sizeof(g_filler_names) / sizeof(g_filler_names[0]); ++j)
	{
		if(strcmp(filler_name, g_filler_names[j]) == 0)
		{
			return j;
		}
	}

	return -1;
}




// richiamano poi tutte la syscall sys_bpf
static int bpf_map_update_elem(int fd, const void *key, const void *value, uint64_t flags)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));

	attr.map_fd = fd; /// IMPORTANTE: questo stabilisce che mappa devo andare ad aggiornare.
	attr.key = (unsigned long) key;
	attr.value = (unsigned long) value;
	attr.flags = flags;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));

	attr.map_fd = fd;
	attr.key = (unsigned long) key;
	attr.value = (unsigned long) value;

	return sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int bpf_map_create(enum bpf_map_type map_type,
			  int key_size, int value_size, int max_entries,
			  uint32_t map_flags)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));

	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	attr.map_flags = map_flags;

	// crea queste mappe nel kernel che hannp le info prese dall'elf, ma non hanno ancora nessuna entry.
	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}











//////////////////////////////////
//////////////////////////////////
// carico un programma bpf nel kernel e mi torna un file descriptor
//////////////////////////////////
//////////////////////////////////

// carico un programma bpf nel kernel e mi torna un file descriptor
static int bpf_load_program(const struct bpf_insn *insns,
			    enum bpf_prog_type type,
			    size_t insns_cnt,
			    char *log_buf,
			    size_t log_buf_sz)
{
	union bpf_attr attr;
	int fd;

	bzero(&attr, sizeof(attr));

	attr.prog_type = type;
	attr.insn_cnt = (uint32_t) insns_cnt;
	attr.insns = (unsigned long) insns;
	attr.license = (unsigned long) license;
	attr.log_buf = (unsigned long) NULL;
	attr.log_size = 0;
	attr.log_level = 0;

	fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
	if(fd >= 0 || !log_buf || !log_buf_sz)
	{
		return fd;
	}

	attr.log_buf = (unsigned long) log_buf;
	attr.log_size = log_buf_sz;
	attr.log_level = 1;
	log_buf[0] = 0;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}









static int bpf_raw_tracepoint_open(const char *name, int prog_fd)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.raw_tracepoint.name = (unsigned long) name;
	attr.raw_tracepoint.prog_fd = prog_fd;

	return sys_bpf(BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
}











#ifndef MINIMAL_BUILD
static int32_t get_elf_section(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname, GElf_Shdr *shdr, Elf_Data **data)
{
	Elf_Scn *scn = elf_getscn(elf, i);
	if(!scn)
	{
		return SCAP_FAILURE;
	}

	if(gelf_getshdr(scn, shdr) != shdr)
	{
		return SCAP_FAILURE;
	}

	*shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
	if(!*shname || !shdr->sh_size)
	{
		return SCAP_FAILURE;
	}

	*data = elf_getdata(scn, 0);
	if(!*data || elf_getdata(scn, *data) != NULL)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

static int cmp_symbols(const void *l, const void *r)
{
	const GElf_Sym *lsym = (const GElf_Sym *)l;
	const GElf_Sym *rsym = (const GElf_Sym *)r;

	if(lsym->st_value < rsym->st_value)
	{
		return -1;
	}
	else if(lsym->st_value > rsym->st_value)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}












///////////////////////////////////////////////////////
///////////////////////////////////////////////////////
// CARCIO LE MAPPE DALL'ELF FILE E POI LE POSIZIONO NEL KERNEL (LOAD PHASE)
///////////////////////////////////////////////////////
///////////////////////////////////////////////////////



static int32_t load_elf_maps_section(scap_t *handle, struct bpf_map_data *maps,
				     int maps_shndx, Elf *elf, Elf_Data *symbols,
				     int strtabidx, int *nr_maps)
{
	Elf_Data *data_maps;
	GElf_Sym *sym;
	Elf_Scn *scn;
	int i;

	scn = elf_getscn(elf, maps_shndx);
	if(scn)
	{
		data_maps = elf_getdata(scn, NULL);
	}

	if(!scn || !data_maps)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Failed to get Elf_Data from maps section %d", maps_shndx);
		return SCAP_FAILURE;
	}

	// lo devo stabilire qua il numero di mappe.
	*nr_maps = 0;
	// non so quante sono quindi ne alloco al massimo
	sym = calloc(BPF_MAPS_MAX + 1, sizeof(GElf_Sym));
	for(i = 0; i < symbols->d_size / sizeof(GElf_Sym); i++)
	{
		ASSERT(*nr_maps < BPF_MAPS_MAX + 1);
		if(!gelf_getsym(symbols, i, &sym[*nr_maps]))
		{
			continue;
		}

		if(sym[*nr_maps].st_shndx != maps_shndx)
		{
			continue;
		}

		(*nr_maps)++;
	}

	qsort(sym, *nr_maps, sizeof(GElf_Sym), cmp_symbols);

	// controllo che le mappe che ho contato corrispondano con il numero di dati che trovo nell'elf
	ASSERT(data_maps->d_size / *nr_maps == sizeof(struct bpf_map_def));

	for(i = 0; i < *nr_maps; i++)
	{
		// struttura che contiene tutte le info sulle mappe
		struct bpf_map_def *def;
		size_t offset;

		offset = sym[i].st_value;
		// nell'elf ho letto un unico grande blocco che contiene tutte le info sulle mappe
		// e adesso riempio quel vettore con tutte le info sulla mappa che ho scritto 
		def = (struct bpf_map_def *)(data_maps->d_buf + offset);
		// offset ll'interno del file elf.
		maps[i].elf_offset = offset;
		memcpy(&maps[i].def, def, sizeof(struct bpf_map_def));
	}

	free(sym);
	return SCAP_SUCCESS;
}
#endif // MINIMAL_BUILD




static int32_t load_maps(scap_t *handle, struct bpf_map_data *maps, int nr_maps)
{
	int j;

    /// IMPORTANTE: si ha un ordine nel caricamento del'elf si sa già che un particolare indice corrisponderà a un certo tipo di mappa bpf.
	for(j = 0; j < nr_maps; ++j)
	{
		// questo sono le uniche che hanno una entry per ogni cpu.
		if(j == SYSDIG_PERF_MAP ||
		   j == SYSDIG_LOCAL_STATE_MAP ||
		   j == SYSDIG_FRAME_SCRATCH_MAP ||
		   j == SYSDIG_TMP_SCRATCH_MAP)
		{
			/// NOTE: una entry per ogni CPU, per queste mappe
			maps[j].def.max_entries = handle->m_ncpus;
		}

		// ogni mappa ha un file descriptor quando viene creata.
		handle->m_bpf_map_fds[j] = bpf_map_create(maps[j].def.type,
							  maps[j].def.key_size,
							  maps[j].def.value_size,
							  maps[j].def.max_entries,
							  maps[j].def.map_flags);

		maps[j].fd = handle->m_bpf_map_fds[j];

		if(handle->m_bpf_map_fds[j] < 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't create map: %s", scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		// Ne esiste solo una di questo tipo `tail_map`.
		if(maps[j].def.type == BPF_MAP_TYPE_PROG_ARRAY)
		{
			handle->m_bpf_prog_array_map_idx = j;
		}
	}

	return SCAP_SUCCESS;
}
























/////////////////////
// non ben capito l'utilizzo
////////////////////

#ifndef MINIMAL_BUILD
static int32_t parse_relocations(scap_t *handle, Elf_Data *data, Elf_Data *symbols,
				 GElf_Shdr *shdr, struct bpf_insn *insn,
				 struct bpf_map_data *maps, int nr_maps)
{
	int nrels;
	int i;

	nrels = shdr->sh_size / shdr->sh_entsize;

	for(i = 0; i < nrels; i++)
	{
		GElf_Sym sym;
		GElf_Rel rel;
		unsigned int insn_idx;
		bool match = false;
		int map_idx;

		gelf_getrel(data, i, &rel);

		insn_idx = rel.r_offset / sizeof(struct bpf_insn);

		gelf_getsym(symbols, GELF_R_SYM(rel.r_info), &sym);

		if(insn[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid relocation for insn[%d].code 0x%x", insn_idx, insn[insn_idx].code);
			return SCAP_FAILURE;
		}

		insn[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;

		for(map_idx = 0; map_idx < nr_maps; map_idx++)
		{
			if(maps[map_idx].elf_offset == sym.st_value)
			{
				match = true;
				break;
			}
		}

		if(match)
		{
			insn[insn_idx].imm = maps[map_idx].fd;
		}
		else
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid relocation for insn[%d] no map_data match\n", insn_idx);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}
#endif // MINIMAL_BUILD


// Carico tracepoint e filler.
// l'event come paramtero sarebbe il nome della sezione quindi per esempio `raw_tracepoint/filler/sys_chmod_x`
static int32_t load_tracepoint(scap_t* handle, const char *event, struct bpf_insn *prog, int size)
{
	struct perf_event_attr attr = {};
	enum bpf_prog_type program_type;
	size_t insns_cnt;
	char buf[256];
	bool raw_tp;
	int efd;
	int err;
	int fd;
	int id;

	insns_cnt = size / sizeof(struct bpf_insn);

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

	char *error = malloc(BPF_LOG_SIZE);
	if(!error)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "malloc(BPF_LOG_BUF_SIZE)");
		return SCAP_FAILURE;
	}

	///NOTA: raw_tracepoint è solo una nostra parola chiave
	// guardo se è un evento di tipo raw oppure no e in ogni caso vado avanti con il nome della sezione quindi magari mi rimarrà solo `filler/sys_chmod_x`
	if(memcmp(event, "raw_tracepoint/", sizeof("raw_tracepoint/") - 1) == 0)
	{
		raw_tp = true;
		// il caricamento avviene in base al tipo di programma bpf
		program_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
		event += sizeof("raw_tracepoint/") - 1;
	}
	else
	{
		raw_tp = false;
		program_type = BPF_PROG_TYPE_TRACEPOINT;
		event += sizeof("tracepoint/") - 1;
	}

	if(*event == 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "event name cannot be empty");
		return SCAP_FAILURE;
	}






	fd = bpf_load_program(prog, program_type, insns_cnt, error, BPF_LOG_SIZE);
	if(fd < 0)
	{
		fprintf(stderr, "%s", error);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "bpf_load_program() err=%d event=%s message=%s", errno, event, error);
		free(error);
		return SCAP_FAILURE;
	}

	free(error);

	// tabella che tiene i file descriptor di tutti i programmi bpf, compresi quelli per i filler, io carico tutti i programmi bpf sia dei filller sia quelli generici `sys_enter`, `sys_exit`, poi per quelli generici andrò a sovrascrivere questo fd con il fde di quando lo apro -> vedi dopo.
	/// NOTA: io associo veramente ai tracepoint del kernel solo i programmi di alto livello non i filler, quelli verranno chiamati indirettamente poi da questi programmi
	handle->m_bpf_prog_fds[handle->m_bpf_prog_cnt++] = fd;


	///FILLER: se ho un filler
	// ho caricato i programmi corrspondenti ai filler nel kernel e ho associato il codice del filler al file descriptor di quel programma per il fller, ho messo quesat mapping in una mappa bpf chiamata tail_map. fatto questo ritorno e passo alla prossima sezione nel file header
	if(memcmp(event, "filler/", sizeof("filler/") - 1) == 0)
	{
		int prog_id;

		//tolgo la parte del filler dal nome della sezione così mi rimane solo il nome della syscall.
		event += sizeof("filler/") - 1;
		if(*event == 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "filler name cannot be empty");
			return SCAP_FAILURE;
		}

		// prendo l'id del filler in base a come li metto io in tabella, quando li aggiungo.
		prog_id = lookup_filler_id(event);
		if(prog_id == -1)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid filler name: %s", event);
			return SCAP_FAILURE;
		}

        // ho caricato il programma bpf ho ottenuto il fd e in una precisa mappa vdo a mettere questa info, ovvero associo il file descriptor del programma bpf a l'id del filler preso da quella tabella.
		// in chiave metto l'id del filler mentre il valore è il file descriptor associato.
		err = bpf_map_update_elem(handle->m_bpf_map_fds[handle->m_bpf_prog_array_map_idx], &prog_id, &fd, BPF_ANY);
		if(err < 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "failure populating program array");
			return SCAP_FAILURE;
		}

		handle->m_bpf_fillers[prog_id] = true;

		return SCAP_SUCCESS;
	}






    /// ATTENZIONE: qui associo al giusto evento `sys_enter`, il programma bpf corretto che poi chiamerà tutti i filler necessari. 
	if(raw_tp)
	{
		// in event è rimasto solo `sys_enter` per esempio
		// quindi associo questo programma bpf al tracepoint `sys_enter`.
		efd = bpf_raw_tracepoint_open(event, fd);
		if(efd < 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "BPF_RAW_TRACEPOINT_OPEN: event %s: %s", event, scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}
	}
	else
	{
		strcpy(buf, "/sys/kernel/debug/tracing/events/");
		strcat(buf, event);
		strcat(buf, "/id");

		efd = open(buf, O_RDONLY, 0);
		if(efd < 0)
		{
			if(strcmp(event, "exceptions/page_fault_user") == 0 ||
			strcmp(event, "exceptions/page_fault_kernel") == 0)
			{
				return SCAP_SUCCESS;
			}

			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "failed to open event %s", event);
			return SCAP_FAILURE;
		}

		err = read(efd, buf, sizeof(buf));
		if(err < 0 || err >= sizeof(buf))
		{
			close(efd);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "read from '%s' failed '%s'", event, scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		close(efd);

		buf[err] = 0;
		id = atoi(buf);
		attr.config = id;

		efd = sys_perf_event_open(&attr, -1, 0, -1, 0);
		if(efd < 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "event %d fd %d err %s", id, efd, scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		if(ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd))
		{
			close(efd);
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "PERF_EVENT_IOC_SET_BPF: %s", scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}
	}

	// aggiorno il fd del program bpf associato al raw_tracepoint
	handle->m_bpf_event_fd[handle->m_bpf_prog_cnt - 1] = efd;

	return SCAP_SUCCESS;
}






























#ifndef MINIMAL_BUILD
static int32_t load_bpf_file(scap_t *handle, const char *path)
{
	int j;
	int maps_shndx = 0;
	int strtabidx = 0;
	GElf_Shdr shdr;
	GElf_Shdr shdr_prog;
	Elf_Data *data;
	Elf_Data *data_prog;
	Elf_Data *symbols = NULL;
	char *shname;
	char *shname_prog;
	int nr_maps = 0;

	// struttura che conterrà tutto quello che estraggo dall'elf sulle mappe e mi servirà per caricarle
	struct bpf_map_data maps[BPF_MAPS_MAX];
	struct utsname osname;
	int32_t res = SCAP_FAILURE;

	// prendo la versione del OS
	if(uname(&osname))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't call uname()");
		return SCAP_FAILURE;
	}

	if(elf_version(EV_CURRENT) == EV_NONE)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid ELF version");
		return SCAP_FAILURE;
	}






	// apro l'elf bpf passato con la variabile di ambiente BPF
	int program_fd = open(path, O_RDONLY, 0);
	if(program_fd < 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open BPF probe '%s': %s", path, scap_strerror(handle, errno));
		return SCAP_FAILURE;
	}


	// è un file elf, "probe.o"
	Elf *elf = elf_begin(program_fd, ELF_C_READ_MMAP_PRIVATE, NULL);
	if(!elf)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't read ELF format");
		goto cleanup;
	}

	GElf_Ehdr ehdr;
	if(gelf_getehdr(elf, &ehdr) != &ehdr)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't read ELF header");
		goto cleanup;
	}









    // analizzo elf headers del bpf probe e vedo se va tutto bene 
	// l'header elf ha diverse info all'interno
	for(j = 0; j < ehdr.e_shnum; ++j)
	{
		if(get_elf_section(elf, j, &ehdr, &shname, &shdr, &data) != SCAP_SUCCESS)
		{
			continue;
		}

		// trovo la sezione delle mappe e mi segno la posizione nell'header elf
		if(strcmp(shname, "maps") == 0)
		{
			// indice a cui trovo le mappe
			maps_shndx = j;
		}
		else if(shdr.sh_type == SHT_SYMTAB)
		{   
			// symbol table
			strtabidx = shdr.sh_link;
			symbols = data;
		}
		else if(strcmp(shname, "kernel_version") == 0) {
			if(strcmp(osname.release, data->d_buf))
			{
				// questo è il problema che salta fuori ogni tanto, quando lo compilo in libs
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "BPF probe is compiled for %s, but running version is %s",
					 (char *) data->d_buf, osname.release);
				goto cleanup;
			}
		}
		else if(strcmp(shname, "probe_version") == 0) {
			if(strcmp(PROBE_VERSION, data->d_buf))
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "BPF probe version is %s, but running version is %s",
					 (char *) data->d_buf, PROBE_VERSION);
				goto cleanup;
			}
		}
		else if(strcmp(shname, "license") == 0)
		{
			license = data->d_buf;
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "BPF probe license is %s", license);
		}
	}





	// se non ci sono simboli errore. sezione symbol table mancante
	if(!symbols)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "missing SHT_SYMTAB section");
		goto cleanup;
	}




	/// MAPPE: ........
	// se ho trovato l'indice prima
	if(maps_shndx)
	{
		// finita questa funzione ho preso tutto il contenuto dall elf, quindi tutte le info sulle mappe, il tipo, il numeor di entry, l'offset che hanno nell'elf, ecc...
		// e ho messo tutto in questo vettore di strutture maps che è sovraallocato a 32+1.
		// da qui ritorno anche il vero numero di mappe inn nr_maps.
		if(load_elf_maps_section(handle, maps, maps_shndx, elf, symbols, strtabidx, &nr_maps) != SCAP_SUCCESS)
		{
			goto cleanup;
		}

		// chiamo proprio la syscall bpf e carico le mappe nel kernel ora sono pronte per essere utilizzate.
		if(load_maps(handle, maps, nr_maps) != SCAP_SUCCESS)
		{
			goto cleanup;
		}
	}

    // INFO su relocation ma non so bene cosa sia (?).
	for(j = 0; j < ehdr.e_shnum; ++j)
	{
		if(get_elf_section(elf, j, &ehdr, &shname, &shdr, &data) != SCAP_SUCCESS)
		{
			continue;
		}

		if(shdr.sh_type == SHT_REL)
		{
			struct bpf_insn *insns;

			if(get_elf_section(elf, shdr.sh_info, &ehdr, &shname_prog, &shdr_prog, &data_prog) != SCAP_SUCCESS)
			{
				continue;
			}

			insns = (struct bpf_insn *) data_prog->d_buf;

			if(parse_relocations(handle, data, symbols, &shdr, insns, maps, nr_maps))
			{
				continue;
			}
		}
	}

	
	
	
	
	// 
	for(j = 0; j < ehdr.e_shnum; ++j)
	{
		// prendo una sezione per volta e ne vedo il nome
		if(get_elf_section(elf, j, &ehdr, &shname, &shdr, &data) != SCAP_SUCCESS)
		{
			continue;
		}

		//shname sta per section name, cerca tutte le sezioni che iniziano per raw_tracepoint/
		/// NOTA: anche i filler iniziano così. 
		if(memcmp(shname, "tracepoint/", sizeof("tracepoint/") - 1) == 0 ||
		   memcmp(shname, "raw_tracepoint/", sizeof("raw_tracepoint/") - 1) == 0)
		{
			if(load_tracepoint(handle, shname, data->d_buf, data->d_size) != SCAP_SUCCESS)
			{
				goto cleanup;
			}
		}
	}

	res = SCAP_SUCCESS;
cleanup:
	elf_end(elf);
	close(program_fd);
	return res;
}
#endif // MINIMAL_BUILD
























// mappo quel file descriptor con un buffer in memoria, il cosidetto ring buffer
static void *perf_event_mmap(scap_t *handle, int fd)
{
	// The function getpagesize() returns the number of bytes in a memory page, where "page" is a fixed-length block, the unit for memory allocation and file mapping performed by mmap.
	int page_size = getpagesize();
	int ring_size = page_size * BUF_SIZE_PAGES; //2048 pagine fi ram
	int header_size = page_size; // l'header sat su una pagina
	int total_size = ring_size * 2 + header_size;

	//
	// All this playing with MAP_FIXED might be very very wrong, revisit
	//

	// map or unmap files or devices into memory.
	/// NOTA: il probe bpf probabilmente andrà a scrivere nel file e il programma che sta sopra, sysdig o falco si troverà in memoria ciò che è stato scritto. 
	// in tmp ho l'indirizzo del primo mapping, ma questo mapping non è legato a nessun file.
	void *tmp = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(tmp == MAP_FAILED)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "mmap (1): %s", scap_strerror(handle, errno));
		return MAP_FAILED;
	}

	// Map the second copy to allow us to handle the wrap case normally
	/// NOTA: qui ho l'indirizzo di un secondo mapping a circa metà della dimensione non so perchè (?)
	void *p1 = mmap(tmp + ring_size, ring_size + header_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
	if(p1 == MAP_FAILED)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "mmap (2): %s", scap_strerror(handle, errno));
		munmap(tmp, total_size);
		return MAP_FAILED;
	}

	ASSERT(p1 == tmp + ring_size);

	// Map the main copy
	void *p2 = mmap(tmp, ring_size + header_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
	if(p2 == MAP_FAILED)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "mmap (3): %s", scap_strerror(handle, errno));
		munmap(tmp, total_size);
		return MAP_FAILED;
	}

	/// NOTA: fa 3 mapping.
	// 1. non associa il mapping a un file preciso e infatti nonviene associato nessun file descriptor al mapping
	// 2. fa un mapping principale ("main") di dimensione ring_size+header_size
	// 3. e un secondo mapping se vogliamo sovrapposto che parte da tmp+ring_size e ha la stessa dimensione.

	ASSERT(p2 == tmp);

	return tmp;
}

static int32_t populate_syscall_routing_table_map(scap_t *handle)
{
	int j;

	for(j = 0; j < SYSCALL_TABLE_SIZE; ++j)
	{
		long code = g_syscall_code_routing_table[j];
		// j contiene il numero della syscall del sistema e code contiene il numero relativo della nostra definizione interna.
		// quindi riempio questa mappa bpf già caricata nel kernel
		if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SYSCALL_CODE_ROUTING_TABLE], &j, &code, BPF_ANY) != 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SYSCALL_CODE_ROUTING_TABLE bpf_map_update_elem < 0");
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

static int32_t populate_syscall_table_map(scap_t *handle)
{
	int j;

	for(j = 0; j < SYSCALL_TABLE_SIZE; ++j)
	{
		const struct syscall_evt_pair *p = &g_syscall_table[j];
		if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SYSCALL_TABLE], &j, p, BPF_ANY) != 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SYSCALL_TABLE bpf_map_update_elem < 0");
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

static int32_t populate_event_table_map(scap_t *handle)
{
	int j;

	for(j = 0; j < PPM_EVENT_MAX; ++j)
	{
		const struct ppm_event_info *e = &g_event_info[j];
		if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_EVENT_INFO_TABLE], &j, e, BPF_ANY) != 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_EVENT_INFO_TABLE bpf_map_update_elem < 0");
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

static int32_t populate_fillers_table_map(scap_t *handle)
{
	int j;

	for(j = 0; j < PPM_EVENT_MAX; ++j)
	{
		const struct ppm_event_entry *e = &g_ppm_events[j];
		if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_FILLERS_TABLE], &j, e, BPF_ANY) != 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_FILLERS_TABLE bpf_map_update_elem < 0");
			return SCAP_FAILURE;
		}
	}


	// è un check per vedere se li ho messi tutti.
	for(j = 0; j < PPM_FILLER_MAX; ++j)
	{
		if(!handle->m_bpf_fillers[j])
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Missing filler %d (%s)\n", j, g_filler_names[j]);
			return SCAP_FAILURE;
		}
	}

	return SCAP_SUCCESS;
}

//
// This is needed to make sure that the driver can properly
// lookup sockets. We generate a fake socket system call
// at the beginning so the calibration will surely take place.
// For more info, read the corresponding filler in kernel space.
//
static int32_t calibrate_socket_file_ops()
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1)
	{
		return SCAP_FAILURE;
	}

	close(fd);
	return SCAP_SUCCESS;
}



int32_t scap_bpf_start_capture(scap_t *handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	// prendo il primo elemento della mappa con indice 0, e setto la cattura.
	/// ATTENTION: da capire cosa significa questo flag abilitato. 
	// aggiorno questo flag nella mappa bpf.
	settings.capture_enabled = true;

	// aggiorno lo stesso elemento
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	if(calibrate_socket_file_ops() != SCAP_SUCCESS)
	{
		ASSERT(false);
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "calibrate_socket_file_ops");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_stop_capture(scap_t *handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.capture_enabled = false;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_set_snaplen(scap_t* handle, uint32_t snaplen)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(snaplen > RW_MAX_SNAPLEN)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "snaplen can't exceed %d\n", RW_MAX_SNAPLEN);
		return SCAP_FAILURE;
	}

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.snaplen = snaplen;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_set_fullcapture_port_range(scap_t* handle, uint16_t range_start, uint16_t range_end)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.fullcapture_port_range_start = range_start;
	settings.fullcapture_port_range_end = range_end;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_set_statsd_port(scap_t* const handle, const uint16_t port)
{
	struct sysdig_bpf_settings settings = {};
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.statsd_port = port;

	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_disable_dynamic_snaplen(scap_t* handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.do_dynamic_snaplen = false;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_start_dropping_mode(scap_t* handle, uint32_t sampling_ratio)
{
	switch(sampling_ratio)
	{
		case 1:
		case 2:
		case 4:
		case 8:
		case 16:
		case 32:
		case 64:
		case 128:
			break;
		default:
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "invalid sampling ratio size");
			return SCAP_FAILURE;
	}

	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.sampling_ratio = sampling_ratio;
	settings.dropping_mode = true;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_stop_dropping_mode(scap_t* handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.sampling_ratio = 1;
	settings.dropping_mode = false;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_enable_dynamic_snaplen(scap_t* handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.do_dynamic_snaplen = true;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_enable_page_faults(scap_t* handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.page_faults = true;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_enable_tracers_capture(scap_t* handle)
{
	struct sysdig_bpf_settings settings;
	int k = 0;

	if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_lookup_elem < 0");
		return SCAP_FAILURE;
	}

	settings.tracers_enabled = true;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}

int32_t scap_bpf_close(scap_t *handle)
{
	int j;

	int page_size = getpagesize();
	int ring_size = page_size * BUF_SIZE_PAGES;
	int header_size = page_size;
	int total_size = ring_size * 2 + header_size;

	for(j = 0; j < handle->m_ndevs; j++)
	{
		if(handle->m_devs[j].m_buffer != MAP_FAILED)
		{
#ifdef _DEBUG
			int ret;
			ret = munmap(handle->m_devs[j].m_buffer, total_size);
#else
			munmap(handle->m_devs[j].m_buffer, total_size);
#endif
			ASSERT(ret == 0);
		}

		if(handle->m_devs[j].m_fd > 0)
		{
			close(handle->m_devs[j].m_fd);
		}
	}

	for(j = 0; j < sizeof(handle->m_bpf_event_fd) / sizeof(handle->m_bpf_event_fd[0]); ++j)
	{
		if(handle->m_bpf_event_fd[j] > 0)
		{
			close(handle->m_bpf_event_fd[j]);
			handle->m_bpf_event_fd[j] = 0;
		}
	}

	for(j = 0; j < sizeof(handle->m_bpf_prog_fds) / sizeof(handle->m_bpf_prog_fds[0]); ++j)
	{
		if(handle->m_bpf_prog_fds[j] > 0)
		{
			close(handle->m_bpf_prog_fds[j]);
			handle->m_bpf_prog_fds[j] = 0;
		}
	}

	for(j = 0; j < sizeof(handle->m_bpf_map_fds) / sizeof(handle->m_bpf_map_fds[0]); ++j)
	{
		if(handle->m_bpf_map_fds[j] > 0)
		{
			close(handle->m_bpf_map_fds[j]);
			handle->m_bpf_map_fds[j] = 0;
		}
	}

	handle->m_bpf_prog_cnt = 0;
	handle->m_bpf_prog_array_map_idx = -1;

	return SCAP_SUCCESS;
}

//
// This is completely horrible, revisit this shameful code
// with a proper solution
//
static int32_t set_boot_time(scap_t *handle, uint64_t *boot_time)
{
	struct timespec ts_uptime;
	struct timeval tv_now;
	uint64_t now;
	uint64_t uptime;

	if(gettimeofday(&tv_now, NULL))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "gettimeofday");
		return SCAP_FAILURE;
	}

	now = tv_now.tv_sec * (uint64_t) 1000000000 + tv_now.tv_usec * 1000;

	if(clock_gettime(CLOCK_BOOTTIME, &ts_uptime))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "clock_gettime");
		return SCAP_FAILURE;
	}

	uptime = ts_uptime.tv_sec * (uint64_t) 1000000000 + ts_uptime.tv_nsec;

	*boot_time = now - uptime;

	return SCAP_SUCCESS;
}


/// È una funzione in cui setto dei valori in alcuni file di BPF, voglio che ci siano dei precisi valori.
static int32_t set_runtime_params(scap_t *handle)
{
	// si settano questi limiti per non limitare cosa il processo BPF può fare
	struct rlimit rl;
	rl.rlim_max = RLIM_INFINITY;
	rl.rlim_cur = rl.rlim_max;
	if(setrlimit(RLIMIT_MEMLOCK, &rl))
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "setrlimit failed");
		return SCAP_FAILURE;
	}


	//  è un file per il just in time compile
	FILE *f = fopen("/proc/sys/net/core/bpf_jit_enable", "w");
	if(!f)
	{
		// snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't open /proc/sys/net/core/bpf_jit_enable");
		// return SCAP_FAILURE;

		// Not every kernel has BPF_JIT enabled. Fix this after COS changes.
		return SCAP_SUCCESS;
	}

	if(fprintf(f, "1") != 1)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't write to /proc/sys/net/core/bpf_jit_enable");
		fclose(f);
		return SCAP_FAILURE;
	}

	fclose(f);

	f = fopen("/proc/sys/net/core/bpf_jit_harden", "w");
	if(!f)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't open /proc/sys/net/core/bpf_jit_harden");
		return SCAP_FAILURE;
	}

    // scrivo il carattere 0 e ritorno un carattere scritto(byte)
	if(fprintf(f, "0") != 1)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't write to /proc/sys/net/core/bpf_jit_harden");
		fclose(f);
		return SCAP_FAILURE;
	}

	fclose(f);

	f = fopen("/proc/sys/net/core/bpf_jit_kallsyms", "w");
	if(!f)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't open /proc/sys/net/core/bpf_jit_kallsyms");
		return SCAP_FAILURE;
	}

	if(fprintf(f, "1") != 1)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Can't write to /proc/sys/net/core/bpf_jit_kallsyms");
		fclose(f);
		return SCAP_FAILURE;
	}

	fclose(f);

	return SCAP_SUCCESS;
}





static int32_t set_default_settings(scap_t *handle)
{
	struct sysdig_bpf_settings settings;

	if(set_boot_time(handle, &settings.boot_time) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	settings.socket_file_ops = NULL;
	settings.snaplen = RW_SNAPLEN;
	settings.sampling_ratio = 1;
	settings.capture_enabled = false;
	settings.do_dynamic_snaplen = false;
	settings.page_faults = false;
	settings.dropping_mode = false;
	settings.is_dropping = false;
	settings.tracers_enabled = false;
	settings.fullcapture_port_range_start = 0;
	settings.fullcapture_port_range_end = 0;
	settings.statsd_port = 8125;

	int k = 0;
	if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_SETTINGS_MAP], &k, &settings, BPF_ANY) != 0)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_SETTINGS_MAP bpf_map_update_elem < 0");
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
}









///  NOTA: funzion principale che fa da loader BPF in scap.
int32_t scap_bpf_load(scap_t *handle, const char *bpf_probe)
{
#ifdef MINIMAL_BUILD
	snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "The eBPF probe driver is not supported when using a minimal build");
	return SCAP_FAILURE;
#else
	int online_cpu;
	int j;

    /// È una funzione in cui setto dei valori in alcuni file di BPF, voglio che ci siano dei precisi valori.
	if(set_runtime_params(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}
 
    // è l'indice dove inizia l'array di mappe del programma BPF.
	handle->m_bpf_prog_array_map_idx = -1;

    // se non c'è il path del bpf probe.
	if(!bpf_probe)
	{
		ASSERT(false);
		return SCAP_FAILURE;
	}


	// 1. Ho aprto l'elf probe.o
	// 2. Ho caricato il contenuto dell'elf per quanto riguarda la sezione "maps", in un vettore di strutture bpm_map, con tutte le informazioni che ho scritto nel codice del probe.
	// 3. modifico alcune informazioni in alcune mappe come il numeor massimo di entry che possono avere, una per cpu per esempio.
	// 4. carico le mappe bpf nel kernel, ma tante devono essere ancora riempite, quasi tutte tranne tail map come vedremo.
	// 5. analizzo tutte le sezioni che iniziano con /raw_tracepoint nel mio caso, carico tutti i programmi bpf associati a ogni sezione nel kernel e ottengo i file descriptor.
	/// 6. se la sezione riguardava un filler nella tail map associo l'id di quel filler al file_descriptor del programma bpf. NOTA: non aggangio quel programma a nessun tracepoint, i filler vengono solo caricati come programmi bpf ma non saranno agganciati a niente
	// 7. se la sezione riguardava un programma bpf associato a `sys_enter`, `sys_exit`, ... non solo lo carico nel kernel ma lo associo anche a il tracepoint giusto.
	if(load_bpf_file(handle, bpf_probe) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}




	// il loader bpf qui contenuto in scap, prima carica le mappe e poi in base alle informazioni le va a riempire
	// 1. Riempio la tabella `syscall_code_routing_table', come chiave ho il codice di sistema della syscall, come valore ho il codice PPM_ stabilito dalla nostra rappresentazione interna.
	if(populate_syscall_routing_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}





	// 1. Riempio la tabella `syscall_table`, come chiave ho il codice di sistema della syscall, come valore i due eventi di entry e di exit associati alla syscall.
	if(populate_syscall_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}







	// 1. Riempio la tabella `event_info_table`, come chiave metto l'indice dell'evento nello tabella globale g_event e come valore le informazioni sul singolo evento tra cui i parametri.
	if(populate_event_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}




	// 1. Riempio la tabella `fillers_table`, come chiave l'indice dell'evento di entry/exit e come valore una serie di info sul filler.
	if(populate_fillers_table_map(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}




	



	// Apre un perf_file dove venfono collezionati eventi, per ogni cpu e associa una zona di memoria (ring_buffer) a questo file, in modo che sysdig per ogni cpu abbia uno spazio virtuale nel suo address space dove accedere ai dati direttamente quando vengono scritti nel file, questa funzione la fornisce mmap.


	//
	// Open and initialize all the devices
	//
	online_cpu = 0;
	for(j = 0; j < handle->m_ncpus; ++j)
	{
		//PERF_EVENT = Hardware event_id to monitor via a performance monitoring event.
		struct perf_event_attr attr = {
			.sample_type = PERF_SAMPLE_RAW,
			.type = PERF_TYPE_SOFTWARE,
			.config = PERF_COUNT_SW_BPF_OUTPUT,
		};
		int pmu_fd;

		// controllo se la cpu è veramente online.
		if(j > 0)
		{
			char filename[SCAP_MAX_PATH_SIZE];
			int online;
			FILE *fp;

			snprintf(filename, sizeof(filename), "/sys/devices/system/cpu/cpu%d/online", j);

			// è un file dove se la cpu è online c'è scritto "1".
			fp = fopen(filename, "r");
			if(fp == NULL)
			{
				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't open %s: %s", filename, scap_strerror(handle, errno));
				return SCAP_FAILURE;
			}

			if(fscanf(fp, "%d", &online) != 1)
			{
				fclose(fp);

				snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "can't read %s: %s", filename, scap_strerror(handle, errno));
				return SCAP_FAILURE;
			}

			fclose(fp);

			// se non è online passa alla prossima.
			if(!online)
			{
				continue;
			}
		}

		// io so già quante devono essere le cpu online, controllo solo che il numero sia giusto.
		if(online_cpu >= handle->m_ndevs)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "processors online: %d, expected: %d", online_cpu, handle->m_ndevs);
			return SCAP_FAILURE;
		}





		// Chiamo una syscall `perf_event_open`, a cui passo anche il numero della cpu.
		// se il pid = -1 come in questo caso, this measures all processes/threads on the specified CPU (j). 
		// questa syscall mi apre un file descriptor dove poi andrò a leggere una serie di info tramite una read per esempio
		pmu_fd = sys_perf_event_open(&attr, -1, j, -1, 0);
		if(pmu_fd < 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "pmu_fd < 0: %s", scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		// il device è questo perf_file che ho aperto con la syscall
		handle->m_devs[online_cpu].m_fd = pmu_fd;

		// questo file descriptor lo mappo con il numero della cpu (j) e lo metto in una bpf table.
		if(bpf_map_update_elem(handle->m_bpf_map_fds[SYSDIG_PERF_MAP], &j, &pmu_fd, BPF_ANY) != 0)
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "SYSDIG_PERF_MAP bpf_map_update_elem < 0: %s", scap_strerror(handle, errno));
			return SCAP_FAILURE;
		}

		// This enables the individual event or event group specified by the file descriptor argument.
		if(ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "PERF_EVENT_IOC_ENABLE");
			return SCAP_FAILURE;
		}





		//
		// Map the ring buffer
		//
		/// IMPORTANTE: da vedere la funzione interna, che tipo di mapping fa, in totale 3 mapping, qui nel buffer torna l'indirizzo iniziale del mapping
		handle->m_devs[online_cpu].m_buffer = perf_event_mmap(handle, pmu_fd);
		if(handle->m_devs[online_cpu].m_buffer == MAP_FAILED)
		{
			return SCAP_FAILURE;
		}

		++online_cpu;
	}

	if(online_cpu != handle->m_ndevs)
	{
		snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "processors online: %d, expected: %d", j, handle->m_ndevs);
		return SCAP_FAILURE;
	}



	// riempie la mappa bpf dei settings
	if(set_default_settings(handle) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	return SCAP_SUCCESS;
#endif // MINIMAL_BUILD
}












// non è scap che la riempie ma è la probe bpf che ci mette dell info 
int32_t scap_bpf_get_stats(scap_t* handle, OUT scap_stats* stats)
{
	int j;

	for(j = 0; j < handle->m_ncpus; j++)
	{
		struct sysdig_bpf_per_cpu_state v;
		// qui tiro fuori questa mappa con le statistiche sugli eventi
		if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_LOCAL_STATE_MAP], &j, &v))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Error looking up local state %d\n", j);
			return SCAP_FAILURE;
		}

		stats->n_evts += v.n_evts;
		stats->n_drops_buffer += handle->m_devs[j].m_evt_lost + v.n_drops_buffer;
		stats->n_drops_pf += v.n_drops_pf;
		stats->n_drops_bug += v.n_drops_bug;
		stats->n_drops += handle->m_devs[j].m_evt_lost +
				  v.n_drops_buffer +
				  v.n_drops_pf +
				  v.n_drops_bug;
	}

	return SCAP_SUCCESS;
}






int32_t scap_bpf_get_n_tracepoint_hit(scap_t* handle, long* ret)
{
	int j;

	for(j = 0; j < handle->m_ncpus; j++)
	{
		struct sysdig_bpf_per_cpu_state v;
		if(bpf_map_lookup_elem(handle->m_bpf_map_fds[SYSDIG_LOCAL_STATE_MAP], &j, &v))
		{
			snprintf(handle->m_lasterr, SCAP_LASTERR_SIZE, "Error looking up local state %d\n", j);
			return SCAP_FAILURE;
		}

		ret[j] = v.n_evts;
	}

	return SCAP_SUCCESS;
}
