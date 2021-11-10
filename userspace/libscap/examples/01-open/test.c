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
#include <signal.h>
#include <scap.h>

uint64_t g_nevts = 0;
scap_t* g_h = NULL;

static void signal_callback(int signal)
{
	scap_stats s;
	printf("events captured: %" PRIu64 "\n", g_nevts);
	scap_get_stats(g_h, &s);
	printf("seen by driver: %" PRIu64 "\n", s.n_evts);
	printf("Number of dropped events: %" PRIu64 "\n", s.n_drops);
	printf("Number of dropped events caused by full buffer: %" PRIu64 "\n", s.n_drops_buffer);
	printf("Number of dropped events caused by invalid memory access: %" PRIu64 "\n", s.n_drops_pf);
	printf("Number of dropped events caused by an invalid condition in the kernel instrumentation: %" PRIu64 "\n", s.n_drops_bug);
	printf("Number of preemptions: %" PRIu64 "\n", s.n_preemptions);
	printf("Number of events skipped due to the tid being in a set of suppressed tids: %" PRIu64 "\n", s.n_suppressed);
	printf("Number of threads currently being suppressed: %" PRIu64 "\n", s.n_tids_suppressed);
	exit(0);
}

int main(int argc, char** argv)
{

	char error[SCAP_LASTERR_SIZE];
	int32_t res;

	// header di un evento, con alcune informazioni su di esso.
	scap_evt* ev;
	// id della cpu dove l'evento è stato catturato.
	uint16_t cpuid;

	if(signal(SIGINT, signal_callback) == SIG_ERR)
	{
		fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
		return -1;
	}

	/////// ROBA AGGIUNTA DA ME
	printf("DEBUG -- Apro handle di cattura.\n");
	//const char* bpf_probe = scap_get_bpf_probe_from_env();
	setenv("SYSDIG_BPF_PROBE","/vagrant/libs/build/driver/bpf/probe.o",1); 

	static const char *SYSDIG_BPF_PROBE_ENV = "SYSDIG_BPF_PROBE";
	char*  bpf_probe;
	bpf_probe = getenv(SYSDIG_BPF_PROBE_ENV);
	
	printf("DEBUG -- %s", bpf_probe);
    ///////


	// g_h = handler dell'istanza di cattura se torna con successo.
	// ha fatto i memory mapping dei device allocando circa 16 MB.
	// e quindi ha i puntatori ai ring buffer settati nei deivce.
	// la cattura si avvia settando i flag in alcuni file
	g_h = scap_open_live(error, &res);


	if(g_h == NULL)
	{
		fprintf(stderr, "%s (%d)\n", error, res);
		return -1;
	}
	
	while(1)
	{
		// abbiamo avviato la cattura adesso scap deve andare a leggere dai ring buffer questi eventi.
		/// NOTA: credo che sinsp chiami next solo quando ha finito di processare evento completamente quindi non gli servono più i dati nel buffer
		res = scap_next(g_h, &ev, &cpuid);

		if(res > 0)
		{
			fprintf(stderr, "%s\n", scap_getlasterr(g_h));
			scap_close(g_h);
			return -1;
		}

		if(res != SCAP_TIMEOUT)
		{
			g_nevts++;
		}
	}

	scap_close(g_h);
	return 0;
}
