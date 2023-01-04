#include "scap.h"
#include <gtest/gtest.h>
#include <unordered_set>
#include <syscall.h>

/* We are supposing that if we overcome this threshold, all buffers are full */
#define MAX_ITERATIONS 3000

scap_t* open_modern_bpf_engine(char* error_buf, int32_t* rc, unsigned long buffer_dim, enum modern_bpf_buffer_mode buffer_mode, std::unordered_set<uint32_t> tp_set = {}, std::unordered_set<uint32_t> ppm_sc_set = {})
{
	struct scap_open_args oargs = {
		.engine_name = MODERN_BPF_ENGINE,
		.mode = SCAP_MODE_LIVE,
	};

	/* If empty we fill with all tracepoints */
	if(tp_set.empty())
	{
		for(int i = 0; i < TP_VAL_MAX; i++)
		{
			oargs.tp_of_interest.tp[i] = 1;
		}
	}
	else
	{
		for(auto tp : tp_set)
		{
			oargs.tp_of_interest.tp[tp] = 1;
		}
	}

	/* If empty we fill with all syscalls */
	if(ppm_sc_set.empty())
	{
		for(int i = 0; i < PPM_SC_MAX; i++)
		{
			oargs.ppm_sc_of_interest.ppm_sc[i] = 1;
		}
	}
	else
	{
		for(auto ppm_sc : ppm_sc_set)
		{
			oargs.ppm_sc_of_interest.ppm_sc[ppm_sc] = 1;
		}
	}

	struct scap_modern_bpf_engine_params modern_bpf_params = {
		.buffer_mode = buffer_mode,
		.buffer_bytes_dim = buffer_dim,
	};
	oargs.engine_params = &modern_bpf_params;

	return scap_open(&oargs, error_buf, rc);
}

void check_event_is_not_overwritten(scap_t* h)
{
	/* Start the capture */
	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS) << "unable to start the capture: " << scap_getlasterr(h) << std::endl;

	/* When the number of events is fixed for `MAX_ITERATIONS` we consider all the buffers full, this is just an approximation */
	scap_stats stats = {};
	uint64_t last_num_events = 0;
	uint16_t iterations = 0;

	while(iterations < MAX_ITERATIONS || stats.n_drops == 0)
	{
		ASSERT_EQ(scap_get_stats(h, &stats), SCAP_SUCCESS) << "unable to get stats: " << scap_getlasterr(h) << std::endl;
		if(last_num_events == (stats.n_evts - stats.n_drops))
		{
			iterations++;
		}
		else
		{
			iterations = 0;
			last_num_events = (stats.n_evts - stats.n_drops);
		}
	}

	/* Stop the capture */
	ASSERT_EQ(scap_stop_capture(h), SCAP_SUCCESS) << "unable to stop the capture: " << scap_getlasterr(h) << std::endl;

	/* The idea here is to check if an event is overwritten while we still have a pointer to it.
	 * Again this is only an approximation, we don't know if new events will be written in the buffer
	 * under test...
	 *
	 * We call `scap_next` keeping the pointer to the event.
	 * An event pointer becomes invalid when we call another `scap_next`, but until that moment it should be valid!
	 */
	scap_evt* evt = NULL;
	uint16_t buffer_id;

	/* The first 'scap_next` could return a `SCAP_TIMEOUT` according to the chosen `buffer_mode` so we ignore it. */
	scap_next(h, &evt, &buffer_id);

	ASSERT_EQ(scap_next(h, &evt, &buffer_id), SCAP_SUCCESS) << "unable to get an event with `scap_next`: " << scap_getlasterr(h) << std::endl;

	last_num_events = 0;
	iterations = 0;

	/* We save some event info to check if they are still valid after some new events */
	uint64_t prev_ts = evt->ts;
	uint64_t prev_tid = evt->tid;
	uint32_t prev_len = evt->len;
	uint16_t prev_type = evt->type;
	uint32_t prev_nparams = evt->nparams;

	/* Start again the capture */
	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS) << "unable to restart the capture: " << scap_getlasterr(h) << std::endl;

	/* We use the same approximation as before */
	while(iterations < MAX_ITERATIONS)
	{
		ASSERT_EQ(scap_get_stats(h, &stats), SCAP_SUCCESS) << "unable to get stats: " << scap_getlasterr(h) << std::endl;
		if(last_num_events == (stats.n_evts - stats.n_drops))
		{
			iterations++;
		}
		else
		{
			iterations = 0;
			last_num_events = (stats.n_evts - stats.n_drops);
		}
	}

	/* We check if the previously collected event is still valid */
	ASSERT_EQ(prev_ts, evt->ts) << "different timestamp" << std::endl;
	ASSERT_EQ(prev_tid, evt->tid) << "different thread id" << std::endl;
	ASSERT_EQ(prev_len, evt->len) << "different event len" << std::endl;
	ASSERT_EQ(prev_type, evt->type) << "different event type" << std::endl;
	ASSERT_EQ(prev_nparams, evt->nparams) << "different num params" << std::endl;
}

TEST(modern_bpf, open_engine)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, MODERN_PER_CPU_BUFFER);
	ASSERT_EQ(!h || ret != SCAP_SUCCESS, false) << "unable to open modern bpf engine: " << error_buffer << std::endl;
	scap_close(h);
}

TEST(modern_bpf, empty_buffer_dim)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 0, MODERN_PER_CPU_BUFFER);
	ASSERT_EQ(!h || ret != SCAP_SUCCESS, true) << "The buffer dimension is 0, we should fail: " << error_buffer << std::endl;
	/* In case of failure the `scap_close(h)` is already called in the vtable `init` method */
}

TEST(modern_bpf, wrong_buffer_dim)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 1 + 4 * 4096, MODERN_PER_CPU_BUFFER);
	ASSERT_EQ(!h || ret != SCAP_SUCCESS, true) << "The buffer dimension is not a multiple of the page size, we should fail: " << error_buffer << std::endl;
}

TEST(modern_bpf, per_CPU_buffer_mode)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, MODERN_PER_CPU_BUFFER);
	ASSERT_EQ(!h || ret != SCAP_SUCCESS, false) << "unable to open modern bpf engine with `MODERN_PER_CPU_BUFFER` mode: " << error_buffer << std::endl;

	ssize_t num_possible_CPUs = sysconf(_SC_NPROCESSORS_CONF);
	uint32_t num_rings = scap_get_ndevs(h);
	ASSERT_EQ(num_rings, num_possible_CPUs) << "We are in `MODERN_PER_CPU_BUFFER` mode so we should have a ring buffer for every possible CPU!" << std::endl;

	check_event_is_not_overwritten(h);
	scap_close(h);
}

TEST(modern_bpf, paired_buffer_mode)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, MODERN_PAIRED_BUFFER);
	ASSERT_EQ(!h || ret != SCAP_SUCCESS, false) << "unable to open modern bpf engine with `MODERN_PAIRED_BUFFER` mode: " << error_buffer << std::endl;

	ssize_t num_possible_CPUs = sysconf(_SC_NPROCESSORS_CONF);
	uint32_t num_expected_rings = num_possible_CPUs / 2 + num_possible_CPUs % 2;
	uint32_t num_rings = scap_get_ndevs(h);
	ASSERT_EQ(num_rings, num_expected_rings) << "We are in `MODERN_PAIRED_BUFFER` mode so we should have a ring buffer for every CPU pair!" << std::endl;

	check_event_is_not_overwritten(h);
	scap_close(h);
}

TEST(modern_bpf, single_buffer_mode)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, MODERN_SINGLE_BUFFER);
	ASSERT_EQ(!h || ret != SCAP_SUCCESS, false) << "unable to open modern bpf engine with `MODERN_SINGLE_BUFFER` mode: " << error_buffer << std::endl;

	uint32_t num_rings = scap_get_ndevs(h);
	ASSERT_EQ(num_rings, 1) << "We are in `MODERN_SINGLE_BUFFER` mode so we should have only one ring buffer for all CPUs!" << std::endl;

	check_event_is_not_overwritten(h);
	scap_close(h);
}

#if defined(__NR_close) && defined(__NR_openat) && defined(__NR_listen) && defined(__NR_accept4) && defined(__NR_getegid) && defined(__NR_getgid) && defined(__NR_geteuid) && defined(__NR_getuid) && defined(__NR_bind) && defined(__NR_connect) && defined(__NR_sendto) && defined(__NR_sendmsg) && defined(__NR_recvmsg) && defined(__NR_recvfrom) && defined(__NR_socket) && defined(__NR_socketpair)

/* Number of events we want to assert */
#define EVENTS_TO_ASSERT 32

void check_event_order(scap_t* h)
{
	uint32_t events_to_assert[EVENTS_TO_ASSERT] = {PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X, PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X, PPME_SOCKET_LISTEN_E, PPME_SOCKET_LISTEN_X, PPME_SOCKET_ACCEPT4_5_E, PPME_SOCKET_ACCEPT4_5_X, PPME_SYSCALL_GETEGID_E, PPME_SYSCALL_GETEGID_X, PPME_SYSCALL_GETGID_E, PPME_SYSCALL_GETGID_X, PPME_SYSCALL_GETEUID_E, PPME_SYSCALL_GETEUID_X, PPME_SYSCALL_GETUID_E, PPME_SYSCALL_GETUID_X, PPME_SOCKET_BIND_E, PPME_SOCKET_BIND_X, PPME_SOCKET_CONNECT_E, PPME_SOCKET_CONNECT_X, PPME_SOCKET_SENDTO_E, PPME_SOCKET_SENDTO_X, PPME_SOCKET_SENDMSG_E, PPME_SOCKET_SENDMSG_X, PPME_SOCKET_RECVMSG_E, PPME_SOCKET_RECVMSG_X, PPME_SOCKET_RECVFROM_E, PPME_SOCKET_RECVFROM_X, PPME_SOCKET_SOCKET_E, PPME_SOCKET_SOCKET_X, PPME_SOCKET_SOCKETPAIR_E, PPME_SOCKET_SOCKETPAIR_X};

	/* Start the capture */
	ASSERT_EQ(scap_start_capture(h), SCAP_SUCCESS) << "unable to start the capture: " << scap_getlasterr(h) << std::endl;

	/* 1. Generate a `close` event pair */
	syscall(__NR_close, -1);

	/* 2. Generate an `openat` event pair */
	syscall(__NR_openat, 0, "/**mock_path**/", 0, 0);

	/* 3. Generate a `listen` event pair */
	syscall(__NR_listen, -1, -1);

	/* 4. Generate an `accept4` event pair */
	syscall(__NR_accept4, -1, NULL, NULL, 0);

	/* 5. Generate a `getegid` event pair */
	syscall(__NR_getegid);

	/* 6. Generate a `getgid` event pair */
	syscall(__NR_getgid);

	/* 7. Generate a `geteuid` event pair */
	syscall(__NR_geteuid);

	/* 8. Generate a `getuid` event pair */
	syscall(__NR_getuid);

	/* 9. Generate a `bind` event pair */
	syscall(__NR_bind, -1, NULL, 0);

	/* 10. Generate a `connect` event pair */
	syscall(__NR_connect, -1, NULL, 0);

	/* 11. Generate a `sendto` event pair */
	syscall(__NR_sendto, -1, NULL, 0, 0, NULL, 0);

	/* 12. Generate a `sendmsg` event pair */
	syscall(__NR_sendmsg, -1, NULL, 0);

	/* 13. Generate a `recvmsg` event pair */
	syscall(__NR_recvmsg, -1, NULL, 0);

	/* 14. Generate a `recvmsg` event pair */
	syscall(__NR_recvfrom, -1, NULL, 0, 0, NULL, 0);

	/* 15. Generate a `socket` event pair */
	syscall(__NR_socket, 0, 0, 0);

	/* 16. Generate a `socketpair` event pair */
	syscall(__NR_socketpair, 0, 0, 0, 0);

	/* Stop the capture */
	ASSERT_EQ(scap_stop_capture(h), SCAP_SUCCESS) << "unable to stop the capture: " << scap_getlasterr(h) << std::endl;

	scap_evt* evt = NULL;
	uint16_t buffer_id = 0;
	int ret = 0;
	uint64_t acutal_pid = getpid();
	/* if we hit 5 consecutive timeouts it means that all buffers are empty (approximation) */
	uint16_t timeouts = 0;

	for(int i = 0; i < EVENTS_TO_ASSERT; i++)
	{
		while(true)
		{
			ret = scap_next(h, &evt, &buffer_id);
			if(ret == SCAP_SUCCESS)
			{
				timeouts = 0;
				if(evt->tid == acutal_pid && evt->type == events_to_assert[i])
				{
					/* We found our event */
					break;
				}
			}
			else if(ret == SCAP_TIMEOUT)
			{
				timeouts++;
				if(timeouts == 5)
				{
					FAIL() << "we didn't find event '" << events_to_assert[i] << "' at position '" << i << "'" << std::endl;
				}
			}
		}
	}
}

TEST(modern_bpf, read_in_order_per_CPU_buffer)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	/* We use buffers of 1 MB to be sure that we don't have drops */
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 1 * 1024 * 1024, MODERN_PER_CPU_BUFFER);
	ASSERT_EQ(!h || ret != SCAP_SUCCESS, false) << "unable to open modern bpf engine with `MODERN_PER_CPU_BUFFER` mode: " << error_buffer << std::endl;

	check_event_order(h);
	scap_close(h);
}

TEST(modern_bpf, read_in_order_paired_buffer)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	/* We use buffers of 1 MB to be sure that we don't have drops */
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 1 * 1024 * 1024, MODERN_PAIRED_BUFFER);
	ASSERT_EQ(!h || ret != SCAP_SUCCESS, false) << "unable to open modern bpf engine with `MODERN_PAIRED_BUFFER` mode: " << error_buffer << std::endl;

	check_event_order(h);
	scap_close(h);
}

TEST(modern_bpf, read_in_order_single_buffer)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	/* We use buffers of 1 MB to be sure that we don't have drops */
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 1 * 1024 * 1024, MODERN_SINGLE_BUFFER);
	ASSERT_EQ(!h || ret != SCAP_SUCCESS, false) << "unable to open modern bpf engine with `MODERN_SINGLE_BUFFER` mode: " << error_buffer << std::endl;

	check_event_order(h);
	scap_close(h);
}
#endif
