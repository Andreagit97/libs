#include <scap.h>
#include <gtest/gtest.h>
#include <unordered_set>
#include <syscall.h>
#include <helpers/engines.h>

scap_t* open_modern_bpf_engine(char* error_buf, int32_t* rc, unsigned long buffer_dim, uint16_t cpus_for_each_buffer, std::unordered_set<uint32_t> ppm_sc_set = {})
{
	struct scap_open_args oargs = {
		.engine_name = MODERN_BPF_ENGINE,
		.mode = SCAP_MODE_LIVE,
	};

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
		.cpus_for_each_buffer = cpus_for_each_buffer,
		.buffer_bytes_dim = buffer_dim,
		.verbose = false,
	};
	oargs.engine_params = &modern_bpf_params;

	return scap_open(&oargs, error_buf, rc);
}

TEST(modern_bpf, open_engine)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	/* we want 1 ring buffer for each CPU */
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, 1);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open modern bpf engine: " << error_buffer << std::endl;
	scap_close(h);
}

TEST(modern_bpf, empty_buffer_dim)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 0, 1);
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS) << "the buffer dimension is 0, we should fail: " << error_buffer << std::endl;
	/* In case of failure the `scap_close(h)` is already called in the vtable `init` method */
}

TEST(modern_bpf, wrong_buffer_dim)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	/* ring buffer dim is not a multiple of PAGE_SIZE */
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 1 + 4 * 4096, 1);
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS) << "the buffer dimension is not a multiple of the page size, we should fail: " << error_buffer << std::endl;
}

TEST(modern_bpf, not_enough_possible_CPUs)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;

	ssize_t num_possible_CPUs = sysconf(_SC_NPROCESSORS_CONF);

	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, num_possible_CPUs + 1);
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS) << "the CPUs required for each ring buffer are greater than the system possible CPUs, we should fail: " << error_buffer << std::endl;
}

TEST(modern_bpf, not_enough_online_CPUs)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;

	ssize_t num_online_CPUs = sysconf(_SC_NPROCESSORS_ONLN);

	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, num_online_CPUs + 1);
	ASSERT_TRUE(!h || ret != SCAP_SUCCESS) << "the CPUs required for each ring buffer are greater than the system online CPUs, we should fail: " << error_buffer << std::endl;
}

TEST(modern_bpf, one_buffer_per_possible_CPU)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, 1);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open modern bpf engine with one ring buffer per CPU: " << error_buffer << std::endl;

	ssize_t num_possible_CPUs = sysconf(_SC_NPROCESSORS_CONF);
	uint32_t num_expected_rings = scap_get_ndevs(h);
	ASSERT_EQ(num_expected_rings, num_possible_CPUs) << "we should have a ring buffer for every possible CPU!" << std::endl;

	check_event_is_not_overwritten(h);
	scap_close(h);
}

TEST(modern_bpf, one_buffer_every_two_possible_CPUs)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, 2);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open modern bpf engine with one ring buffer every 2 CPUs: " << error_buffer << std::endl;

	ssize_t num_possible_CPUs = sysconf(_SC_NPROCESSORS_CONF);
	uint32_t num_expected_rings = num_possible_CPUs / 2;
	if(num_possible_CPUs % 2 != 0)
	{
		num_expected_rings++;
	}
	uint32_t num_rings = scap_get_ndevs(h);
	ASSERT_EQ(num_rings, num_expected_rings) << "we should have one ring buffer every 2 CPUs!" << std::endl;

	check_event_is_not_overwritten(h);
	scap_close(h);
}

TEST(modern_bpf, one_buffer_shared_between_all_possible_CPUs_with_special_value)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	/* `0` is a special value that means one single shared ring buffer */
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, 0);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open modern bpf engine with one single shared ring buffer: " << error_buffer << std::endl;

	uint32_t num_rings = scap_get_ndevs(h);
	ASSERT_EQ(num_rings, 1) << "we should have only one ring buffer shared between all CPUs!" << std::endl;

	check_event_is_not_overwritten(h);
	scap_close(h);
}

/* In this test we don't need to check for buffer corruption with `check_event_is_not_overwritten`
 * we have already done it in the previous test `one_buffer_shared_between_all_CPUs_with_special_value`.
 */
TEST(modern_bpf, one_buffer_shared_between_all_online_CPUs_with_explicit_CPUs_number)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;

	ssize_t num_possible_CPUs = sysconf(_SC_NPROCESSORS_ONLN);

	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 4 * 4096, num_possible_CPUs);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open modern bpf engine with one single shared ring buffer: " << error_buffer << std::endl;

	uint32_t num_rings = scap_get_ndevs(h);
	ASSERT_EQ(num_rings, 1) << "we should have only one ring buffer shared between all CPUs!" << std::endl;

	scap_close(h);
}

TEST(modern_bpf, read_in_order_one_buffer_per_online_CPU)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	/* We use buffers of 1 MB to be sure that we don't have drops */
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 1 * 1024 * 1024, 1);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open modern bpf engine with one ring buffer per CPU: " << error_buffer << std::endl;

	check_event_order(h);
	scap_close(h);
}

TEST(modern_bpf, read_in_order_one_buffer_every_two_online_CPUs)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	/* We use buffers of 1 MB to be sure that we don't have drops */
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 1 * 1024 * 1024, 2);
	ASSERT_FALSE(!h || ret != SCAP_SUCCESS) << "unable to open modern bpf engine with one ring buffer every 2 CPUs: " << error_buffer << std::endl;

	check_event_order(h);
	scap_close(h);
}

TEST(modern_bpf, read_in_order_one_buffer_shared_between_all_possible_CPUs)
{
	char error_buffer[FILENAME_MAX] = {0};
	int ret = 0;
	/* We use buffers of 1 MB to be sure that we don't have drops */
	scap_t* h = open_modern_bpf_engine(error_buffer, &ret, 1 * 1024 * 1024, 0);
	ASSERT_EQ(!h || ret != SCAP_SUCCESS, false) << "unable to open modern bpf engine with one single shared ring buffer: " << error_buffer << std::endl;

	check_event_order(h);
	scap_close(h);
}
