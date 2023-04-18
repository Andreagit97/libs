/*
Copyright (C) 2023 The Falco Authors.

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

#include <gtest/gtest.h>

#include "sinsp_with_test_input.h"
#include "test_utils.h"

TEST_F(sinsp_with_test_input, check_init_thread)
{
	/* Right now we have only the init process here */
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	uint64_t init_tid = 1;
	evt = add_event_advance_ts(increasing_ts(), init_tid, PPME_SYSCALL_CLONE_20_E, 0);

	sinsp_threadinfo* tinfo = evt->get_thread_info(false);
	ASSERT_TRUE(tinfo);
	ASSERT_TRUE(tinfo->is_main_thread());
	ASSERT_EQ(tinfo->get_main_thread(), tinfo);
	ASSERT_EQ(tinfo->get_parent_thread(), nullptr);
	ASSERT_EQ(tinfo->m_tid, init_tid);
	ASSERT_EQ(tinfo->m_pid, init_tid);
	ASSERT_EQ(tinfo->m_ptid, (int64_t)0);
}

/*=============================== CLONE PARENT EXIT EVENT ===========================*/

/* Parse a simple PPME_SYSCALL_CLONE_20_X event */
TEST_F(sinsp_with_test_input, parse_clone_exit_parent)
{
	add_default_init_thread();
	open_inspector();
	uint64_t init_tid = 1;
	uint64_t parent_ppid = 0;

	/* Scaffolding needed to call the PPME_SYSCALL_CLONE_20_X */
	uint64_t child_tid = 20;
	uint64_t not_relevant_64 = 0;
	uint32_t not_relevant_32 = 0;
	scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

	/* Here we simulate a new process spawned by the init one.
	 * The parent is the init process so `tid` == `pid` and `tid` == `vtid`.
	 * Here the father event comes before the child.
	 */
	add_event_advance_ts(increasing_ts(), init_tid, PPME_SYSCALL_CLONE_20_X, 20, child_tid, "bash", empty_bytebuf, init_tid, init_tid, parent_ppid, "", not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_32, not_relevant_32, not_relevant_32, "bash", empty_bytebuf, PPM_CL_CLONE_FILES, not_relevant_32, not_relevant_32, init_tid, init_tid);

	/* The father exit event has already created the tinfo for the child */
	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(child_tid, false, true).get();
	ASSERT_TRUE(tinfo);
	ASSERT_EQ(tinfo->m_tid, child_tid);
	ASSERT_EQ(tinfo->m_pid, child_tid); /* this seems correct since we have a new process*/
	ASSERT_EQ(tinfo->m_ptid, init_tid); /// [TODO]: this could be a wrong assumption if the clone is performed by a thread

	/* If we are in a container the father never parses its `PPME_SYSCALL_CLONE_20_X` event, but here we are not in a container */
	ASSERT_EQ(tinfo->m_vtid, child_tid);
	ASSERT_EQ(tinfo->m_vpid, child_tid);
}

/* Parse a failed PPME_SYSCALL_CLONE_20_X event */
TEST_F(sinsp_with_test_input, parse_clone_exit_parent_failed)
{
	add_default_init_thread();
	open_inspector();
	uint64_t init_tid = 1;
	uint64_t parent_ppid = 0;

	/* Scaffolding needed to call the PPME_SYSCALL_CLONE_20_X */
	int64_t child_tid = -2;
	uint64_t not_relevant_64 = 0;
	uint32_t not_relevant_32 = 0;
	scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

	/* Here we simulate a new process spawned by the init one.
	 * The parent is the init process so `tid` == `pid` and `tid` == `vtid`.
	 * Here the father event comes before the child.
	 */
	add_event_advance_ts(increasing_ts(), init_tid, PPME_SYSCALL_CLONE_20_X, 20, child_tid, "bash", empty_bytebuf, init_tid, init_tid, parent_ppid, "", not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_32, not_relevant_32, not_relevant_32, "bash", empty_bytebuf, PPM_CL_CLONE_FILES, not_relevant_32, not_relevant_32, init_tid, init_tid);

	/* The system call failed we don't populate the thread_info for the child  */
	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(child_tid, false, true).get();
	ASSERT_TRUE(tinfo == nullptr);
}

/* Parse a PPME_SYSCALL_CLONE_20_X event with the parent into a container */
TEST_F(sinsp_with_test_input, parse_clone_exit_parent_in_container)
{
	add_default_init_thread();
	open_inspector();
	/* we spawn a clone event from a thread that doesn't exist in our table just to test the behavior in containers */
	uint64_t mock_tid = 18;
	uint64_t mock_vtid = 34;
	uint64_t parent_ppid = 1;

	/* Scaffolding needed to call the PPME_SYSCALL_CLONE_20_X */
	int64_t child_tid = 36;
	uint64_t not_relevant_64 = 0;
	uint32_t not_relevant_32 = 0;
	scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

	/* Here we simulate a new process spawned by the init one.
	 * The parent is the init process so `tid` == `pid` and `tid` == `vtid`.
	 * Here the father event comes before the child.
	 */
	add_event_advance_ts(increasing_ts(), mock_tid, PPME_SYSCALL_CLONE_20_X, 20, child_tid, "bash", empty_bytebuf, mock_tid, mock_tid, parent_ppid, "", not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_32, not_relevant_32, not_relevant_32, "bash", empty_bytebuf, PPM_CL_CLONE_FILES, not_relevant_32, not_relevant_32, mock_vtid, mock_vtid);

	/* The father process is in a container we don't populate the thread_info for the child  */
	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(child_tid, false, true).get();
	ASSERT_TRUE(tinfo == nullptr);
}

/*=============================== CLONE FATHER EXIT EVENT ===========================*/
