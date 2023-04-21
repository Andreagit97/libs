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

#define INIT_TID 1
#define INIT_PID INIT_TID
#define INIT_PARENT 0

#define ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(tid, pid, ppid, vtid, vpid)          \
	{                                                                         \
		tinfo = m_inspector.get_thread_ref(tid, false, true).get();       \
		ASSERT_TRUE(tinfo);                                               \
		ASSERT_EQ(tinfo->m_tid, tid);                                     \
		ASSERT_EQ(tinfo->m_pid, pid);                                     \
		ASSERT_EQ(tinfo->m_ptid, ppid);                                   \
		ASSERT_EQ(tinfo->m_vtid, vtid);                                   \
		ASSERT_EQ(tinfo->m_vpid, vpid);                                   \
		ASSERT_EQ(tinfo->is_main_thread(), tinfo->m_tid == tinfo->m_pid); \
	}

#define ASSERT_THREAD_INFO_PIDS(tid, pid, ppid)                                \
	{                                                                      \
		ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(tid, pid, ppid, tid, pid) \
	}

TEST_F(sinsp_with_test_input, THRD_STATE_check_init_thread)
{
	/* Right now we have only the init process here */
	add_default_init_thread();
	open_inspector();
	uint64_t init_tid = 1;
	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(init_tid, false, true).get();
	ASSERT_TRUE(tinfo);
	ASSERT_TRUE(tinfo->is_main_thread());
	ASSERT_EQ(tinfo->get_main_thread(), tinfo);
	ASSERT_EQ(tinfo->get_parent_thread(), nullptr);
	ASSERT_EQ(tinfo->m_tid, init_tid);
	ASSERT_EQ(tinfo->m_pid, init_tid);
	ASSERT_EQ(tinfo->m_ptid, (int64_t)0);
}

/*=============================== CLONE PARENT EXIT EVENT ===========================*/

/* Parse a failed PPME_SYSCALL_CLONE_20_X event */
TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_failed)
{
	add_default_init_thread();
	open_inspector();

	int64_t child_tid = -3;

	/* Here we generate a parent clone exit event failed */
	generate_clone_x_event(child_tid, INIT_TID, INIT_PID, INIT_PARENT);

	/* We should have a NULL pointer here  */
	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(child_tid, false, true).get();
	ASSERT_TRUE(tinfo == nullptr);
}

/* Parse a PPME_SYSCALL_CLONE_20_X event with the parent into a container */
TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_in_container)
{
	add_default_init_thread();
	open_inspector();

	/* We simulate a parent clone exit event that wants to generate a child into a container */
	int64_t child_tid = 24;

	/* Parent clone exit event */
	generate_clone_x_event(child_tid, INIT_TID, INIT_PID, INIT_PARENT, PPM_CL_CLONE_NEWPID | PPM_CL_CHILD_IN_PIDNS);

	/* The child process is in a container so the parent doesn't populate the thread_info for the child  */
	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(child_tid, false, true).get();
	ASSERT_TRUE(tinfo == nullptr);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_remove_mock_child)
{
	add_default_init_thread();
	open_inspector();

	/* we spawn a mock clone child event but we remove the `PPM_CL_CLONE_INVERTED` flag
	 * in this way the parent clone event should remove it
	 */
	int64_t child_tid = 24;
	int64_t child_pid = 24;
	int64_t child_parent = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, child_tid, child_pid, child_parent, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE, "old_bash");

	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(child_tid, false, true).get();
	ASSERT_TRUE(tinfo);
	ASSERT_EQ(tinfo->m_comm, "old_bash");

	/* Remove the `PPM_CL_CLONE_INVERTED` flag */
	tinfo->m_flags = tinfo->m_flags & ~PPM_CL_CLONE_INVERTED;

	/* Parent clone exit event */
	/* The parent considers the existing child entry stale and removes it. It populates a new threadinfo */
	generate_clone_x_event(child_tid, INIT_TID, INIT_PID, INIT_PARENT, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE, "new_bash");

	tinfo = m_inspector.get_thread_ref(child_tid, false, true).get();
	ASSERT_TRUE(tinfo);
	/* We should find the new name now since this should be a fresh threadinfo */
	ASSERT_EQ(tinfo->m_comm, "new_bash");
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_keep_mock_child)
{
	add_default_init_thread();
	open_inspector();

	/* we spawn a mock clone child event this should be preserved by the parent
	 * since we don't remove the `PPM_CL_CLONE_INVERTED` flag this time.
	 */
	int64_t child_tid = 24;
	int64_t child_pid = 24;
	int64_t child_parent = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, child_tid, child_pid, child_parent, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE, "old_bash");

	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(child_tid, false, true).get();
	ASSERT_TRUE(tinfo);
	ASSERT_EQ(tinfo->m_comm, "old_bash");

	/* Parent clone exit event */
	/* The parent considers the existing child entry stale and removes it. It populates a new threadinfo */
	generate_clone_x_event(child_tid, INIT_TID, INIT_PID, INIT_PARENT, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE, "new_bash");

	tinfo = m_inspector.get_thread_ref(child_tid, false, true).get();
	ASSERT_TRUE(tinfo);
	/* We should find the new name now since this should be a fresh threadinfo */
	ASSERT_EQ(tinfo->m_comm, "old_bash");
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_simple)
{
	add_default_init_thread();
	open_inspector();
	sinsp_threadinfo* tinfo = NULL;

	/* We create a first child */
	int64_t first_child_tid = 24;
	int64_t first_child_pid = 24;
	int64_t first_child_parent = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(first_child_tid, INIT_TID, INIT_PID, INIT_PARENT);
	ASSERT_THREAD_INFO_PIDS(first_child_tid, first_child_pid, first_child_parent)

	/* The first child creates a second child */
	int64_t second_child_tid = 30;
	int64_t second_child_pid = 30;
	int64_t second_child_parent = first_child_pid;

	/* Parent clone exit event */
	generate_clone_x_event(second_child_tid, first_child_tid, first_child_pid, first_child_parent);
	ASSERT_THREAD_INFO_PIDS(second_child_tid, second_child_pid, second_child_parent)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_clone_parent_flag)
{
	add_default_init_thread();
	open_inspector();
	sinsp_threadinfo* tinfo = NULL;

	/* We create a first child */
	int64_t first_child_tid = 24;
	int64_t first_child_pid = 24;
	int64_t first_child_parent = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(first_child_tid, INIT_TID, INIT_PID, INIT_PARENT);
	ASSERT_THREAD_INFO_PIDS(first_child_tid, first_child_pid, first_child_parent)

	/* The first child creates a second child with the `CLONE_PARENT` flag */
	int64_t second_child_tid = 30;
	int64_t second_child_pid = 30;
	int64_t second_child_parent = INIT_PID; /* with the `CLONE_PARENT` flag the parent is the parent of the calling process */

	/* Parent clone exit event */
	generate_clone_x_event(second_child_tid, first_child_tid, first_child_pid, first_child_parent, PPM_CL_CLONE_PARENT);
	ASSERT_THREAD_INFO_PIDS(second_child_tid, second_child_pid, second_child_parent)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_clone_thread_flag)
{
	add_default_init_thread();
	open_inspector();
	sinsp_threadinfo* tinfo = NULL;

	/* We create a first child */
	int64_t first_child_tid = 24;
	int64_t first_child_pid = 24;
	int64_t first_child_parent = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(first_child_tid, INIT_TID, INIT_PID, INIT_PARENT);
	ASSERT_THREAD_INFO_PIDS(first_child_tid, first_child_pid, first_child_parent)

	/* The first child creates a thread */
	int64_t second_thread_tid = 30;
	int64_t second_thread_pid = 24;
	int64_t second_thread_parent = INIT_PID; /* with the `CLONE_THREAD` flag the parent is the parent of the calling process */

	/* Parent clone exit event */
	generate_clone_x_event(second_thread_tid, first_child_tid, first_child_pid, first_child_parent, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(second_thread_tid, second_thread_pid, second_thread_parent)
}

/*=============================== CLONE FATHER EXIT EVENT ===========================*/

/*=============================== TRAVERSE THREAD INFO ===========================*/

/* here the parent always comes first but we can do also the opposite */
TEST_F(sinsp_with_test_input, THRD_STATE_traverse_thread_info)
{
	add_default_init_thread();
	open_inspector();
	sinsp_threadinfo* tinfo = NULL;

	/* Init process creates a child process */

	/*=============================== p1_t1 ===========================*/

	uint64_t p1_t1_tid = 2;
	uint64_t p1_t1_pid = p1_t1_tid;
	uint64_t p1_t1_parent = INIT_PID;

	/* Parent exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PARENT);

	/* Check fields after parent parsing */
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_parent)

	/* Child exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_parent);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_parent)

	/*=============================== p1_t1 ===========================*/

	/* p1 process creates a second thread */

	/*=============================== p1_t2 ===========================*/

	uint64_t p1_t2_tid = 6;
	uint64_t p1_t2_pid = p1_t1_pid;
	uint64_t p1_t2_parent = INIT_PID;

	/* Parent exit event */
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_parent, PPM_CL_CLONE_THREAD);

	/* Check fields after parent parsing */
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_parent)

	/* Child exit event */
	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_parent, PPM_CL_CLONE_THREAD);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_parent)

	/*=============================== p1_t2 ===========================*/

	/* The second thread of p1 create a new process p2 */

	/*=============================== p2_t1 ===========================*/

	uint64_t p2_t1_tid = 25;
	uint64_t p2_t1_pid = 25;
	uint64_t p2_t1_parent = INIT_PID;

	/* Parent exit event */
	generate_clone_x_event(p2_t1_tid, p1_t2_tid, p1_t2_pid, p1_t2_parent, PPM_CL_CLONE_PARENT);

	/* Check fields after parent parsing */
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_parent)

	/* Child exit event */
	generate_clone_x_event(0, p2_t1_tid, p2_t1_pid, p2_t1_parent, PPM_CL_CLONE_PARENT);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_parent)

	/*=============================== p2_t1 ===========================*/

	/* p2 process creates a second thread */

	/*=============================== p2_t2 ===========================*/

	uint64_t p2_t2_tid = 23;
	uint64_t p2_t2_pid = p2_t1_pid;
	uint64_t p2_t2_parent = INIT_PID; /* p2_t2 will have the same parent of p2_t1 */

	/* Parent exit event */
	generate_clone_x_event(p2_t2_tid, p2_t1_tid, p2_t1_pid, p2_t1_parent, PPM_CL_CLONE_THREAD);

	/* Check fields after parent parsing */
	ASSERT_THREAD_INFO_PIDS(p2_t2_tid, p2_t2_pid, p2_t2_parent)

	/* Child exit event */
	generate_clone_x_event(0, p2_t2_tid, p2_t2_pid, p2_t2_parent, PPM_CL_CLONE_THREAD);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS(p2_t2_tid, p2_t2_pid, p2_t2_parent)

	/*=============================== p2_t2 ===========================*/

	/* The leader thread of p2 create a new process p3 */

	/*=============================== p3_t1 ===========================*/

	uint64_t p3_t1_tid = 72;
	uint64_t p3_t1_pid = p3_t1_tid;
	uint64_t p3_t1_parent = p2_t1_pid;

	/* Parent exit event */
	generate_clone_x_event(p3_t1_tid, p2_t1_tid, p2_t1_pid, p2_t1_parent);

	/* Check fields after parent parsing */
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_parent)

	/* Child exit event */
	generate_clone_x_event(0, p3_t1_tid, p3_t1_pid, p3_t1_parent);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_parent)

	/*=============================== p3_t1 ===========================*/

	/* The leader thread of p3 create a new process p4 in a new container */

	/*=============================== p4_t1 ===========================*/

	uint64_t p4_t1_tid = 76;
	uint64_t p4_t1_pid = p4_t1_tid;
	uint64_t p4_t1_parent = p3_t1_pid;
	uint64_t p4_t1_vtid = 1; /* This process will be the `init` one in the new namespace */
	uint64_t p4_t1_vpid = p4_t1_vtid;

	/* Parent exit event */
	generate_clone_x_event(p4_t1_tid, p3_t1_tid, p3_t1_pid, p3_t1_parent, PPM_CL_CHILD_IN_PIDNS | PPM_CL_CLONE_NEWPID);

	/* Check fields after parent parsing
	 * Note: here we cannot assert anything because the child will be in a container
	 * and so the parent doesn't create the `thread-info` for the child.
	 */

	/* Child exit event */
	/* On arm64 the flag `PPM_CL_CLONE_NEWPID` is not sent by the child, so we simulate the worst case */
	generate_clone_x_event(0, p4_t1_tid, p4_t1_pid, p4_t1_parent, PPM_CL_CHILD_IN_PIDNS, p4_t1_vtid, p4_t1_vpid);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, p4_t1_parent, p4_t1_vtid, p4_t1_vpid)

	/*=============================== p4_t1 ===========================*/

	/* ... */
}

/*=============================== TRAVERSE THREAD INFO ===========================*/
