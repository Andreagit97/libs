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
#define INIT_PTID 0
#define UNUSED __attribute__((unused))

#define ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(tid, pid, ppid, vtid, vpid)                      \
	{                                                                                     \
		sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(tid, false, true).get(); \
		ASSERT_TRUE(tinfo);                                                           \
		ASSERT_EQ(tinfo->m_tid, tid);                                                 \
		ASSERT_EQ(tinfo->m_pid, pid);                                                 \
		ASSERT_EQ(tinfo->m_ptid, ppid);                                               \
		ASSERT_EQ(tinfo->m_vtid, vtid);                                               \
		ASSERT_EQ(tinfo->m_vpid, vpid);                                               \
		ASSERT_EQ(tinfo->is_main_thread(), tinfo->m_tid == tinfo->m_pid);             \
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
	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(tinfo);
	ASSERT_TRUE(tinfo->is_main_thread());
	ASSERT_EQ(tinfo->get_main_thread(), tinfo);
	ASSERT_EQ(tinfo->get_parent_thread(), nullptr);
	ASSERT_EQ(tinfo->m_tid, INIT_TID);
	ASSERT_EQ(tinfo->m_pid, INIT_PID);
	ASSERT_EQ(tinfo->m_ptid, INIT_PTID);
}

/*=============================== CLONE PARENT EXIT EVENT ===========================*/

/* Parse a failed PPME_SYSCALL_CLONE_20_X event */
TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_failed)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;
	int64_t p1_t1_tid = -3;

	/* Here we generate a parent clone exit event failed */
	evt = generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);

	/* Since we are the father we should have a thread-info associated even if the clone failed */
	ASSERT_TRUE(evt->get_thread_info());
	ASSERT_EQ(evt->get_thread_info()->m_tid, INIT_TID);
	ASSERT_EQ(evt->get_thread_info()->m_pid, INIT_PID);
	ASSERT_EQ(evt->get_thread_info()->m_ptid, INIT_PTID);

	/* We should have a NULL pointer here so no thread-info for the new process */
	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo == nullptr);
}

/* Parse a PPME_SYSCALL_CLONE_20_X event with the parent into a container */
TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_in_container)
{
	add_default_init_thread();
	open_inspector();

	/* We simulate a parent clone exit event that wants to generate a child into a container */
	int64_t p1_t1_tid = 24;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID, PPM_CL_CLONE_NEWPID | PPM_CL_CHILD_IN_PIDNS);

	/* The child process is in a container so the parent doesn't populate the thread_info for the child  */
	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo == nullptr);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_remove_mock_child)
{
	add_default_init_thread();
	open_inspector();

	/* we spawn a mock clone child event but we remove the `PPM_CL_CLONE_INVERTED` flag
	 * in this way the parent clone event should remove it
	 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE, "old_bash");

	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo->m_comm, "old_bash");

	/* Remove the `PPM_CL_CLONE_INVERTED` flag */
	p1_t1_tinfo->m_flags = p1_t1_tinfo->m_flags & ~PPM_CL_CLONE_INVERTED;

	/* Parent clone exit event */
	/* The parent considers the existing child entry stale and removes it. It populates a new thread info */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE, "new_bash");

	p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	/* We should find the new name now since this should be a fresh thread info */
	ASSERT_EQ(p1_t1_tinfo->m_comm, "new_bash");
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_keep_mock_child)
{
	add_default_init_thread();
	open_inspector();

	/* we spawn a mock clone child event this should be preserved by the parent
	 * since we don't remove the `PPM_CL_CLONE_INVERTED` flag this time.
	 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE, "old_bash");

	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo->m_comm, "old_bash");

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE, "new_bash");

	p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo->m_comm, "old_bash");
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_simple)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* The process p1 creates a second process p2 */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = p1_t1_pid;

	/* Parent clone exit event */
	generate_clone_x_event(p2_t1_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_clone_parent_flag)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* The process p1 creates a second process p2 with the `CLONE_PARENT` flag */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = INIT_PID; /* with the `CLONE_PARENT` flag the parent is the parent of the calling process */

	/* Parent clone exit event */
	generate_clone_x_event(p2_t1_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_PARENT);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_clone_thread_flag)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	/// todo(@Andreagit97): rename all `_parent` in ptid;
	int64_t p1_t1_ptid = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* The process p1 creates a second thread p1_t2 */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_PID; /* with the `CLONE_THREAD` flag the parent is the parent of the calling process */

	/* Parent clone exit event */
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)
}

// TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_simulate_old_scap_file)
// {
// 	add_default_init_thread();
// 	open_inspector();

// 	/* Init create a child process p1 */
// 	int64_t p1_t1_tid = 24;
// 	int64_t p1_t1_pid = 24;
// 	int64_t p1_t1_ptid = INIT_PID;

// 	/* Parent clone exit event */
// 	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
// 	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

// 	/* process p1 creates a second thread */
// 	int64_t p1_t2_tid = 30;
// 	int64_t p1_t2_pid = 24;
// 	int64_t p1_t2_ptid = INIT_PID; /* with the `CLONE_THREAD` flag the parent is the parent of the calling process */

// 	/* Parent clone exit event */
// 	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);
// 	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)

// 	/* The second thread of p1 creates a new process p2 */
// 	/* Here we are receiving the clone exit event of the parent so the old scap-file won't have wrong info.
// 	 * Only if the new process (that is the child of a thread) will do another clone() we will notice the wrong info.
// 	 */
// 	int64_t p2_t1_tid = 80;
// 	int64_t p2_t1_pid = 80;
// 	int64_t p2_t1_ptid = p1_t2_pid;

// 	/* Parent clone exit event */
// 	generate_clone_x_event(p2_t1_tid, p1_t2_tid, p1_t2_pid, p1_t2_ptid);
// 	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)

// 	/* process p2 creates a new process p3 */
// 	int64_t p3_t1_tid = 90;
// 	int64_t p3_t1_pid = 90;
// 	int64_t p3_t1_ptid = p2_t1_pid;

// 	/* Parent clone exit event */
// 	/* Please note here that the parent of p2 will be wrong in the scap-file!
// 	 * It should be `p2_t1_parent` and so `p1_t2_pid` but indeed it will be the tid of `p1_t2` and so `p1_t2_tid`
// 	 * BTW thanks to our recovery logic we should be able to correctly populate the new process thread info (p3 thread info)
// 	 */
// 	generate_clone_x_event(p3_t1_tid, p2_t1_tid, p2_t1_pid, p1_t2_tid);
// 	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_ptid)
// 	sinsp_threadinfo* ptinfo = m_inspector.get_thread_ref(p2_t1_tid, false, true).get();
// 	ASSERT_TRUE(ptinfo);
// 	/* The clone parent event carries wrong info so we don't update the parent info */
// 	ASSERT_EQ(ptinfo->m_ptid, p2_t1_ptid);
// }

/* Here the parent exit event always comes first  */
TEST_F(sinsp_with_test_input, THRD_STATE_traverse_thread_info_parent_first)
{
	/* This test represents the following process tree:
	 *	- (init) tid 1 pid 1 ptid 0
	 *  - (p_1 - t1) tid 2 pid 2 ptid 1
	 *  - (p_1 - t2) tid 3 pid 2 ptid 1
	 * 	  - (p_2 - t1) tid 25 pid 25 ptid 1 (CLONE_ptid)
	 * 		- (p_3 - t1) tid 72 pid 72 ptid 25
	 * 			- (p_4 - t1) tid 76 pid 76 ptid 72 (container: vtid 1 vpid 1)
	 * 	  - (p_2 - t2) tid 23 pid 25 ptid 1
	 */

	add_default_init_thread();
	open_inspector();

	/* Init process creates a child process */

	/*=============================== p1_t1 ===========================*/

	int64_t p1_t1_tid = 2;
	int64_t p1_t1_pid = p1_t1_tid;
	int64_t p1_t1_ptid = INIT_TID;

	/* Parent exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);

	/* Check fields after parent parsing */
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* Child exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/*=============================== p1_t1 ===========================*/

	/* p1 process creates a second thread */

	/*=============================== p1_t2 ===========================*/

	int64_t p1_t2_tid = 6;
	int64_t p1_t2_pid = p1_t1_pid;
	int64_t p1_t2_ptid = INIT_TID;

	/* Parent exit event */
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);

	/* Check fields after parent parsing */
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)

	/* Child exit event */
	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_THREAD);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)

	/*=============================== p1_t2 ===========================*/

	/* The second thread of p1 create a new process p2 */

	/*=============================== p2_t1 ===========================*/

	int64_t p2_t1_tid = 25;
	int64_t p2_t1_pid = 25;
	int64_t p2_t1_ptid = INIT_TID;

	/* Parent exit event */
	generate_clone_x_event(p2_t1_tid, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_PARENT);

	/* Check fields after parent parsing */
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)

	/* Child exit event */
	generate_clone_x_event(0, p2_t1_tid, p2_t1_pid, p2_t1_ptid, PPM_CL_CLONE_PARENT);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)

	/*=============================== p2_t1 ===========================*/

	/* p2 process creates a second thread */

	/*=============================== p2_t2 ===========================*/

	int64_t p2_t2_tid = 23;
	int64_t p2_t2_pid = p2_t1_pid;
	int64_t p2_t2_ptid = INIT_TID; /* p2_t2 will have the same parent of p2_t1 */

	/* Parent exit event */
	generate_clone_x_event(p2_t2_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid, PPM_CL_CLONE_THREAD);

	/* Check fields after parent parsing */
	ASSERT_THREAD_INFO_PIDS(p2_t2_tid, p2_t2_pid, p2_t2_ptid)

	/* Child exit event */
	generate_clone_x_event(0, p2_t2_tid, p2_t2_pid, p2_t2_ptid, PPM_CL_CLONE_THREAD);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS(p2_t2_tid, p2_t2_pid, p2_t2_ptid)

	/*=============================== p2_t2 ===========================*/

	/* The leader thread of p2 create a new process p3 */

	/*=============================== p3_t1 ===========================*/

	int64_t p3_t1_tid = 72;
	int64_t p3_t1_pid = p3_t1_tid;
	int64_t p3_t1_ptid = p2_t1_tid;

	/* Parent exit event */
	generate_clone_x_event(p3_t1_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid);

	/* Check fields after parent parsing */
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_ptid)

	/* Child exit event */
	generate_clone_x_event(0, p3_t1_tid, p3_t1_pid, p3_t1_ptid);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_ptid)

	/*=============================== p3_t1 ===========================*/

	/* The leader thread of p3 create a new process p4 in a new container */

	/*=============================== p4_t1 ===========================*/

	int64_t p4_t1_tid = 76;
	int64_t p4_t1_pid = p4_t1_tid;
	int64_t p4_t1_ptid = p3_t1_tid;
	int64_t p4_t1_vtid = 1; /* This process will be the `init` one in the new namespace */
	int64_t p4_t1_vpid = p4_t1_vtid;

	/* Parent exit event */
	generate_clone_x_event(p4_t1_tid, p3_t1_tid, p3_t1_pid, p3_t1_ptid, PPM_CL_CHILD_IN_PIDNS | PPM_CL_CLONE_NEWPID);

	/* Check fields after parent parsing
	 * Note: here we cannot assert anything because the child will be in a container
	 * and so the parent doesn't create the `thread-info` for the child.
	 */

	/* Child exit event */
	/* On arm64 the flag `PPM_CL_CLONE_NEWPID` is not sent by the child, so we simulate the worst case */
	generate_clone_x_event(0, p4_t1_tid, p4_t1_pid, p4_t1_ptid, PPM_CL_CHILD_IN_PIDNS, p4_t1_vtid, p4_t1_vpid);

	/* Check fields after child parsing */
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, p4_t1_ptid, p4_t1_vtid, p4_t1_vpid)

	/*=============================== p4_t1 ===========================*/

	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(p4_t1_tid, false, true).get();

	std::vector<int64_t> p4_traverse_parents;
	/* Here we prepare tid of the parents, please note that all the parents will always be process so
	 * `tid == pid`.
	 */
	std::vector<int64_t> expected_p4_traverse_parents = {p4_t1_ptid, p3_t1_ptid, p2_t1_ptid};

	sinsp_threadinfo::visitor_func_t p4_visitor = [&p4_traverse_parents](sinsp_threadinfo* pt)
	{
		/* we stop when we reach the init parent */
		p4_traverse_parents.push_back(pt->m_tid);
		if(pt->m_tid == INIT_TID)
		{
			return false;
		}
		return true;
	};

	tinfo->traverse_parent_state(p4_visitor);
	ASSERT_EQ(p4_traverse_parents, expected_p4_traverse_parents);

	/* Remove some threads from the tree... */

	/* Implement reparenting... */

	/* Check again the traverse... */
}

/*=============================== CLONE PARENT EXIT EVENT ===========================*/

/*=============================== CLONE CHILD EXIT EVENT ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_in_container)
{
	add_default_init_thread();
	open_inspector();

	/* We simulate a child clone exit event that wants to generate a child into a container */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;
	int64_t p1_t1_vtid = 80;
	int64_t p1_t1_vpid = 80;

	/* Child clone exit event */
	/* if we use `sched_proc_fork` tracepoint `PPM_CL_CLONE_NEWPID` won't be sent so we don't use it here, we use just `PPM_CL_CHILD_IN_PIDNS` */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CHILD_IN_PIDNS, p1_t1_vtid, p1_t1_vpid);

	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p1_t1_tid, p1_t1_pid, p1_t1_ptid, p1_t1_vtid, p1_t1_vpid)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_already_there)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);

	/* Now we try to create a child with a different pid but same tid with a clone exit child event */
	int64_t new_pid = 35;
	sinsp_evt* evt = generate_clone_x_event(0, p1_t1_tid, new_pid, p1_t1_ptid);

	/* The child parser should find a valid `evt->m_tinfo` set by the previous
	 * parent clone event, so this new child event should be ignored and so
	 * the pid shouldn't be updated
	 */
	ASSERT_TRUE(evt && evt->get_thread_info());
	ASSERT_EQ(evt->get_thread_info()->m_pid, p1_t1_pid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_replace_stale_child)
{
	add_default_init_thread();
	open_inspector();
	sinsp_threadinfo* tinfo = NULL;

	/* Create a mock child with a clone exit parent event */
	int64_t p1_t1_tid = 24;
	// int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);

	/* Now we taint the child thread info `clone_ts`, in this way when the
	 * clone child exit event will be called we should treat the current thread info
	 * as stale.
	 */
	tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(tinfo);
	tinfo->m_clone_ts = tinfo->m_clone_ts - (CLONE_STALE_TIME_NS + 1);

	/* Now we try to create a child with a different pid but same tid with a clone exit child event */
	int64_t new_pid = 35;
	sinsp_evt* evt = generate_clone_x_event(0, p1_t1_tid, new_pid, p1_t1_ptid);

	/* The child parser should find a "stale" `evt->m_tinfo` set by the previous
	 * parent clone event and should replace it with new thread info.
	 */
	ASSERT_TRUE(evt && evt->get_thread_info());
	ASSERT_EQ(evt->get_thread_info()->m_pid, new_pid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_simple)
{
	add_default_init_thread();
	open_inspector();
	sinsp_evt* evt = NULL;

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	evt = generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* Check if the thread-info in the thread table is correctly assigned to our event */
	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(evt && evt->get_thread_info());
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo, evt->get_thread_info());

	/* process p1 creates a new process p2 */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = p1_t1_pid;

	/* Child clone exit event */
	evt = generate_clone_x_event(0, p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)

	/* Check if the thread-info in the thread table is correctly assigned to our event */
	sinsp_threadinfo* p2_t1_tinfo = m_inspector.get_thread_ref(p2_t1_tid, false, true).get();
	ASSERT_TRUE(evt && evt->get_thread_info());
	ASSERT_TRUE(p2_t1_tinfo);
	ASSERT_EQ(p2_t1_tinfo, evt->get_thread_info());
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_clone_parent_flag)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* process p1 creates a new process p2 with the `CLONE_PARENT` flag */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = INIT_PID; /* with the `CLONE_PARENT` flag the parent is the parent of the calling process */

	/* Child clone exit event */
	/* Please note that in the clone child exit event, it could happen that
	 * we don't have the `PPM_CL_CLONE_PARENT` flag because the event could
	 * be generated by the `sched_proc_fork` tracepoint. BTW the child parser
	 * shouldn't need this flag to detect the real parent, so we omit it here
	 * and see what happens.
	 */
	generate_clone_x_event(0, p2_t1_tid, p2_t1_pid, p2_t1_ptid); // PPM_CL_CLONE_PARENT
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_clone_thread_flag)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* process p1 creates a new thread (p1_t2_tid) */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_PID; /* with the `CLONE_THREAD` flag the parent is the parent of the calling process */

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)
}

// TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_simulate_old_scap_file)
// {
// 	add_default_init_thread();
// 	open_inspector();

// 	/* Init creates a new process p1 */
// 	int64_t p1_t1_tid = 24;
// 	int64_t p1_t1_pid = 24;
// 	int64_t p1_t1_ptid = INIT_PID;

// 	/* Child clone exit event */
// 	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
// 	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

// 	/* process p1 creates a new thread (p1_t2_tid) */
// 	int64_t p1_t2_tid = 30;
// 	int64_t p1_t2_pid = 24;
// 	int64_t p1_t2_ptid = INIT_PID; /* with the `CLONE_THREAD` flag the parent is the parent of the calling process */

// 	/* Child clone exit event */
// 	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_THREAD);
// 	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)

// 	/* p1_t2 creates a new process p2 */
// 	int64_t p2_t1_tid = 80;
// 	int64_t p2_t1_pid = 80;
// 	int64_t p2_t1_ptid = p1_t1_pid;

// 	/* Child clone exit event */
// 	/* old scap files return `real_parent->pid` so the parent will be the second thread and not the leader thread.
// 	 * BTW, our recovery logic should patch the parent value to `p1_t1_pid`.
// 	 */
// 	generate_clone_x_event(0, p2_t1_tid, p2_t1_pid, p1_t2_tid);
// 	/* Here we should see the patched thread info */
// 	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)
// }

// TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_simulate_old_scap_file_missing_info)
// {
// 	add_default_init_thread();
// 	open_inspector();

// 	/* Init creates a new process p1 */
// 	int64_t p1_t1_tid = 24;
// 	int64_t p1_t1_pid = 24;
// 	int64_t p1_t1_ptid = INIT_PID;

// 	/* Child clone exit event */
// 	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
// 	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

// 	/* Now let's imagine that the process p1 creates a new thread (p1_t2)
// 	 * like in the previous test, but we miss it.
// 	 *
// 	 *   generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_THREAD);
// 	 *
// 	 * When this thread (p1_t2) will create a new process we won't be able
// 	 * to patch the `ptid` since we miss the caller thread info!
// 	 */

// 	int64_t p1_t2_tid = 30;
// 	UNUSED int64_t p1_t2_pid = 24;
// 	UNUSED int64_t p1_t2_ptid = INIT_PID;

// 	/* Missing clone! */

// 	/* p1_t2 creates a new process p2 */
// 	int64_t p2_t1_tid = 80;
// 	int64_t p2_t1_pid = 80;
// 	/* The real parent should be `p1_t2_pid` but in old scap files we used `p1_t2_tid`
// 	 * Here we simulate the scap_file behavior.
// 	 */
// 	int64_t p2_t1_ptid = p1_t2_tid;

// 	/* Child clone exit event */
// 	generate_clone_x_event(0, p2_t1_tid, p2_t1_pid, p2_t1_ptid);
// 	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)

// 	/* During the parsing logic of the child we create also a mock parent (p2_t1_ptid) since
// 	 * it was not present. Let's assert some of its values...
// 	 */
// 	sinsp_threadinfo* p1_t2_tinfo = m_inspector.get_thread_ref(p2_t1_ptid, false, true).get();
// 	ASSERT_TRUE(p1_t2_tinfo);
// 	ASSERT_EQ(p1_t2_tinfo->m_user.uid, 0xffffffff);
// 	ASSERT_EQ(p1_t2_tinfo->m_user.uid, 0xffffffff);
// 	ASSERT_EQ(p1_t2_tinfo->m_loginuser.uid, 0xffffffff);
// 	ASSERT_EQ(p1_t2_tinfo->m_nchilds, 0);
// 	ASSERT_EQ(p1_t2_tinfo->m_exe, "<NA>");
// 	ASSERT_EQ(p1_t2_tinfo->m_comm, "<NA>");
// 	ASSERT_EQ(p1_t2_tinfo->m_tid, p2_t1_ptid);
// 	ASSERT_EQ(p1_t2_tinfo->m_pid, p2_t1_ptid); /// todo: this is wrong we created a new main thread but this is not a main thread!
// 	GTEST_SKIP() << "The parent thread info matches the expected one, but some parent data are not correct!";
// }

/*=============================== CLONE CHILD EXIT EVENT ===========================*/

/*=============================== EXECVE EVENTS ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_remove_thread_after_execve)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* process p1 creates a new thread (p1_t2) */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = p1_t1_pid;
	int64_t p1_t2_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)

	/* p1_t2 creates a new thread (p1_t3) */
	int64_t p1_t3_tid = 36;
	int64_t p1_t3_pid = p1_t1_pid;
	int64_t p1_t3_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t3_tid, p1_t3_pid, p1_t3_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t3_tid, p1_t3_pid, p1_t3_ptid)

	/* p1_t2 calls an execve */
	generate_execve_enter_and_exit_event(0, p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid);

	/* Here we still have the thread info of `p1_t2_tid` */
	sinsp_threadinfo* p1_t2_tinfo = m_inspector.get_thread_ref(p1_t2_tid, false, true).get();
	ASSERT_TRUE(p1_t2_tinfo);

	/* At the next event we should remove the thread info of `p1_t2_tid`.
	 * `PPME_SYSCALL_UNLINK_2_E` is just a random event in this case.
	 */
	add_event_advance_ts(increasing_ts(), p1_t1_tid, PPME_SYSCALL_UNLINK_2_E, 0);

	p1_t2_tinfo = m_inspector.get_thread_ref(p1_t2_tid, false, true).get();
	ASSERT_FALSE(p1_t2_tinfo);

	/* Please note that we still have the thread info of `p1_t3` when we should remove it */
	sinsp_threadinfo* p1_t3_tinfo = m_inspector.get_thread_ref(p1_t3_tid, false, true).get();
	ASSERT_TRUE(p1_t3_tinfo);
	GTEST_SKIP() << "The expected behavior is correct but we need to remove all threads! Moreover, if the main thread performs the execve does someone remove all other threads?";
}

/*=============================== EXECVE EVENTS ===========================*/

/*=============================== NEW THREAD LOGIC ===========================*/

/* There is a bug in this test! 
 * we count some threads more than one time!
 */
TEST_F(sinsp_with_test_input, THRD_STATE_check_number_of_children)
{
	add_default_init_thread();
	open_inspector();

	/* - init
	 *  - p1_t1 (we will create this, thanks to `get_thread_ref()` in `parse_clone_exit_child`)
	 *  - p1_t2
	 *  - p1_t3  
	 * 
	 * We want to check if `p1_t1` will have the right number of children.
	 */

	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;

	/* create thread `p1_t2` for process `p1_t1` */
	int64_t p1_t2_tid = 25;
	int64_t p1_t2_pid = p1_t1_pid;
	int64_t p1_t2_ptid = INIT_TID;

	FAIL() << " We have to be able here the missing thread-leader";
	/* Child clone exit event */
	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)

	// /* Now we should have created also `p1_t1` as an invalid tinfo */
	// sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	// ASSERT_TRUE(p1_t1_tinfo);
	// /* in `add_thread()` we call `increment_mainthread_childcount` so we should be able to correctly
	//  * assign this thread to the new created process.
	//  */
	// ASSERT_EQ(p1_t1_tinfo->m_nchilds, 1);

	// /* Please note that `p1_t1` is still an invalid thread so we will destroy it again at the next clone child event */
	// /// todo(@Andreagit97) not sure this is exactly what we want but populating it with child comm could be a wrong assumption.

	// /* create thread `p1_t3` for process `p1_t1` */
	// int64_t p1_t3_tid = 26;
	// int64_t p1_t3_pid = p1_t1_pid;
	// int64_t p1_t3_ptid = INIT_TID;

	// /* Child clone exit event */
	// generate_clone_x_event(0, p1_t3_tid, p1_t3_pid, p1_t3_ptid, PPM_CL_CLONE_THREAD);
	// ASSERT_THREAD_INFO_PIDS(p1_t3_tid, p1_t3_pid, p1_t3_ptid)

	// p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	// ASSERT_TRUE(p1_t1_tinfo);
	// ASSERT_EQ(p1_t1_tinfo->m_nchilds, 2);
}

/*=============================== NEW THREAD LOGIC ===========================*/

/*=============================== REMOVE THREAD LOGIC ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_remove_non_existing_thread)
{
	add_default_init_thread();
	open_inspector();

	int64_t unknown_tid = 24;
	
	/* we should do nothing, here we are only checking that nothing will crash */
	m_inspector.remove_thread(unknown_tid, false);
	m_inspector.remove_thread(unknown_tid, true);
}

TEST_F(sinsp_with_test_input, THRD_STATE_remove_a_thread_leader_without_children)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* We should be able to remove the thread since it doesn't have children */
	m_inspector.remove_thread(p1_t1_tid, false);
	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_FALSE(p1_t1_tinfo);
}



/* creare un proccesso vuoto con il finto scan di proc e prima creare alcuni suoi thread e vedere il numero che si setta di child figli */

/*=============================== REMOVE THREAD LOGIC ===========================*/
