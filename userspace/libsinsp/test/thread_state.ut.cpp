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
	sinsp_evt* evt = NULL;
	int64_t child_tid = -3;

	/* Here we generate a parent clone exit event failed */
	evt = generate_clone_x_event(child_tid, INIT_TID, INIT_PID, INIT_PARENT);

	/* Since we are the father we should have a thread-info associated even if the clone failed */
	ASSERT_TRUE(evt->get_thread_info());
	ASSERT_EQ(evt->get_thread_info()->m_tid, INIT_TID);
	ASSERT_EQ(evt->get_thread_info()->m_pid, INIT_PID);
	ASSERT_EQ(evt->get_thread_info()->m_ptid, INIT_PARENT);

	/* We should have a NULL pointer here so no thread-info for the child */
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

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_simulate_old_scap_file)
{
	add_default_init_thread();
	open_inspector();

	/* Init create a child process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_parent = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PARENT);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_parent)

	/* process p1 creates a second thread */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_parent = INIT_PID; /* with the `CLONE_THREAD` flag the parent is the parent of the calling process */

	/* Parent clone exit event */
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_parent, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_parent)

	/* The second thread of p1 creates a new process p2 */
	/* Here we are receiving the clone exit event of the parent so the old scap-file won't have wrong info.
	 * Only if the new process (that is the child of a thread) will do another clone() we will notice the wrong info.
	 */
	int64_t p2_t1_tid = 80;
	int64_t p2_t1_pid = 80;
	int64_t p2_t1_parent = p1_t2_pid;

	/* Parent clone exit event */
	generate_clone_x_event(p2_t1_tid, p1_t2_tid, p1_t2_pid, p1_t2_parent);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_parent)

	/* process p2 creates a new process p3 */
	int64_t p3_t1_tid = 90;
	int64_t p3_t1_pid = 90;
	int64_t p3_t1_parent = p2_t1_pid;

	/* Parent clone exit event */
	/* Please note here that the parent of p2 will be wrong in the scap-file!
	 * It should be `p2_t1_parent` and so `p1_t2_pid` but indeed it will be the tid of `p1_t2` and so `p1_t2_tid`
	 * BTW thanks to our recovery logic we should be able to correctly populate the new process thread info (p3 thread info) 
	 */
	generate_clone_x_event(p3_t1_tid, p2_t1_tid, p2_t1_pid, p1_t2_tid);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_parent)
	sinsp_threadinfo* ptinfo = m_inspector.get_thread_ref(p2_t1_tid, false, true).get();
	ASSERT_TRUE(ptinfo);
	/* The clone parent event carries wrong info so we don't update the parent info */
	ASSERT_EQ(ptinfo->m_ptid, p2_t1_parent);
}

/* Here the parent exit event always comes first  */
TEST_F(sinsp_with_test_input, THRD_STATE_traverse_thread_info_parent_first)
{
	/* This test represents the following process tree:
	 *	- (init) tid 1 pid 1 ppid 0
	 *  - (p_1 - t1) tid 2 pid 2 ppid 1
	 *  - (p_1 - t2) tid 3 pid 2 ppid 1
	 * 	  - (p_2 - t1) tid 25 pid 25 ppid 1
	 * 		- (p_3 - t1) tid 72 pid 72 ppid 25
	 * 			- (p_4 - t1) tid 76 pid 76 ppid 72 (container: vtid 1 vpid 1)
	 * 	  - (p_2 - t2) tid 23 pid 25 ppid 1
	 */

	add_default_init_thread();
	open_inspector();

	/* Init process creates a child process */

	/*=============================== p1_t1 ===========================*/

	int64_t p1_t1_tid = 2;
	int64_t p1_t1_pid = p1_t1_tid;
	int64_t p1_t1_parent = INIT_PID;

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

	int64_t p1_t2_tid = 6;
	int64_t p1_t2_pid = p1_t1_pid;
	int64_t p1_t2_parent = INIT_PID;

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

	int64_t p2_t1_tid = 25;
	int64_t p2_t1_pid = 25;
	int64_t p2_t1_parent = INIT_PID;

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

	int64_t p2_t2_tid = 23;
	int64_t p2_t2_pid = p2_t1_pid;
	int64_t p2_t2_parent = INIT_PID; /* p2_t2 will have the same parent of p2_t1 */

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

	int64_t p3_t1_tid = 72;
	int64_t p3_t1_pid = p3_t1_tid;
	int64_t p3_t1_parent = p2_t1_pid;

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

	int64_t p4_t1_tid = 76;
	int64_t p4_t1_pid = p4_t1_tid;
	int64_t p4_t1_parent = p3_t1_pid;
	int64_t p4_t1_vtid = 1; /* This process will be the `init` one in the new namespace */
	int64_t p4_t1_vpid = p4_t1_vtid;

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

	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(p4_t1_tid, false, true).get();

	std::vector<int64_t> p4_traverse_parents;
	/* Here we prepare tid of the parents, please note that all the parents will always be process so
	 * `tid == pid`.
	 */
	std::vector<int64_t> expected_p4_traverse_parents = {p4_t1_parent, p3_t1_parent, p2_t1_parent};

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
	int64_t child_tid = 24;
	int64_t child_pid = 24;
	int64_t child_parent = INIT_PID;
	int64_t child_vtid = 80;
	int64_t child_vpid = 80;

	/* Child clone exit event */
	/* if we use `sched_proc_fork` tracepoint `PPM_CL_CLONE_NEWPID` won't be sent so we don't use it here, w use just `PPM_CL_CHILD_IN_PIDNS` */
	generate_clone_x_event(0, child_tid, child_pid, child_parent, PPM_CL_CHILD_IN_PIDNS, child_vtid, child_vpid);

	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(child_tid, child_pid, child_parent, child_vtid, child_vpid)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_already_there)
{
	add_default_init_thread();
	open_inspector();

	/* Create a mock child with a clone exit parent event */
	int64_t mock_child_tid = 24;
	int64_t mock_child_pid = 24;
	int64_t mock_child_parent = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(mock_child_tid, INIT_TID, INIT_PID, INIT_PARENT);

	/* Now we try to create a child with a different pid but same tid with a clone exit child event */
	int64_t new_pid = 35;
	sinsp_evt* evt = generate_clone_x_event(0, mock_child_tid, new_pid, mock_child_parent);

	/* The child parser should find a valid `evt->m_tinfo` set by the previous
	 * parent clone event, so this new child event should be ignored and so
	 * the pid shouldn't be updated
	 */
	ASSERT_TRUE(evt && evt->get_thread_info());
	ASSERT_EQ(evt->get_thread_info()->m_pid, mock_child_pid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_replace_stale_child)
{
	add_default_init_thread();
	open_inspector();
	sinsp_threadinfo* tinfo = NULL;

	/* Create a mock child with a clone exit parent event */
	int64_t mock_child_tid = 24;
	int64_t mock_child_parent = INIT_PID;

	/* Parent clone exit event */
	generate_clone_x_event(mock_child_tid, INIT_TID, INIT_PID, INIT_PARENT);

	/* Now we taint the child thread info `clone_ts`, in this way when the
	 * clone child exit event will be called we should treat the current thread info
	 * as stale.
	 */
	tinfo = m_inspector.get_thread_ref(mock_child_tid, false, true).get();
	ASSERT_TRUE(tinfo);
	tinfo->m_clone_ts = tinfo->m_clone_ts - (CLONE_STALE_TIME_NS + 1);

	/* Now we try to create a child with a different pid but same tid with a clone exit child event */
	int64_t new_pid = 35;
	sinsp_evt* evt = generate_clone_x_event(0, mock_child_tid, new_pid, mock_child_parent);

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
	sinsp_threadinfo* tinfo = NULL;

	/* We create a first child */
	int64_t first_child_tid = 24;
	int64_t first_child_pid = 24;
	int64_t first_child_parent = INIT_PID;

	/* Child clone exit event */
	evt = generate_clone_x_event(0, first_child_tid, first_child_pid, first_child_parent);
	ASSERT_THREAD_INFO_PIDS(first_child_tid, first_child_pid, first_child_parent)

	/* Check if the thread-info in the thread table is correctly assigned to our event */
	tinfo = m_inspector.get_thread_ref(first_child_tid, false, true).get();
	ASSERT_TRUE(evt && evt->get_thread_info());
	ASSERT_TRUE(tinfo);
	ASSERT_EQ(tinfo, evt->get_thread_info());

	/* The first child creates a second child */
	int64_t second_child_tid = 30;
	int64_t second_child_pid = 30;
	int64_t second_child_parent = first_child_pid;

	/* Child clone exit event */
	evt = generate_clone_x_event(0, second_child_tid, second_child_pid, second_child_parent);
	ASSERT_THREAD_INFO_PIDS(second_child_tid, second_child_pid, second_child_parent)

	/* Check if the thread-info in the thread table is correctly assigned to our event */
	tinfo = m_inspector.get_thread_ref(second_child_tid, false, true).get();
	ASSERT_TRUE(evt && evt->get_thread_info());
	ASSERT_TRUE(tinfo);
	ASSERT_EQ(tinfo, evt->get_thread_info());
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_clone_parent_flag)
{
	add_default_init_thread();
	open_inspector();

	/* We create a first child */
	int64_t first_child_tid = 24;
	int64_t first_child_pid = 24;
	int64_t first_child_parent = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, first_child_tid, first_child_pid, first_child_parent);
	ASSERT_THREAD_INFO_PIDS(first_child_tid, first_child_pid, first_child_parent)

	/* The first child creates a second child with the `CLONE_PARENT` flag */
	int64_t second_child_tid = 30;
	int64_t second_child_pid = 30;
	int64_t second_child_parent = INIT_PID; /* with the `CLONE_PARENT` flag the parent is the parent of the calling process */

	/* Child clone exit event */
	/* Please note that in the clone child exit event, it could happen that
	 * we don't have the `PPM_CL_CLONE_PARENT` flag because the event could
	 * be generated by the `sched_proc_fork` tracepoint. BTW the child parser
	 * shouldn't need this flag to detect the real parent, so we omit it here
	 * and see what happens.
	 */
	generate_clone_x_event(0, second_child_tid, second_child_pid, second_child_parent); // PPM_CL_CLONE_PARENT
	ASSERT_THREAD_INFO_PIDS(second_child_tid, second_child_pid, second_child_parent)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_clone_thread_flag)
{
	add_default_init_thread();
	open_inspector();

	/* We create a first child */
	int64_t first_child_tid = 24;
	int64_t first_child_pid = 24;
	int64_t first_child_parent = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, first_child_tid, first_child_pid, first_child_parent);
	ASSERT_THREAD_INFO_PIDS(first_child_tid, first_child_pid, first_child_parent)

	/* The first child creates a thread */
	int64_t second_thread_tid = 30;
	int64_t second_thread_pid = 24;
	int64_t second_thread_parent = INIT_PID; /* with the `CLONE_THREAD` flag the parent is the parent of the calling process */

	/* Child clone exit event */
	generate_clone_x_event(0, second_thread_tid, second_thread_pid, second_thread_parent, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(second_thread_tid, second_thread_pid, second_thread_parent)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_simulate_old_scap_file)
{
	add_default_init_thread();
	open_inspector();

	/* We create a first child */
	int64_t first_child_tid = 24;
	int64_t first_child_pid = 24;
	int64_t first_child_parent = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, first_child_tid, first_child_pid, first_child_parent);
	ASSERT_THREAD_INFO_PIDS(first_child_tid, first_child_pid, first_child_parent)

	/* The first child creates a thread */
	int64_t second_thread_tid = 30;
	int64_t second_thread_pid = 24;
	int64_t second_thread_parent = INIT_PID; /* with the `CLONE_THREAD` flag the parent is the parent of the calling process */

	/* Child clone exit event */
	generate_clone_x_event(0, second_thread_tid, second_thread_pid, second_thread_parent, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(second_thread_tid, second_thread_pid, second_thread_parent)

	/* The second thread creates a child */
	int64_t second_child_tid = 80;
	int64_t second_child_pid = 80;
	/* old scap files return `real_parent->pid` so the parent will be the second thread and not the leader thread.
	 * BTW, our recovery logic should patch the parent value to `first_child_pid`.
	 */
	int64_t second_child_parent = second_thread_tid; // our recovery logic will set `first_child_pid` here

	/* Child clone exit event */
	generate_clone_x_event(0, second_child_tid, second_child_pid, second_child_parent);
	ASSERT_THREAD_INFO_PIDS(second_child_tid, second_child_pid, first_child_pid)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_simulate_old_scap_file_missing_info)
{
	add_default_init_thread();
	open_inspector();

	/* We create a first child */
	int64_t first_child_tid = 24;
	int64_t first_child_pid = 24;
	int64_t first_child_parent = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, first_child_tid, first_child_pid, first_child_parent);
	ASSERT_THREAD_INFO_PIDS(first_child_tid, first_child_pid, first_child_parent)

	/* Now let's imagine that the first child creates a thread
	 * like in the previous test, but we miss it.
	 *
	 * 	 int64_t second_thread_tid = 30;
	 *   int64_t second_thread_pid = 24;
	 *   int64_t second_thread_parent = INIT_PID;
	 *   generate_clone_x_event(0, second_thread_tid, second_thread_pid, second_thread_parent, PPM_CL_CLONE_THREAD);
	 *
	 * When this thread will create a new process we won't be able
	 * to patch the `ptid` since we miss the caller thread info!
	 */

	/* The second thread creates a child */
	int64_t second_child_tid = 80;
	int64_t second_child_pid = 80;
	int64_t second_child_parent = 30; // Our recovery logic will leave `second_thread_tid`, because we miss caller info
	const char* second_child_mock_name = "mock_name";
	/* Child clone exit event */
	generate_clone_x_event(0, second_child_tid, second_child_pid, second_child_parent, 0, second_child_tid, second_child_pid, second_child_mock_name);
	ASSERT_THREAD_INFO_PIDS(second_child_tid, second_child_pid, second_child_parent)

	/* During the parsing logic of the child we create also a mock parent since
	 * it was not present. Let's assert some of its values...
	 */
	sinsp_threadinfo* ptinfo = m_inspector.get_thread_ref(second_child_parent, false, true).get();
	ASSERT_TRUE(ptinfo);
	ASSERT_EQ(ptinfo->m_user.uid, 0xffffffff);
	ASSERT_EQ(ptinfo->m_user.uid, 0xffffffff);
	ASSERT_EQ(ptinfo->m_loginuser.uid, 0xffffffff);
	ASSERT_EQ(ptinfo->m_nchilds, 0);
	ASSERT_EQ(ptinfo->m_exe, second_child_mock_name);
	ASSERT_EQ(ptinfo->m_comm, second_child_mock_name);
	ASSERT_EQ(ptinfo->m_tid, second_child_parent);
	ASSERT_EQ(ptinfo->m_pid, second_child_parent); /// todo: this is wrong we created a new main thread but this is not a main thread!
	GTEST_SKIP() << "The parent thread info matches the expected one, but some parent data are not correct!";
}

/*=============================== CLONE CHILD EXIT EVENT ===========================*/
