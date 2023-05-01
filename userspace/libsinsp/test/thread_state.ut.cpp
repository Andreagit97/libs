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

#define ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(tid, pid, ptid, vtid, vpid)                                               \
	{                                                                                                              \
		sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(tid, false, true).get();                          \
		ASSERT_TRUE(tinfo);                                                                                    \
		ASSERT_EQ(tinfo->m_tid, tid);                                                                          \
		ASSERT_EQ(tinfo->m_pid, pid);                                                                          \
		ASSERT_EQ(tinfo->m_ptid, ptid);                                                                        \
		ASSERT_EQ(tinfo->m_vtid, vtid);                                                                        \
		ASSERT_EQ(tinfo->m_vpid, vpid);                                                                        \
		ASSERT_EQ(tinfo->is_main_thread(), tinfo->m_tid == tinfo->m_pid);                                      \
	}

#define ASSERT_THREAD_INFO_PIDS(tid, pid, ppid)                                                                        \
	{                                                                                                              \
		ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(tid, pid, ppid, tid, pid)                                         \
	}

#define ASSERT_THREAD_GROUP_INFO(tg_pid, alive_threads, reaper_enabled, threads_num, ...)                              \
	{                                                                                                              \
		sinsp_threadinfo* pid_tinfo = m_inspector.get_thread_ref(tg_pid, false, true).get();                   \
		ASSERT_TRUE(pid_tinfo);                                                                                \
		ASSERT_TRUE(pid_tinfo->m_tginfo.get());                                                                \
		ASSERT_EQ(pid_tinfo->m_tginfo->alive_count, alive_threads);                                            \
		ASSERT_EQ(pid_tinfo->m_tginfo->reaper, reaper_enabled);                                                \
		ASSERT_EQ(pid_tinfo->m_tginfo->pid, tg_pid);                                                           \
		ASSERT_EQ(pid_tinfo->m_tginfo->threads.size(), threads_num);                                           \
		std::set<int64_t> tid_to_assert{__VA_ARGS__};                                                          \
		for(const auto& tid : tid_to_assert)                                                                   \
		{                                                                                                      \
			sinsp_threadinfo* tid_tinfo = m_inspector.get_thread_ref(tid, false, true).get();              \
			ASSERT_TRUE(tid_tinfo);                                                                        \
			ASSERT_EQ(tid_tinfo->m_pid, tg_pid) << "Thread '" + std::to_string(tid_tinfo->m_tid) +         \
								       "' doesn't belong to the thread group id '" +   \
								       std::to_string(tg_pid) + "'";                   \
			bool found = false;                                                                            \
			for(const auto& thread : pid_tinfo->m_tginfo->threads)                                         \
			{                                                                                              \
				if(thread.lock().get() == tid_tinfo)                                                   \
				{                                                                                      \
					found = true;                                                                  \
				}                                                                                      \
			}                                                                                              \
			ASSERT_TRUE(found);                                                                            \
		}                                                                                                      \
		uint16_t not_expired_count = 0;                                                                        \
		for(const auto& thread : pid_tinfo->m_tginfo->threads)                                                 \
		{                                                                                                      \
			if(!thread.expired())                                                                          \
			{                                                                                              \
				not_expired_count++;                                                                   \
			}                                                                                              \
		}                                                                                                      \
		ASSERT_EQ(not_expired_count, alive_threads);                                                           \
	}

#define ASSERT_THREAD_CHILDREN(parent_tid, children_num, not_expired, ...)                                             \
	{                                                                                                              \
		sinsp_threadinfo* parent_tinfo = m_inspector.get_thread_ref(parent_tid, false, true).get();            \
		ASSERT_TRUE(parent_tinfo);                                                                             \
		ASSERT_EQ(parent_tinfo->m_children.size(), children_num);                                              \
		std::set<int64_t> tid_to_assert{__VA_ARGS__};                                                          \
		for(const auto& tid : tid_to_assert)                                                                   \
		{                                                                                                      \
			sinsp_threadinfo* tid_tinfo = m_inspector.get_thread_ref(tid, false, true).get();              \
			ASSERT_TRUE(tid_tinfo);                                                                        \
			bool found = false;                                                                            \
			for(const auto& child : parent_tinfo->m_children)                                              \
			{                                                                                              \
				if(child.lock().get() == tid_tinfo)                                                    \
				{                                                                                      \
					found = true;                                                                  \
				}                                                                                      \
			}                                                                                              \
			ASSERT_TRUE(found);                                                                            \
		}                                                                                                      \
		uint16_t not_expired_count = 0;                                                                        \
		for(const auto& child : parent_tinfo->m_children)                                                      \
		{                                                                                                      \
			if(!child.expired())                                                                           \
			{                                                                                              \
				not_expired_count++;                                                                   \
			}                                                                                              \
		}                                                                                                      \
		ASSERT_EQ(not_expired_count, not_expired);                                                             \
	}

/* if `missing==true` we shouldn't find the thread info */
#define ASSERT_MISSING_THREAD_INFO(tid_to_check, missing)                                                              \
	{                                                                                                              \
		if(missing)                                                                                            \
		{                                                                                                      \
			ASSERT_FALSE(m_inspector.get_thread_ref(tid_to_check, false));                                 \
		}                                                                                                      \
		else                                                                                                   \
		{                                                                                                      \
			ASSERT_TRUE(m_inspector.get_thread_ref(tid_to_check, false));                                  \
		}                                                                                                      \
	}

/* This is the default tree:
 *	- (init) tid 1 pid 1 ptid 0
 *  - (p_1 - t1) tid 2 pid 2 ptid 1
 *  - (p_1 - t2) tid 3 pid 2 ptid 1
 * 	 - (p_2 - t1) tid 25 pid 25 ptid 1 (CLONE_PARENT)
 * 	  - (p_3 - t1) tid 72 pid 72 ptid 25
 * 	   - (p_4 - t1) tid 76 pid 76 ptid 72 (container: vtid 1 vpid 1)
 * 	   - (p_4 - t2) tid 79 pid 76 ptid 72 (container: vtid 2 vpid 1)
 * 		- (p_5 - t1) tid 82 pid 82 ptid 79 (container: vtid 10 vpid 10)
 * 		- (p_5 - t2) tid 84 pid 82 ptid 79 (container: vtid 12 vpid 10)
 *  	 - (p_6 - t2) tid 87 pid 87 ptid 84 (container: vtid 17 vpid 17)
 * 	 - (p_2 - t2) tid 23 pid 25 ptid 1
 * 	 - (p_2 - t3) tid 24 pid 25 ptid 1
 */
#define DEFAULT_TREE                                                                                                   \
	add_default_init_thread();                                                                                     \
	open_inspector();                                                                                              \
                                                                                                                       \
	/* Init process creates a child process */                                                                     \
                                                                                                                       \
	/*=============================== p1_t1 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p1_t1_tid = 2;                                                                                  \
	UNUSED int64_t p1_t1_pid = p1_t1_tid;                                                                          \
	UNUSED int64_t p1_t1_ptid = INIT_TID;                                                                          \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);                                              \
                                                                                                                       \
	/*=============================== p1_t1 ===========================*/                                          \
                                                                                                                       \
	/* p1 process creates a second thread */                                                                       \
                                                                                                                       \
	/*=============================== p1_t2 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p1_t2_tid = 6;                                                                                  \
	UNUSED int64_t p1_t2_pid = p1_t1_pid;                                                                          \
	UNUSED int64_t p1_t2_ptid = INIT_TID;                                                                          \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);                      \
                                                                                                                       \
	/*=============================== p1_t2 ===========================*/                                          \
                                                                                                                       \
	/* The second thread of p1 create a new process p2 */                                                          \
                                                                                                                       \
	/*=============================== p2_t1 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p2_t1_tid = 25;                                                                                 \
	UNUSED int64_t p2_t1_pid = 25;                                                                                 \
	UNUSED int64_t p2_t1_ptid = INIT_TID;                                                                          \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p2_t1_tid, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_PARENT);                      \
                                                                                                                       \
	/*=============================== p2_t1 ===========================*/                                          \
                                                                                                                       \
	/* p2 process creates a second thread */                                                                       \
                                                                                                                       \
	/*=============================== p2_t2 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p2_t2_tid = 23;                                                                                 \
	UNUSED int64_t p2_t2_pid = p2_t1_pid;                                                                          \
	UNUSED int64_t p2_t2_ptid = INIT_TID; /* p2_t2 will have the same parent of p2_t1 */                           \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p2_t2_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid, PPM_CL_CLONE_THREAD);                      \
                                                                                                                       \
	/*=============================== p2_t2 ===========================*/                                          \
                                                                                                                       \
	/* p2_t2 creates a new thread p2_t3 */                                                                         \
                                                                                                                       \
	/*=============================== p2_t3 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p2_t3_tid = 24;                                                                                 \
	UNUSED int64_t p2_t3_pid = p2_t1_pid;                                                                          \
	UNUSED int64_t p2_t3_ptid = INIT_TID;                                                                          \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p2_t3_tid, p2_t2_tid, p2_t2_pid, p2_t2_ptid, PPM_CL_CLONE_THREAD);                      \
                                                                                                                       \
	/*=============================== p2_t3 ===========================*/                                          \
                                                                                                                       \
	/* The leader thread of p2 create a new process p3 */                                                          \
                                                                                                                       \
	/*=============================== p3_t1 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p3_t1_tid = 72;                                                                                 \
	UNUSED int64_t p3_t1_pid = p3_t1_tid;                                                                          \
	UNUSED int64_t p3_t1_ptid = p2_t1_tid;                                                                         \
                                                                                                                       \
	/* Parent exit event */                                                                                        \
	generate_clone_x_event(p3_t1_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid);                                           \
                                                                                                                       \
	/*=============================== p3_t1 ===========================*/                                          \
                                                                                                                       \
	/* The leader thread of p3 create a new process p4 in a new container */                                       \
                                                                                                                       \
	/*=============================== p4_t1 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p4_t1_tid = 76;                                                                                 \
	UNUSED int64_t p4_t1_pid = p4_t1_tid;                                                                          \
	UNUSED int64_t p4_t1_ptid = p3_t1_tid;                                                                         \
	UNUSED int64_t p4_t1_vtid = 1; /* This process will be the `init` one in the new namespace */                  \
	UNUSED int64_t p4_t1_vpid = p4_t1_vtid;                                                                        \
                                                                                                                       \
	generate_clone_x_event(p4_t1_tid, p3_t1_tid, p3_t1_pid, p3_t1_ptid,                                            \
			       PPM_CL_CHILD_IN_PIDNS | PPM_CL_CLONE_NEWPID);                                           \
                                                                                                                       \
	/* Check fields after parent parsing                                                                           \
	 * Note: here we cannot assert anything because the child will be in a container                               \
	 * and so the parent doesn't create the `thread-info` for the child.                                           \
	 */                                                                                                            \
                                                                                                                       \
	/* Child exit event */                                                                                         \
	/* On arm64 the flag `PPM_CL_CLONE_NEWPID` is not sent by the child, so we simulate the                        \
	 * worst case */                                                                                               \
	generate_clone_x_event(0, p4_t1_tid, p4_t1_pid, p4_t1_ptid, PPM_CL_CHILD_IN_PIDNS, p4_t1_vtid, p4_t1_vpid);    \
                                                                                                                       \
	/*=============================== p4_t1 ===========================*/                                          \
                                                                                                                       \
	/*=============================== p4_t2 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p4_t2_tid = 79;                                                                                 \
	UNUSED int64_t p4_t2_pid = p4_t1_pid;                                                                          \
	UNUSED int64_t p4_t2_ptid = p3_t1_tid;                                                                         \
	UNUSED int64_t p4_t2_vtid = 2;                                                                                 \
	UNUSED int64_t p4_t2_vpid = p4_t1_vpid;                                                                        \
                                                                                                                       \
	generate_clone_x_event(0, p4_t2_tid, p4_t2_pid, p4_t2_ptid, PPM_CL_CLONE_THREAD, p4_t2_vtid, p4_t2_vpid);      \
                                                                                                                       \
	/*=============================== p4_t2 ===========================*/                                          \
                                                                                                                       \
	/*=============================== p5_t1 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p5_t1_tid = 82;                                                                                 \
	UNUSED int64_t p5_t1_pid = p5_t1_tid;                                                                          \
	UNUSED int64_t p5_t1_ptid = p4_t2_tid;                                                                         \
	UNUSED int64_t p5_t1_vtid = 10;                                                                                \
	UNUSED int64_t p5_t1_vpid = p5_t1_vtid;                                                                        \
                                                                                                                       \
	generate_clone_x_event(0, p5_t1_tid, p5_t1_pid, p5_t1_ptid, DEFAULT_VALUE, p5_t1_vtid, p5_t1_vpid);            \
                                                                                                                       \
	/*=============================== p5_t1 ===========================*/                                          \
                                                                                                                       \
	/*=============================== p5_t2 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p5_t2_tid = 84;                                                                                 \
	UNUSED int64_t p5_t2_pid = p5_t1_pid;                                                                          \
	UNUSED int64_t p5_t2_ptid = p4_t2_tid;                                                                         \
	UNUSED int64_t p5_t2_vtid = 12;                                                                                \
	UNUSED int64_t p5_t2_vpid = p5_t1_vpid;                                                                        \
                                                                                                                       \
	generate_clone_x_event(0, p5_t2_tid, p5_t2_pid, p5_t2_ptid, PPM_CL_CLONE_THREAD, p5_t2_vtid, p5_t2_vpid);      \
                                                                                                                       \
	/*=============================== p5_t2 ===========================*/                                          \
                                                                                                                       \
	/*=============================== p6_t1 ===========================*/                                          \
                                                                                                                       \
	UNUSED int64_t p6_t1_tid = 87;                                                                                 \
	UNUSED int64_t p6_t1_pid = p6_t1_tid;                                                                          \
	UNUSED int64_t p6_t1_ptid = p5_t2_tid;                                                                         \
	UNUSED int64_t p6_t1_vtid = 17;                                                                                \
	UNUSED int64_t p6_t1_vpid = p6_t1_vtid;                                                                        \
                                                                                                                       \
	generate_clone_x_event(0, p6_t1_tid, p6_t1_pid, p6_t1_ptid, DEFAULT_VALUE, p6_t1_vtid, p6_t1_vpid);            \
                                                                                                                       \
	/*=============================== p6_t1 ===========================*/

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

	/* assert thread group info */
	ASSERT_TRUE(tinfo->m_tginfo);
	ASSERT_EQ(tinfo->m_tginfo->alive_count, 1);
	ASSERT_EQ(tinfo->m_tginfo->reaper, true);
	ASSERT_EQ(tinfo->m_tginfo->threads.front().lock().get(), tinfo);
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

	/* Since we are the father we should have a thread-info associated even if the clone failed
	 */
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

	/* The child process is in a container so the parent doesn't populate the thread_info for
	 * the child  */
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
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE,
			       "old_bash");

	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo->m_comm, "old_bash");

	/* Remove the `PPM_CL_CLONE_INVERTED` flag */
	p1_t1_tinfo->m_flags = p1_t1_tinfo->m_flags & ~PPM_CL_CLONE_INVERTED;

	/* Parent clone exit event */
	/* The parent considers the existing child entry stale and removes it. It populates a new
	 * thread info */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE,
			       "new_bash");

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
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE,
			       "old_bash");

	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false, true).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_EQ(p1_t1_tinfo->m_comm, "old_bash");

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE,
			       "new_bash");

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
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, p1_t1_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

	/* The process p1 creates a second process p2 */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = p1_t1_tid;

	/* Parent clone exit event */
	generate_clone_x_event(p2_t1_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, p2_t1_tid)
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 1, 1, p2_t1_tid)

	/* Init should always have just one child */
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

	/* Now the schema is:
	 * - init
	 *  - p1_t1
	 *   - p2_t2
	 *
	 * if we remove p1_t1, we should see:
	 * - thread group info is deleted from the thread_manager.
	 * - ptid of `p2_t1` is updated to `INIT_TID`
	 * - init has 2 children but the only one not expired is `p2_t1`
	 * - there is no more a thread info for `p1_t1`
	 */
	remove_thread(p1_t1_tid);

	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(p1_t1_pid));
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, INIT_TID)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 1, p2_t1_tid)
	ASSERT_MISSING_THREAD_INFO(p1_t1_tid, true)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_clone_parent_flag)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

	/* The process p1 creates a second process p2 with the `CLONE_PARENT` flag */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	/* with the `CLONE_PARENT` flag the parent is the parent of the calling process */
	int64_t p2_t1_ptid = INIT_TID;

	/* Parent clone exit event */
	generate_clone_x_event(p2_t1_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_PARENT);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, p2_t1_tid)

	/* Assert that init has 2 children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p2_t1_tid)

	/* Now the schema is:
	 * - init
	 *  - p1_t1
	 *   - p2_t1 (where the parent is init)
	 *
	 * if we remove p2_t1, we should see:
	 * - thread group info is deleted from the thread_manager.
	 * - init has 2 children but the only one not expired is `p1_t1`
	 * - there is no more thread info for `p2_t1`
	 */
	remove_thread(p2_t1_tid);

	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(p2_t1_pid));
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 1, p1_t1_tid)
	ASSERT_MISSING_THREAD_INFO(p2_t1_tid, true)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_clone_remove_main_thread_first)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

	/* The process p1 creates a second thread p1_t2 */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	/* with the `CLONE_THREAD` flag the parent is the parent of the calling process */
	int64_t p1_t2_ptid = INIT_TID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, p1_t1_tid, p1_t2_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid)

	/* Now the schema is:
	 * - init
	 *  - p1_t1
	 *  - p1_t2
	 *
	 * if we remove p1_t1, we should see:
	 * - thread group info is not deleted from the thread_manager and the alive count is 1
	 * - init has 2 children
	 * - there is still thread info for `p1_t1`
	 */
	remove_thread(p1_t1_tid);

	auto tginfo = m_inspector.m_thread_manager->get_thread_group_info(p1_t1_tid).get();
	ASSERT_TRUE(tginfo);
	ASSERT_EQ(tginfo->alive_count, 1);
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid)

	/* We should have the thread info but the thread should be marked as CLOSED */
	auto p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_TRUE(p1_t1_tinfo->m_flags & PPM_CL_CLOSED);
	/* We double-check the thread group info with the one in the thread table */
	ASSERT_TRUE(p1_t1_tinfo->m_tginfo);
	ASSERT_EQ(p1_t1_tinfo->m_tginfo->alive_count, 1);

	/* Now we remove also p1_t2, we should see
	 * - thread group info is deleted from the thread_manager
	 * - init has 2 children, but both are expired
	 * - there are no more thread info for `p1_t1` and `p1_t2`
	 */
	remove_thread(p1_t2_tid);

	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(p1_t1_tid));
	ASSERT_MISSING_THREAD_INFO(p1_t1_tid, true)
	ASSERT_MISSING_THREAD_INFO(p1_t2_tid, true)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 0)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_parent_clone_remove_second_thread_first)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

	/* The process p1 creates a second thread p1_t2 */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	/* with the `CLONE_THREAD` flag the parent is the parent of the calling process */
	int64_t p1_t2_ptid = INIT_TID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, p1_t1_tid, p1_t2_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid)

	/* Now the schema is:
	 * - init
	 *  - p1_t1
	 *  - p1_t2
	 *
	 * if we remove p1_t2, we should see:
	 * - thread group info is not deleted from the thread_manager and the alive count is 1
	 * - init has 1 child
	 */
	remove_thread(p1_t2_tid);

	auto tginfo = m_inspector.m_thread_manager->get_thread_group_info(p1_t2_pid).get();
	ASSERT_TRUE(tginfo);
	ASSERT_EQ(tginfo->alive_count, 1);
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 1, p1_t1_tid)
	ASSERT_MISSING_THREAD_INFO(p1_t2_tid, true)

	/* Check if the main thread is still there */
	auto p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_TRUE(p1_t1_tinfo->m_tginfo);
	ASSERT_EQ(p1_t1_tinfo->m_tginfo->alive_count, 1);

	/* Now we remove also p1_t1, we should see
	 * - thread group info is deleted from the thread_manager
	 * - init has 2 children, but both are expired
	 * - there are no more thread info for `p1_t1` and `p1_t2`
	 */
	remove_thread(p1_t1_tid);

	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(p1_t1_tid));
	ASSERT_MISSING_THREAD_INFO(p1_t1_tid, true)
	ASSERT_MISSING_THREAD_INFO(p1_t2_tid, true)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 0)
}

/*=============================== CLONE PARENT EXIT EVENT ===========================*/

/*=============================== DEFAULT TREE ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_check_default_tree)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* Check Thread info */
	ASSERT_THREAD_INFO_PIDS(INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p2_t2_tid, p2_t2_pid, p2_t2_ptid);
	ASSERT_THREAD_INFO_PIDS(p2_t3_tid, p2_t3_pid, p2_t3_ptid);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_ptid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, p4_t1_ptid, p4_t1_vtid, p4_t1_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t2_tid, p4_t2_pid, p4_t2_ptid, p4_t2_vtid, p4_t2_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p5_t1_tid, p5_t1_pid, p5_t1_ptid, p5_t1_vtid, p5_t1_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p5_t2_tid, p5_t2_pid, p5_t2_ptid, p5_t2_vtid, p5_t2_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p6_t1_tid, p6_t1_pid, p6_t1_ptid, p6_t1_vtid, p6_t1_vpid);

	/* Check Thread group info */
	ASSERT_THREAD_GROUP_INFO(INIT_PID, 1, true, 1, INIT_TID);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, false, 3, p2_t1_tid, p2_t2_tid, p2_t3_tid);
	ASSERT_THREAD_GROUP_INFO(p3_t1_pid, 1, false, 1, p3_t1_tid);
	ASSERT_THREAD_GROUP_INFO(p4_t2_pid, 2, true, 2, p4_t1_tid, p4_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 2, false, 2, p5_t1_tid, p5_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p6_t1_pid, 1, false, 1, p6_t1_tid);

	/* Check children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5, p1_t1_tid, p1_t2_tid, p2_t1_tid, p2_t2_tid, p2_t3_tid);
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 1, 1, p3_t1_tid);
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);
	ASSERT_THREAD_CHILDREN(p4_t2_tid, 2, 2, p5_t1_tid, p5_t2_tid);
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_traverse_default_tree)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	std::vector<int64_t> traverse_parents;
	sinsp_threadinfo::visitor_func_t visitor = [&traverse_parents](sinsp_threadinfo* pt)
	{
		/* we stop when we reach the init parent */
		traverse_parents.push_back(pt->m_tid);
		if(pt->m_tid == INIT_TID)
		{
			return false;
		}
		return true;
	};

	/*=============================== p4_t1 traverse ===========================*/

	sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(p4_t1_tid, false, true).get();

	std::vector<int64_t> expected_p4_traverse_parents = {p4_t1_ptid, p3_t1_ptid, p2_t1_ptid};

	tinfo->traverse_parent_state(visitor);
	ASSERT_EQ(traverse_parents, expected_p4_traverse_parents);

	/*=============================== p4_t1 traverse ===========================*/

	/*=============================== p5_t2 traverse ===========================*/

	tinfo = m_inspector.get_thread_ref(p5_t2_tid, false).get();

	std::vector<int64_t> expected_p5_traverse_parents = {p5_t2_ptid, p4_t2_ptid, p3_t1_ptid, p2_t1_ptid};

	traverse_parents.clear();
	tinfo->traverse_parent_state(visitor);
	ASSERT_EQ(traverse_parents, expected_p5_traverse_parents);

	/*=============================== p5_t2 traverse ===========================*/

	/*=============================== remove threads ===========================*/

	/* Remove p4_t2 */
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 0, 0)
	remove_thread(p4_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p4_t1_pid, 1, true, 2, p4_t1_tid)
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 2, 2, p5_t1_tid, p5_t2_tid)

	/* Remove p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 0, 0)
	remove_thread(p5_t2_tid);
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid)

	/* Remove p5_t1 */
	remove_thread(p5_t1_tid);

	/* Now p6_t1 should be assigned to p4_t1 since it is the reaper */
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 3, 1, p6_t1_tid)

	/* Set p2_t1 group as reaper, emulate prctl */
	auto tginfo = m_inspector.m_thread_manager->get_thread_group_info(p2_t1_pid).get();
	tginfo->reaper = true;

	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, true, 3, p2_t1_tid, p2_t2_tid, p2_t3_tid)

	/* Remove p2_t1 */
	ASSERT_THREAD_CHILDREN(p2_t2_tid, 0, 0)
	remove_thread(p2_t1_tid);
	ASSERT_THREAD_CHILDREN(p2_t2_tid, 1, 1, p3_t1_tid)

	/* Remove p2_t2 */
	ASSERT_THREAD_CHILDREN(p2_t3_tid, 0, 0)
	remove_thread(p2_t2_tid);
	/* Please note that the parent of `p2_t2` is `init` since it was created with
	 * CLONE_PARENT flag.
	 */
	ASSERT_THREAD_CHILDREN(p2_t3_tid, 1, 1, p3_t1_tid)

	/* Remove p3_t1 */
	remove_thread(p3_t1_tid);
	ASSERT_THREAD_CHILDREN(p2_t3_tid, 2, 1, p4_t1_tid)

	/*=============================== remove threads ===========================*/

	/*=============================== p6_t1 traverse ===========================*/

	tinfo = m_inspector.get_thread_ref(p6_t1_tid, false).get();

	std::vector<int64_t> expected_p6_traverse_parents = {p4_t1_tid, p2_t3_tid, INIT_TID};

	traverse_parents.clear();
	tinfo->traverse_parent_state(visitor);
	ASSERT_EQ(traverse_parents, expected_p6_traverse_parents);

	/*=============================== p6_t1 traverse ===========================*/
}

/*=============================== DEFAULT TREE ===========================*/

/*=============================== CLONE CHILD EXIT EVENT ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_in_container)
{
	add_default_init_thread();
	open_inspector();

	/* We simulate a child clone exit event that wants to generate a child into a container */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;
	int64_t p1_t1_vtid = 80;
	int64_t p1_t1_vpid = 80;

	/* Child clone exit event */
	/* if we use `sched_proc_fork` tracepoint `PPM_CL_CLONE_NEWPID` won't be sent so we don't
	 * use it here, we use just `PPM_CL_CHILD_IN_PIDNS` */
	generate_clone_x_event(0, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CHILD_IN_PIDNS, p1_t1_vtid, p1_t1_vpid);

	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p1_t1_tid, p1_t1_pid, p1_t1_ptid, p1_t1_vtid, p1_t1_vpid)
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, p1_t1_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_clone_exit_child_already_there)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	/* Parent clone exit event */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);

	/* Now we try to create a child with a different pid but same tid with a clone exit child
	 * event */
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

	/* Now we try to create a child with a different pid but same tid with a clone exit child
	 * event */
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
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, p1_t1_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

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
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, p2_t1_tid)
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 1, 1, p2_t1_tid)

	/* Check if the thread-info in the thread table is correctly assigned to our event */
	sinsp_threadinfo* p2_t1_tinfo = m_inspector.get_thread_ref(p2_t1_tid, false, true).get();
	ASSERT_TRUE(evt && evt->get_thread_info());
	ASSERT_TRUE(p2_t1_tinfo);
	ASSERT_EQ(p2_t1_tinfo, evt->get_thread_info());

	/* Now the schema is:
	 * - init
	 *  - p1_t1
	 *   - p2_t2
	 *
	 * if we remove p1_t1, we should see:
	 * - thread group info is deleted from the thread_manager.
	 * - ptid of `p2_t1` is updated to `INIT_TID`
	 * - init has 2 children but the only one not expired is `p1_t1`
	 * - there is no more a thread info for `p1_t1`
	 */
	remove_thread(p1_t1_tid);

	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(p1_t1_pid));
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, INIT_TID)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 1, p2_t1_tid)
	ASSERT_MISSING_THREAD_INFO(p1_t1_tid, true)
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
	int64_t p2_t1_ptid = INIT_PID; /* with the `CLONE_PARENT` flag the parent is the parent of
					  the calling process */

	/* Child clone exit event */
	/* Please note that in the clone child exit event, it could happen that
	 * we don't have the `PPM_CL_CLONE_PARENT` flag because the event could
	 * be generated by the `sched_proc_fork` tracepoint. BTW the child parser
	 * shouldn't need this flag to detect the real parent, so we omit it here
	 * and see what happens.
	 */
	generate_clone_x_event(0, p2_t1_tid, p2_t1_pid, p2_t1_ptid); // PPM_CL_CLONE_PARENT
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)

	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p2_t1_tid)

	/* Now the schema is:
	 * - init
	 *  - p1_t1
	 *   - p2_t2 (where the parent is init)
	 *
	 * if we remove p2_t2, we should see:
	 * - thread group info is deleted from the thread_manager.
	 * - init has 2 children but the only one not expired is `p1_t1`
	 * - there is no more a thread info for `p2_t1`
	 */
	remove_thread(p2_t1_tid);

	ASSERT_FALSE(m_inspector.m_thread_manager->get_thread_group_info(p2_t1_pid));
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 1, p1_t1_tid)
	ASSERT_MISSING_THREAD_INFO(p2_t1_tid, true)
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
	int64_t p1_t2_ptid = INIT_PID; /* with the `CLONE_THREAD` flag the parent is the parent of
					  the calling process */

	// /* Child clone exit event */
	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)

	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, p1_t1_tid, p1_t2_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid)
}

/*=============================== CLONE CHILD EXIT EVENT ===========================*/

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

/*=============================== REMOVE THREAD LOGIC ===========================*/

/*=============================== BROKEN CASES ===========================*/

TEST_F(sinsp_with_test_input, BROKEN_fdtable_with_threads)
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

	/* Init has just 1 fd so the new process should have the same fd. */
	sinsp_threadinfo* p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	ASSERT_EQ(p1_t1_tinfo->m_fdtable.m_table.size(), 1);

	/* process p1 creates a new thread (p1_t2_tid) */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_THREAD | PPM_CL_CLONE_FILES);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)

	sinsp_threadinfo* p1_t2_tinfo = m_inspector.get_thread_ref(p1_t2_tid, false).get();
	ASSERT_EQ(p1_t2_tinfo->m_flags & PPM_CL_CLONE_FILES, 1);
	ASSERT_EQ(p1_t2_tinfo->get_fd_table()->m_table.size(), 1);

	/* process p1 creates a new thread (p1_t2_tid) */
	int64_t p1_t3_tid = 37;
	int64_t p1_t3_pid = 24;
	int64_t p1_t3_ptid = INIT_PID;

	/* Child clone exit event */
	generate_clone_x_event(0, p1_t3_tid, p1_t3_pid, p1_t3_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t3_tid, p1_t3_pid, p1_t3_ptid)

	/* This is wrong, the thread doesn't have the CLONE_FILES flag but we don't copy the file_descriptor of the main
	 * thread */
	sinsp_threadinfo* p1_t3_tinfo = m_inspector.get_thread_ref(p1_t3_tid, false).get();
	ASSERT_EQ(p1_t3_tinfo->m_flags & PPM_CL_CLONE_FILES, 0);
	ASSERT_EQ(p1_t3_tinfo->get_fd_table()->m_table.size(), 0);

	GTEST_SKIP()
		<< "Threads don't acquire the fdtable of the parent even if `PPM_CL_CLONE_FILES` is not specified!";
}

TEST_F(sinsp_with_test_input, BROKEN_remove_thread_after_execve)
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
	GTEST_SKIP() << "The expected behavior is correct but we need to remove all threads! Moreover, "
			"if the main thread performs the execve does someone remove all other threads?";
}

TEST_F(sinsp_with_test_input, BROKEN_missing_both_clone_events_create_leader_thread)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)

	/* The process p1 creates a second process p2 but we miss both clone events so we know nothing about it */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = p1_t1_tid;

	/* The process p2 creates a new process p3 */
	int64_t p3_t1_tid = 50;
	int64_t p3_t1_pid = 50;
	int64_t p3_t1_ptid = p2_t1_tid;

	generate_clone_x_event(p3_t1_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_ptid)

	/* Process p2 is generated as invalid so we have no thread info */
	auto tginfo = m_inspector.m_thread_manager->get_thread_group_info(p2_t1_tid).get();
	ASSERT_FALSE(tginfo);

	/* Moreover if we check p2_t1 parent, it is INIT and this is not what we want! */
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p2_t1_tid)
	GTEST_SKIP() << "The expected behavior is correct but we need create a correct tree also in this case!";
}

/*=============================== BROKEN CASES ===========================*/
