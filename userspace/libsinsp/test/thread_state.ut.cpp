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

#define ASSERT_THREAD_GROUP_INFO(tg_pid, alive_threads, reaper_enabled, threads_num, not_expired, ...)                 \
	{                                                                                                              \
		auto tginfo = m_inspector.m_thread_manager->get_thread_group_info(tg_pid).get();                       \
		ASSERT_TRUE(tginfo);                                                                                   \
		ASSERT_EQ(tginfo->get_thread_count(), alive_threads);                                                  \
		ASSERT_EQ(tginfo->is_reaper(), reaper_enabled);                                                        \
		ASSERT_EQ(tginfo->get_tgroup_pid(), tg_pid);                                                           \
		ASSERT_EQ(tginfo->get_thread_list().size(), threads_num);                                              \
		std::set<int64_t> tid_to_assert{__VA_ARGS__};                                                          \
		for(const auto& tid : tid_to_assert)                                                                   \
		{                                                                                                      \
			sinsp_threadinfo* tid_tinfo = m_inspector.get_thread_ref(tid, false, true).get();              \
			ASSERT_TRUE(tid_tinfo);                                                                        \
			ASSERT_EQ(tid_tinfo->m_pid, tg_pid) << "Thread '" + std::to_string(tid_tinfo->m_tid) +         \
								       "' doesn't belong to the thread group id '" +   \
								       std::to_string(tg_pid) + "'";                   \
			bool found = false;                                                                            \
			for(const auto& thread : tginfo->get_thread_list())                                            \
			{                                                                                              \
				if(thread.lock().get() == tid_tinfo)                                                   \
				{                                                                                      \
					found = true;                                                                  \
				}                                                                                      \
			}                                                                                              \
			ASSERT_TRUE(found);                                                                            \
		}                                                                                                      \
		uint16_t not_expired_count = 0;                                                                        \
		for(const auto& thread : tginfo->get_thread_list())                                                    \
		{                                                                                                      \
			if(!thread.expired())                                                                          \
			{                                                                                              \
				not_expired_count++;                                                                   \
			}                                                                                              \
		}                                                                                                      \
		ASSERT_EQ(not_expired_count, not_expired);                                                             \
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

#define ASSERT_THREAD_INFO_FLAG(tid, flag, present)                                                                    \
	{                                                                                                              \
		sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(tid, false, true).get();                          \
		ASSERT_TRUE(tinfo);                                                                                    \
		if(present)                                                                                            \
		{                                                                                                      \
			ASSERT_TRUE(tinfo->m_flags& flag);                                                             \
		}                                                                                                      \
		else                                                                                                   \
		{                                                                                                      \
			ASSERT_FALSE(tinfo->m_flags& flag);                                                            \
		}                                                                                                      \
	}

#define ASSERT_THREAD_INFO_COMM(tid, comm)                                                                             \
	{                                                                                                              \
		sinsp_threadinfo* tinfo = m_inspector.get_thread_ref(tid, false).get();                                \
		ASSERT_TRUE(tinfo);                                                                                    \
		ASSERT_EQ(tinfo->m_comm, comm);                                                                        \
	}

#define DEFAULT_TREE_NUM_PROCS 12

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
 *  	 - (p_6 - t1) tid 87 pid 87 ptid 84 (container: vtid 17 vpid 17)
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
	generate_clone_x_event(p4_t1_tid, p3_t1_tid, p3_t1_pid, p3_t1_ptid, PPM_CL_CLONE_NEWPID);                      \
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
	generate_clone_x_event(0, p4_t2_tid, p4_t2_pid, p4_t2_ptid, PPM_CL_CLONE_THREAD | PPM_CL_CHILD_IN_PIDNS,       \
			       p4_t2_vtid, p4_t2_vpid);                                                                \
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
	generate_clone_x_event(0, p5_t1_tid, p5_t1_pid, p5_t1_ptid, PPM_CL_CHILD_IN_PIDNS, p5_t1_vtid, p5_t1_vpid);    \
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
	generate_clone_x_event(0, p5_t2_tid, p5_t2_pid, p5_t2_ptid, PPM_CL_CHILD_IN_PIDNS, p5_t2_vtid, p5_t2_vpid);    \
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
	generate_clone_x_event(0, p6_t1_tid, p6_t1_pid, p6_t1_ptid, PPM_CL_CHILD_IN_PIDNS, p6_t1_vtid, p6_t1_vpid);    \
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
	ASSERT_EQ(tinfo->m_tginfo->get_thread_count(), 1);
	ASSERT_EQ(tinfo->m_tginfo->is_reaper(), true);
	ASSERT_EQ(tinfo->m_tginfo->get_thread_list().front().lock().get(), tinfo);
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

	/* Flag `PPM_CL_CHILD_IN_PIDNS` is not set in this case! */
	generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID, PPM_CL_CLONE_NEWPID);

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
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, 1, p1_t1_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

	/* The process p1 creates a second process p2 */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = p1_t1_tid;

	/* Parent clone exit event */
	generate_clone_x_event(p2_t1_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid)
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, 1, p2_t1_tid)
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
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, 1, p2_t1_tid)

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
	auto evt = generate_clone_x_event(p1_t1_tid, INIT_TID, INIT_PID, INIT_PTID);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid)

	/* `proc.nchilds` doesn't take into consideration the main thread */
	ASSERT_EQ(get_field_as_string(evt, "proc.nthreads"), "1");
	ASSERT_EQ(get_field_as_string(evt, "proc.nchilds"), "0");

	/* The process p1 creates a second thread p1_t2 */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	/* with the `CLONE_THREAD` flag the parent is the parent of the calling process */
	int64_t p1_t2_ptid = INIT_TID;

	/* Parent clone exit event */
	evt = generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid)

	/* the child thread should always have these 2 flags */
	ASSERT_THREAD_INFO_FLAG(p1_t2_tid, PPM_CL_CLONE_THREAD, true);
	ASSERT_THREAD_INFO_FLAG(p1_t2_tid, PPM_CL_CLONE_FILES, true);

	/* in this case the parent shouldn't have them */
	ASSERT_THREAD_INFO_FLAG(p1_t1_tid, PPM_CL_CLONE_THREAD, false);
	ASSERT_THREAD_INFO_FLAG(p1_t1_tid, PPM_CL_CLONE_FILES, false);

	/* assert some filterchecks */
	ASSERT_EQ(get_field_as_string(evt, "proc.nthreads"), "2");
	ASSERT_EQ(get_field_as_string(evt, "proc.nchilds"), "1");

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

	/* We generate just a mock event to assert filterchecks */
	evt = add_event_advance_ts(increasing_ts(), p1_t2_tid, PPME_SYSCALL_GETCWD_E, 0);
	ASSERT_EQ(get_field_as_string(evt, "proc.nthreads"), "1");
	ASSERT_EQ(get_field_as_string(evt, "proc.nchilds"), "1");

	auto tginfo = m_inspector.m_thread_manager->get_thread_group_info(p1_t1_tid).get();
	ASSERT_TRUE(tginfo);
	ASSERT_EQ(tginfo->get_thread_count(), 1);
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid)

	/* We should have the thread info but the thread should be marked as CLOSED */
	auto p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_TRUE(p1_t1_tinfo->is_dead());
	/* We double-check the thread group info with the one in the thread table */
	ASSERT_TRUE(p1_t1_tinfo->m_tginfo);
	ASSERT_EQ(p1_t1_tinfo->m_tginfo->get_thread_count(), 1);

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
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid)
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
	ASSERT_EQ(tginfo->get_thread_count(), 1);
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 1, p1_t1_tid)
	ASSERT_MISSING_THREAD_INFO(p1_t2_tid, true)

	/* Check if the main thread is still there */
	auto p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	ASSERT_TRUE(p1_t1_tinfo);
	ASSERT_TRUE(p1_t1_tinfo->m_tginfo);
	ASSERT_EQ(p1_t1_tinfo->m_tginfo->get_thread_count(), 1);

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
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, 1, p1_t1_tid)
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
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, 1, p1_t1_tid)
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
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, 1, p2_t1_tid)
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

	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid)
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid)
}

/*=============================== CLONE CHILD EXIT EVENT ===========================*/

/*=============================== ADD THREAD FROM PROC ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_create_thread_dependencies_after_proc_scan)
{
	/* - init
	 *  - p1_t1
	 *   - p2_t1
	 *  - p1_t2
	 *  - p1_t3 (invalid)
	 *   - p3_t1
	 * - init_t2
	 * - init_t3
	 */

	add_default_init_thread();

	/* p1_t1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_PID;

	/* p2_t1 */
	int64_t p2_t1_tid = 30;
	int64_t p2_t1_pid = 30;
	int64_t p2_t1_ptid = 24;

	/* p1_t2 */
	int64_t p1_t2_tid = 25;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_PID;

	/* p1_t3, this is invalid */
	int64_t p1_t3_tid = 26;
	int64_t p1_t3_pid = -1;
	int64_t p1_t3_ptid = -1;

	/* p3_t1, this is a child of the invalid one */
	int64_t p3_t1_tid = 40;
	int64_t p3_t1_pid = 40;
	int64_t p3_t1_ptid = 26; /* this parent doesn't exist we will reparent it to init */

	/* init_t2, this is a thread of init */
	int64_t init_t2_tid = 2;
	int64_t init_t2_pid = INIT_PID;
	int64_t init_t2_ptid = INIT_PTID;

	/* init_t3, this is a thread of init */
	int64_t init_t3_tid = 3;
	int64_t init_t3_pid = INIT_PID;
	int64_t init_t3_ptid = INIT_PTID;

	/* Populate thread table */
	add_simple_thread(p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	add_simple_thread(p3_t1_tid, p3_t1_pid, p3_t1_ptid);
	add_simple_thread(p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	add_simple_thread(p1_t2_tid, p1_t2_pid, p1_t2_ptid);
	add_simple_thread(p1_t3_tid, p1_t3_pid, p1_t3_ptid);
	add_simple_thread(init_t2_tid, init_t2_pid, init_t2_ptid);
	add_simple_thread(init_t3_tid, init_t3_pid, init_t3_ptid);

	/* Here we fill the thread table */
	open_inspector();
	ASSERT_EQ(8, m_inspector.m_thread_manager->get_thread_count());

	/* Children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 3, 3, p1_t1_tid, p1_t2_tid, p3_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 1, 1, p2_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t3_tid, 0, 0);

	/* Thread group */
	ASSERT_THREAD_GROUP_INFO(INIT_PID, 3, true, 3, 3, INIT_TID, init_t2_tid, init_t3_tid);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, 1, p2_t1_tid)
	ASSERT_THREAD_GROUP_INFO(p3_t1_pid, 1, false, 1, 1, p3_t1_tid)

	auto p1_t3_tinfo = m_inspector.get_thread_ref(p1_t3_tid, false).get();
	ASSERT_TRUE(p1_t3_tinfo);
	ASSERT_FALSE(p1_t3_tinfo->m_tginfo);
	ASSERT_EQ(p1_t3_tinfo->m_ptid, -1);

	/* These shouldn't be init children their parent should be `0` */
	ASSERT_THREAD_INFO_PIDS(init_t2_tid, init_t2_pid, init_t2_ptid);
	ASSERT_THREAD_INFO_PIDS(init_t3_tid, init_t3_pid, init_t3_ptid);
}

/*=============================== ADD THREAD FROM PROC ===========================*/

/*=============================== REMOVE THREAD LOGIC ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_remove_non_existing_thread)
{
	add_default_init_thread();
	open_inspector();

	int64_t unknown_tid = 24;

	/* we should do nothing, here we are only checking that nothing will crash */
	m_inspector.remove_thread(unknown_tid);
	m_inspector.remove_thread(unknown_tid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_remove_inactive_threads_1)
{
	DEFAULT_TREE

	set_threadinfo_last_access_time(INIT_TID, 70);
	set_threadinfo_last_access_time(p1_t1_tid, 70);
	set_threadinfo_last_access_time(p1_t2_tid, 70);
	set_threadinfo_last_access_time(p2_t1_tid, 70);
	set_threadinfo_last_access_time(p3_t1_tid, 70);
	set_threadinfo_last_access_time(p4_t1_tid, 70);
	set_threadinfo_last_access_time(p4_t2_tid, 70);
	set_threadinfo_last_access_time(p5_t1_tid, 70);
	set_threadinfo_last_access_time(p5_t2_tid, 70);
	set_threadinfo_last_access_time(p6_t1_tid, 70);
	set_threadinfo_last_access_time(p2_t2_tid, 70);
	set_threadinfo_last_access_time(p2_t3_tid, 70);

	/* This should remove no one */
	remove_inactive_threads(80, 20);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS, m_inspector.m_thread_manager->get_thread_count());

	/* mark p2_t1 and p2_t3 to remove */
	set_threadinfo_last_access_time(p2_t1_tid, 20);
	set_threadinfo_last_access_time(p2_t3_tid, 20);

	/* p2_t1 shouldn't be removed from the table since it is a leader thread and we still have some threads in that
	 * group while p2_t3 should be removed.
	 */
	remove_inactive_threads(80, 20);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, m_inspector.m_thread_manager->get_thread_count());
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 3, 2, p2_t1_tid, p2_t2_tid);

	/* Calling PRCTL on an unknown thread should generate an invalid thread */
	int64_t unknown_tid = 61103;
	add_event_advance_ts(increasing_ts(), unknown_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)0);

	auto unknown_tinfo = m_inspector.get_thread_ref(unknown_tid, false).get();
	ASSERT_TRUE(unknown_tinfo);
	ASSERT_FALSE(unknown_tinfo->m_tginfo);
	ASSERT_EQ(unknown_tinfo->m_ptid, -1);

	/* We want to be sure that this is removed because it is inactive */
	set_threadinfo_last_access_time(unknown_tid, 70);

	/* This call should remove only invalid threads */
	remove_inactive_threads(80, 20);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, m_inspector.m_thread_manager->get_thread_count());

	/* successive remove call on `p2_t1` do nothing */
	m_inspector.remove_thread(p2_t1_tid);
	m_inspector.remove_thread(p2_t1_tid);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, m_inspector.m_thread_manager->get_thread_count());
}

TEST_F(sinsp_with_test_input, THRD_STATE_remove_inactive_threads_2)
{
	DEFAULT_TREE

	set_threadinfo_last_access_time(INIT_TID, 70);
	set_threadinfo_last_access_time(p1_t1_tid, 70);
	set_threadinfo_last_access_time(p1_t2_tid, 70);
	set_threadinfo_last_access_time(p2_t1_tid, 70);
	set_threadinfo_last_access_time(p3_t1_tid, 70);
	set_threadinfo_last_access_time(p4_t1_tid, 70);
	set_threadinfo_last_access_time(p4_t2_tid, 70);
	set_threadinfo_last_access_time(p5_t1_tid, 70);
	set_threadinfo_last_access_time(p5_t2_tid, 70);
	set_threadinfo_last_access_time(p6_t1_tid, 70);
	set_threadinfo_last_access_time(p2_t2_tid, 70);
	set_threadinfo_last_access_time(p2_t3_tid, 70);

	/* we remove p5_t2, so p4_t2 will have just one not expired child */
	remove_thread(p5_t2_tid);
	ASSERT_THREAD_CHILDREN(p4_t2_tid, 2, 1, p5_t1_tid);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, m_inspector.m_thread_manager->get_thread_count());

	/* set the expired children threshold to 3 */
	sinsp_threadinfo::set_expired_children_threshold(3);
	ASSERT_EQ(sinsp_threadinfo::get_expired_children_threshold(), 3);

	/* p4_t2 has a number of children lower than the threshold so
	 * `remove_inactive_threads` do nothing.
	 */
	remove_inactive_threads(80, 20);
	ASSERT_THREAD_CHILDREN(p4_t2_tid, 2, 1, p5_t1_tid);

	/* set the expired children threshold to 1 */
	sinsp_threadinfo::set_expired_children_threshold(1);
	ASSERT_EQ(sinsp_threadinfo::get_expired_children_threshold(), 1);

	/* This should remove no one, but thanks to `clean_expired_children`
	 * logic it should clean the expired children of p4_t2_tid
	 */
	remove_inactive_threads(80, 20);
	ASSERT_THREAD_CHILDREN(p4_t2_tid, 1, 1, p5_t1_tid);

	/* restore the threshold */
	sinsp_threadinfo::set_expired_children_threshold(DEFAULT_CHILDREN_THRESHOLD);
	ASSERT_EQ(sinsp_threadinfo::get_expired_children_threshold(), DEFAULT_CHILDREN_THRESHOLD);
}

/*=============================== REMOVE THREAD LOGIC ===========================*/

/*=============================== TRAVERSE PARENT ===========================*/

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
	ASSERT_THREAD_GROUP_INFO(INIT_PID, 1, true, 1, 1, INIT_TID);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, false, 3, 3, p2_t1_tid, p2_t2_tid, p2_t3_tid);
	ASSERT_THREAD_GROUP_INFO(p3_t1_pid, 1, false, 1, 1, p3_t1_tid);
	ASSERT_THREAD_GROUP_INFO(p4_t2_pid, 2, true, 2, 2, p4_t1_tid, p4_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 2, false, 2, 2, p5_t1_tid, p5_t2_tid);
	ASSERT_THREAD_GROUP_INFO(p6_t1_pid, 1, false, 1, 1, p6_t1_tid);

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
	ASSERT_THREAD_GROUP_INFO(p4_t1_pid, 1, true, 2, 1, p4_t1_tid)
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 2, 2, p5_t1_tid, p5_t2_tid)
}

TEST_F(sinsp_with_test_input, THRD_STATE_check_dead_thread_is_not_a_reaper)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* Remove p5_t1, it is the main thread and it is only marked as dead */
	remove_thread(p5_t1_tid);
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2, p5_t2_tid)

	/* Remove p5_t2
	 * p5_t1 is marked as dead so it shouldn't be considered as a reaper.
	 */
	remove_thread(p5_t2_tid);
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 1, 1, p6_t1_tid)
}

/*===============================  TRAVERSE PARENT ===========================*/

/*=============================== FDTABLE ===========================*/

// TEST_F(sinsp_with_test_input, THRD_STATE_fdtable_with_threads)
// {
// 	DEFAULT_TREE

// 	/* This is the main thread */
// 	sinsp_threadinfo* p2_t1_tinfo = m_inspector.get_thread_ref(p2_t1_tid, false).get();
// 	ASSERT_EQ(p2_t1_tinfo->get_fd_table()->m_table.size(), 1);
// 	ASSERT_THREAD_INFO_FLAG(p2_t1_tid, PPM_CL_CLONE_FILES, false);

// 	/* Parent info */
// 	uint64_t main_table_size = p2_t1_tinfo->get_fd_table()->m_table.size();
// 	p2_t1_tinfo->m_cwd = "/test";
// 	p2_t1_tinfo->m_env = {"test", "env", "var"};

// 	auto main_cwd = p2_t1_tinfo->m_cwd;
// 	auto main_env = p2_t1_tinfo->m_env;

// 	sinsp_threadinfo* p2_t2_tinfo = m_inspector.get_thread_ref(p2_t2_tid, false).get();
// 	ASSERT_EQ(p2_t2_tinfo->get_fd_table()->m_table.size(), main_table_size);
// 	ASSERT_EQ(p2_t2_tinfo->get_cwd(), main_cwd);
// 	ASSERT_EQ(p2_t2_tinfo->get_env(), main_env);
// 	ASSERT_THREAD_INFO_FLAG(p2_t2_tid, PPM_CL_CLONE_FILES, true);

// 	sinsp_threadinfo* p2_t3_tinfo = m_inspector.get_thread_ref(p2_t3_tid, false).get();
// 	ASSERT_EQ(p2_t3_tinfo->get_fd_table()->m_table.size(), main_table_size);
// 	ASSERT_EQ(p2_t3_tinfo->get_cwd(), main_cwd);
// 	ASSERT_EQ(p2_t3_tinfo->get_env(), main_env);
// 	ASSERT_THREAD_INFO_FLAG(p2_t3_tid, PPM_CL_CLONE_FILES, true);

// 	/* Here we remove the main thread */
// 	m_inspector.remove_thread(p2_t1_tid);
// 	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 2, false, 3, 3, p2_t1_tid, p2_t2_tid, p2_t3_tid);
// 	ASSERT_THREAD_INFO_FLAG(p2_t1_tid, PPM_CL_CLOSED, true);

// 	/* Still have access to shared fields */
// 	ASSERT_EQ(p2_t2_tinfo->get_fd_table()->m_table.size(), main_table_size);
// 	ASSERT_EQ(p2_t2_tinfo->get_cwd(), main_cwd);
// 	ASSERT_EQ(p2_t2_tinfo->get_env(), main_env);

// 	ASSERT_EQ(p2_t3_tinfo->get_fd_table()->m_table.size(), main_table_size);
// 	ASSERT_EQ(p2_t3_tinfo->get_cwd(), main_cwd);
// 	ASSERT_EQ(p2_t3_tinfo->get_env(), main_env);

// 	/* remove the main thread with PROC_EXIT.
// 	 * This call should have no effect.
// 	 */
// 	remove_thread(p2_t1_tid);
// 	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 2, false, 3, 3, p2_t1_tid, p2_t2_tid, p2_t3_tid);
// 	ASSERT_THREAD_INFO_FLAG(p2_t1_tid, PPM_CL_CLOSED, true);

// 	/* Still have access to shared fields */
// 	ASSERT_EQ(p2_t2_tinfo->get_fd_table()->m_table.size(), main_table_size);
// 	ASSERT_EQ(p2_t2_tinfo->get_cwd(), main_cwd);
// 	ASSERT_EQ(p2_t2_tinfo->get_env(), main_env);

// 	ASSERT_EQ(p2_t3_tinfo->get_fd_table()->m_table.size(), main_table_size);
// 	ASSERT_EQ(p2_t3_tinfo->get_cwd(), main_cwd);
// 	ASSERT_EQ(p2_t3_tinfo->get_env(), main_env);

// 	/* remove the main thread manually from the table...
// 	 * now secondary threads should lose access to fdtable, cwd and
// 	 * env
// 	 */
// 	m_inspector.m_thread_manager->m_threadtable.erase(p2_t1_tid);
// 	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 2, false, 3, 2, p2_t2_tid, p2_t3_tid);

// 	/* we should obtain nullptr */
// 	ASSERT_FALSE(p2_t2_tinfo->get_fd_table());
// 	ASSERT_FALSE(p2_t3_tinfo->get_fd_table());

// 	ASSERT_EQ(p2_t2_tinfo->get_cwd(), "./");
// 	ASSERT_EQ(p2_t3_tinfo->get_cwd(), "./");
// 	ASSERT_NE(p2_t2_tinfo->m_env, main_env);
// 	ASSERT_NE(p2_t3_tinfo->m_env, main_env);
// }

/*=============================== FDTABLE ===========================*/

/*=============================== PRCTL ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_failed_prctl)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* FAILED PPM_PR_SET_CHILD_SUBREAPER */

	/* p2_t2 is not a reaper and shouldn't become it after this call */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);

	/* Let's imagine a prctl is called on `p2_t2` but it fails */
	add_event_advance_ts(increasing_ts(), p2_t2_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)-1,
			     PPM_PR_SET_CHILD_SUBREAPER, "<NA>", (int64_t)1);

	/* p2_t2 is not a reaper and shouldn't become it after this call */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);

	/* FAILED PPM_PR_GET_CHILD_SUBREAPER */

	/* Same thing for a failed prctl get */
	add_event_advance_ts(increasing_ts(), p2_t2_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)-1,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)1);

	/* p2_t2 is not a reaper and shouldn't become it after this call */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);

	/* INVALID THREAD INFO */

	/* this time the prctl call is successful but we call it from an invalid thread.
	 * Our logic will generate an invalid thread info, but this shouldn't have a valid tginfo so nothing should
	 * happen.
	 */
	int64_t invalid_tid = 61004;
	add_event_advance_ts(increasing_ts(), invalid_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)1);

	sinsp_threadinfo* invalid_tid_tinfo = m_inspector.get_thread_ref(invalid_tid, false).get();
	ASSERT_TRUE(invalid_tid_tinfo);
	ASSERT_FALSE(invalid_tid_tinfo->m_tginfo);

	/* UNKNOWN prctl option */

	/* Nothing should happen */
	add_event_advance_ts(increasing_ts(), invalid_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0, PPM_PR_SET_NAME, "<NA>",
			     (int64_t)1);
}

TEST_F(sinsp_with_test_input, THRD_STATE_prctl_set_child_subreaper)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* SET CHILD_SUBREAPER */

	/* p2_t2 is not a reaper and should become it after this call */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);

	/* Let's imagine a prctl is called on `p2_t2` */
	add_event_advance_ts(increasing_ts(), p2_t2_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_SET_CHILD_SUBREAPER, "<NA>", (int64_t)80);

	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, true, 3, 3);

	/* UNSET CHILD_SUBREAPER */

	/* Let's imagine `p2_t3` unset its group with a prctl call */
	add_event_advance_ts(increasing_ts(), p2_t3_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_SET_CHILD_SUBREAPER, "<NA>", (int64_t)0);

	/* p2_t2 group should have reaper==false */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);
}

TEST_F(sinsp_with_test_input, THRD_STATE_prctl_get_child_subreaper)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* SET CHILD_SUBREAPER */

	/* p2_t2 is not a reaper and should become it after this call */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);

	/* Let's imagine a prctl is called on `p2_t2` */
	add_event_advance_ts(increasing_ts(), p2_t2_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)1);

	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, true, 3, 3);

	/* UNSET CHILD_SUBREAPER */

	/* Let's imagine `p2_t3` unset its group with a prctl call */
	add_event_advance_ts(increasing_ts(), p2_t3_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)0);

	/* p2_t2 group should have reaper==false */
	ASSERT_THREAD_GROUP_INFO(p2_t2_pid, 3, false, 3, 3);
}

/*=============================== PRCTL ===========================*/

/*=============================== EXECVE ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_execve_from_a_not_leader_thread)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* `p2_t2` calls an execve and `p2_t1` will take control in the exit event */
	generate_execve_enter_and_exit_event(0, p2_t2_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid);

	/* we should have just one thread alive, the leader one */
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 3, 1, p2_t1_tid);

	/* we shouldn't be able to find old threads in the thread table */
	sinsp_threadinfo* p2_t2_tinfo = m_inspector.get_thread_ref(p2_t2_tid, false).get();
	ASSERT_FALSE(p2_t2_tinfo);

	sinsp_threadinfo* p2_t3_tinfo = m_inspector.get_thread_ref(p2_t3_tid, false).get();
	ASSERT_FALSE(p2_t3_tinfo);
}

TEST_F(sinsp_with_test_input, THRD_STATE_execve_from_a_leader_thread)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* `p2_t1` calls an execve */
	generate_execve_enter_and_exit_event(0, p2_t1_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid);

	/* we should have just one thread alive, the leader one */
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 3, 1, p2_t1_tid);

	/* we shouldn't be able to find old threads in the thread table */
	sinsp_threadinfo* p2_t2_tinfo = m_inspector.get_thread_ref(p2_t2_tid, false).get();
	ASSERT_FALSE(p2_t2_tinfo);

	sinsp_threadinfo* p2_t3_tinfo = m_inspector.get_thread_ref(p2_t3_tid, false).get();
	ASSERT_FALSE(p2_t3_tinfo);
}

TEST_F(sinsp_with_test_input, THRD_STATE_execve_from_a_not_leader_thread_with_a_child)
{
	/* Instantiate the default tree */
	DEFAULT_TREE

	/* Create a child for `p2t3` */
	int64_t p7_t1_tid = 100;
	UNUSED int64_t p7_t1_pid = 100;
	UNUSED int64_t p7_t1_ptid = p2_t3_tid;

	generate_clone_x_event(p7_t1_tid, p2_t3_tid, p2_t3_pid, p2_t3_ptid);

	ASSERT_THREAD_CHILDREN(p2_t3_tid, 1, 1, p7_t1_tid);

	/* Right now `p2_t1` has just one child */
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 1, 1, p3_t1_tid);

	/* `p2_t2` calls an execve and `p2_t1` will take control in the exit event */
	generate_execve_enter_and_exit_event(0, p2_t2_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid);

	/* we should have just one thread alive, the leader one */
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 3, 1, p2_t1_tid);

	/* we shouldn't be able to find old threads in the thread table */
	sinsp_threadinfo* p2_t2_tinfo = m_inspector.get_thread_ref(p2_t2_tid, false).get();
	ASSERT_FALSE(p2_t2_tinfo);

	sinsp_threadinfo* p2_t3_tinfo = m_inspector.get_thread_ref(p2_t3_tid, false).get();
	ASSERT_FALSE(p2_t3_tinfo);

	/* Now the father of `p7_t1` should be `p2_t1` */
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 2, 2, p3_t1_tid, p7_t1_tid);
}

/*=============================== EXECVE ===========================*/

/*=============================== MISSING INFO ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_missing_both_clone_events_create_leader_thread)
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

	/* We use the clone parent exit event */
	generate_clone_x_event(p3_t1_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_ptid);
	ASSERT_THREAD_GROUP_INFO(p3_t1_pid, 1, false, 1, 1, p3_t1_tid);

	/* We should have created a valid thread info for p2_t1 */
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, 1, p2_t1_tid);
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 1, 1, p3_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 1, 1, p2_t1_tid);

	/* Process p2 is generated as invalid so we have no thread info */
	auto tinfo = m_inspector.m_thread_manager->get_thread_ref(p2_t1_tid).get();
	ASSERT_TRUE(tinfo);
	ASSERT_FALSE(tinfo->is_invalid());
}

/* Here we are using the parent clone exit event to reconstruct the tree */
TEST_F(sinsp_with_test_input, THRD_STATE_missing_both_clone_events_create_secondary_threads)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 but we miss both clone events so we know nothing about it */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	/* The process p1 creates a second thread p1_t2 */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_TID;

	/* We use the clone parent exit event */
	generate_clone_x_event(p1_t2_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)
	ASSERT_THREAD_GROUP_INFO(p1_t2_pid, 2, false, 2, 2, p1_t2_tid, p1_t1_tid);
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid);
}

/* Here we are using the child clone exit event to reconstruct the tree */
TEST_F(sinsp_with_test_input, THRD_STATE_missing_both_clone_events_create_secondary_threads_child_event)
{
	add_default_init_thread();
	open_inspector();

	/* Init creates a new process p1 but we miss both clone events so we know nothing about it */
	int64_t p1_t1_tid = 24;
	UNUSED int64_t p1_t1_pid = 24;
	UNUSED int64_t p1_t1_ptid = INIT_TID;

	/* The process p1 creates a second thread p1_t2 */
	int64_t p1_t2_tid = 30;
	int64_t p1_t2_pid = 24;
	int64_t p1_t2_ptid = INIT_TID;

	/* We use the clone child exit event */
	generate_clone_x_event(0, p1_t2_tid, p1_t2_pid, p1_t2_ptid, PPM_CL_CLONE_THREAD);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid)
	ASSERT_THREAD_GROUP_INFO(p1_t2_pid, 2, false, 2, 2, p1_t2_tid, p1_t1_tid);
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 2, p1_t1_tid, p1_t2_tid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_missing_process_execve_repair)
{
	add_default_init_thread();
	open_inspector();

	/* A process that we don't have in the table calls prctl */
	int64_t p1_t1_tid = 24;
	UNUSED int64_t p1_t1_pid = 24;
	UNUSED int64_t p1_t1_ptid = INIT_TID;

	/* This event should create an invalid thread info */
	add_event_advance_ts(increasing_ts(), p1_t1_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)0);

	/* Now we call an execve on this event */
	generate_execve_enter_and_exit_event(0, p1_t1_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid);

	/* we should have a valid thread group info and init should have a child now */
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, 1, p1_t1_tid);
	ASSERT_THREAD_CHILDREN(INIT_TID, 1, 1, p1_t1_tid);
}

/*=============================== MISSING INFO ===========================*/

/*=============================== COMM UPDATE ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_caller_comm_update_after_clone_events)
{
	add_default_init_thread();

	/* Let's create process p1 */
	int64_t p1_t1_tid = 24;
	int64_t p1_t1_pid = 24;
	int64_t p1_t1_ptid = INIT_TID;

	add_simple_thread(p1_t1_tid, p1_t1_pid, p1_t1_ptid, "old-name");

	open_inspector();

	/* Now imagine that process p1 calls a prctl and changes its name... */

	/* p1_t1 create a new process p2_t1. The clone caller exit event contains the new comm and should update the
	 * comm of p1
	 */

	int64_t p2_t1_tid = 26;
	UNUSED int64_t p2_t1_pid = 26;
	UNUSED int64_t p2_t1_ptid = p1_t1_tid;

	ASSERT_THREAD_INFO_COMM(p1_t1_tid, "old-name");
	generate_clone_x_event(p2_t1_tid, p1_t1_tid, p1_t1_pid, p1_t1_ptid, DEFAULT_VALUE, DEFAULT_VALUE, DEFAULT_VALUE,
			       "new-name");
	/* The caller has a new comm but we don't catch it! */
	ASSERT_THREAD_INFO_COMM(p1_t1_tid, "old-name");

	/* After this event the child will have the caller `comm` but this is not the right behavior!
	 * The child should have its own `comm`.
	 */
	ASSERT_THREAD_INFO_COMM(p2_t1_tid, "new-name");
	GTEST_SKIP()
		<< "The behavior of this test is wrong we don't update the `comm` name of the caller if it changes!";
}

/*=============================== COMM UPDATE ===========================*/

/*=============================== THREAD-GROUP-INFO ===========================*/

static sinsp_threadinfo* add_thread_to_the_table(sinsp* insp, int64_t tid, int64_t pid, int64_t ptid)
{
	auto thread_info = new sinsp_threadinfo(insp);
	thread_info->m_tid = tid;
	thread_info->m_pid = pid;
	thread_info->m_ptid = ptid;
	insp->add_thread(thread_info);
	return thread_info;
}

TEST(thread_group_info, create_thread_group_info)
{
	std::shared_ptr<sinsp_threadinfo> tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo.reset();

	/* This will throw an exception since tinfo is expired */
	EXPECT_THROW(thread_group_info(34, true, tinfo), sinsp_exception);

	tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 23;
	tinfo->m_pid = 23;

	thread_group_info tginfo(tinfo->m_pid, true, tinfo);
	EXPECT_EQ(tginfo.get_thread_count(), 1);
	EXPECT_TRUE(tginfo.is_reaper());
	EXPECT_EQ(tginfo.get_tgroup_pid(), 23);
	auto threads = tginfo.get_thread_list();
	ASSERT_EQ(threads.size(), 1);
	ASSERT_EQ(tginfo.get_first_thread(), tinfo.get());

	/* There are no threads in the thread group info, the first thread should be nullprt */
	tinfo.reset();
	ASSERT_EQ(tginfo.get_first_thread(), nullptr);

	tginfo.set_reaper(false);
	EXPECT_FALSE(tginfo.is_reaper());

	tginfo.set_reaper(true);
	EXPECT_TRUE(tginfo.is_reaper());
}

TEST(thread_group_info, populate_thread_group_info)
{
	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 23;
	tinfo->m_pid = 23;

	thread_group_info tginfo(tinfo->m_pid, false, tinfo);
	EXPECT_FALSE(tginfo.is_reaper());

	tginfo.increment_thread_count();
	tginfo.increment_thread_count();
	EXPECT_EQ(tginfo.get_thread_count(), 3);
	tginfo.decrement_thread_count();
	EXPECT_EQ(tginfo.get_thread_count(), 2);

	auto tinfo1 = std::make_shared<sinsp_threadinfo>();
	tginfo.add_thread_to_the_group(tinfo1, true);
	ASSERT_EQ(tginfo.get_first_thread(), tinfo1.get());
	EXPECT_EQ(tginfo.get_thread_count(), 3);

	auto tinfo2 = std::make_shared<sinsp_threadinfo>();
	tginfo.add_thread_to_the_group(tinfo2, false);
	ASSERT_EQ(tginfo.get_first_thread(), tinfo1.get());
	ASSERT_EQ(tginfo.get_thread_list().back().lock().get(), tinfo2.get());
	EXPECT_EQ(tginfo.get_thread_count(), 4);
}

TEST(thread_group_info, get_main_thread)
{
	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 23;
	tinfo->m_pid = 23;

	auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	/* We are the main thread so here we don't use the thread group info */
	ASSERT_EQ(tinfo->get_main_thread(), tinfo.get());

	/* Now we change the tid so we are no more a main thread and we use the thread group info
	 * we should obtain a nullptr since tinfo doesn't have any thread info associated.
	 */
	tinfo->m_tid = 25;
	ASSERT_EQ(tinfo->get_main_thread(), nullptr);

	/* We should still obtain a nullptr since the first tinfo in the table is not a main thread. */
	tinfo->m_tginfo = tginfo;
	ASSERT_EQ(tinfo->get_main_thread(), nullptr);

	auto main_tinfo = std::make_shared<sinsp_threadinfo>();
	main_tinfo->m_tid = 23;
	main_tinfo->m_pid = 23;

	/* We should still obtain a nullptr since we put the main thread as the last element of the list. */
	tinfo->m_tginfo->add_thread_to_the_group(main_tinfo, false);
	ASSERT_EQ(tinfo->get_main_thread(), nullptr);

	tinfo->m_tginfo->add_thread_to_the_group(main_tinfo, true);
	ASSERT_EQ(tinfo->get_main_thread(), main_tinfo.get());
}

TEST(thread_group_info, get_num_threads)
{
	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 25;
	tinfo->m_pid = 23;

	auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	/* Thread info doesn't have an associated thread group info */
	ASSERT_EQ(tinfo->get_num_threads(), 0);
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 0);

	tinfo->m_tginfo = tginfo;
	ASSERT_EQ(tinfo->get_num_threads(), 1);
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 1);

	auto main_tinfo = std::make_shared<sinsp_threadinfo>();
	main_tinfo->m_tid = 23;
	main_tinfo->m_pid = 23;

	tinfo->m_tginfo->add_thread_to_the_group(main_tinfo, true);
	ASSERT_EQ(tinfo->get_num_threads(), 2);
	/* 1 thread is the main thread so we should return just 1 */
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 1);

	main_tinfo->set_dead();

	/* Please note that here we still have 2 because we have just marked the thread as Dead without decrementing the
	 * alive count */
	ASSERT_EQ(tinfo->get_num_threads(), 2);
	ASSERT_EQ(tinfo->get_num_not_leader_threads(), 2);
}

TEST(thread_group_info, thread_group_manager)
{
	sinsp inspector;
	/* We don't have thread group info here */
	ASSERT_FALSE(inspector.m_thread_manager->get_thread_group_info(8).get());

	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_pid = 12;
	auto tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	inspector.m_thread_manager->set_thread_group_info(tinfo->m_pid, tginfo);
	ASSERT_TRUE(inspector.m_thread_manager->get_thread_group_info(tinfo->m_pid).get());

	auto new_tginfo = std::make_shared<thread_group_info>(tinfo->m_pid, false, tinfo);

	/* We should replace the old thread group info */
	inspector.m_thread_manager->set_thread_group_info(tinfo->m_pid, new_tginfo);
	ASSERT_NE(inspector.m_thread_manager->get_thread_group_info(tinfo->m_pid).get(), tginfo.get());
	ASSERT_EQ(inspector.m_thread_manager->get_thread_group_info(tinfo->m_pid).get(), new_tginfo.get());
}

TEST(thread_group_info, create_thread_dependencies)
{
	sinsp m_inspector;

	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo.reset();

	/* The thread info is nullptr */
	EXPECT_THROW(m_inspector.m_thread_manager->create_thread_dependencies(tinfo), sinsp_exception);

	/* The thread info is nullptr */
	tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo->m_tid = 4;
	tinfo->m_pid = -1;
	tinfo->m_ptid = 1;

	/* The thread info is invalid we do nothing */
	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_FALSE(tinfo->m_tginfo);

	/* We set a valid pid and a valid thread group info */
	tinfo->m_pid = 4;
	auto tginfo = std::make_shared<thread_group_info>(4, false, tinfo);
	tinfo->m_tginfo = tginfo;
	ASSERT_EQ(tinfo->m_tginfo->get_thread_count(), 1);

	/* The thread info already has a thread group we do nothing */
	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);
	ASSERT_EQ(tinfo->m_tginfo->get_thread_count(), 1);

	/* We reset the thread group */
	tinfo->m_tginfo.reset();
	tginfo.reset();

	/* We set a not existent parent `3`, but our thread table is empty, we don't have any thread in it
	 * so we will search for `3` and we won't find anything. So as a fallback, we will search
	 * for init but also in this case we won't find anything so we will set tid 0 as a parent.
	 */
	tinfo->m_ptid = 3;
	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);

	/* We created thread group info */
	ASSERT_THREAD_GROUP_INFO(tinfo->m_pid, 1, false, 1, 1);

	/* We set the parent to 0 */
	ASSERT_EQ(tinfo->m_ptid, 0);
}

TEST(thread_group_info, find_reaper_with_null_thread_group_info)
{
	sinsp m_inspector;

	/* This is the dead thread. This is an invalid thread (ptid==-1) so it won't have a thread group info */
	auto thread_to_remove = add_thread_to_the_table(&m_inspector, 27, 25, -1);

	/* We need to set the thread as dead before calling the reaper function */
	thread_to_remove->set_dead();

	/* Call the reaper function without thread group info.
	 * We should search for init thread info, but init is not there in this example
	 * so the method should return a nullptr.
	 */
	ASSERT_FALSE(m_inspector.m_thread_manager->find_new_reaper(thread_to_remove));
}

TEST(thread_group_info, find_reaper_in_the_same_thread_group)
{
	sinsp m_inspector;

	/* Add init to the thread table */
	add_thread_to_the_table(&m_inspector, INIT_TID, INIT_PID, INIT_PTID);

	/* This is the dead thread */
	auto thread_to_remove = add_thread_to_the_table(&m_inspector, 27, 25, 1);

	/* We need to set the thread as dead before calling the reaper function */
	thread_to_remove->set_dead();

	/* Add a new thread to the group that will be the reaper */
	auto thread_reaper = add_thread_to_the_table(&m_inspector, 25, 25, 1);

	/* Call the find reaper method, the reaper thread should be the unique thread alive in the group  */
	ASSERT_EQ(m_inspector.m_thread_manager->find_new_reaper(thread_to_remove), thread_reaper);
}

TEST(thread_group_info, find_a_valid_reaper)
{
	sinsp m_inspector;

	/* Add init to the thread table */
	add_thread_to_the_table(&m_inspector, INIT_TID, INIT_PID, INIT_PTID);

	/* p1_t1 is a child of init */
	auto p1_t1 = add_thread_to_the_table(&m_inspector, 20, 20, INIT_TID);
	p1_t1->m_tginfo->set_reaper(true);

	/* p2_t1 is a child of p1_t1 */
	add_thread_to_the_table(&m_inspector, 21, 21, 20);

	/* p3_t1 is a child of p2_t1 */
	auto p2_t1 = add_thread_to_the_table(&m_inspector, 22, 22, 21);

	/* We need to set the thread as dead before calling the reaper function */
	p2_t1->set_dead();

	/* We have no threads in the same group so we will search for a reaper in the parent hierarchy  */
	ASSERT_EQ(m_inspector.m_thread_manager->find_new_reaper(p2_t1), p1_t1);
}

/*=============================== THREAD-GROUP-INFO ===========================*/

/*=============================== THREAD-INFO ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_assign_children_to_reaper)
{
	DEFAULT_TREE

	auto p3_t1_tinfo = m_inspector.get_thread_ref(p3_t1_tid, false).get();

	/* The reaper cannot be null */
	EXPECT_THROW(p3_t1_tinfo->assign_children_to_reaper(nullptr), sinsp_exception);

	/* children of p3_t1 are p4_t1 and p4_t2 we can reparent them to p1_t1 */
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 0, 0);

	auto p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	p3_t1_tinfo->assign_children_to_reaper(p1_t1_tinfo);

	/* all p3_t1 children should be expired */
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 2, 0);

	/* the new parent should be p1_t1 */
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, p1_t1_tid, p4_t1_vtid, p4_t1_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t2_tid, p4_t2_pid, p1_t1_tid, p4_t2_vtid, p4_t2_vpid);

	ASSERT_THREAD_CHILDREN(p1_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);

	/* Another call to the reparenting function should do nothing */
	p3_t1_tinfo->assign_children_to_reaper(p1_t1_tinfo);
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 2, 0);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);
}

/*=============================== THREAD-INFO ===========================*/

/*=============================== SCAP-FILES ===========================*/

#include <libsinsp_test_var.h>

sinsp_evt* search_evt_by_num(sinsp* inspector, uint64_t evt_num)
{
	sinsp_evt* evt;
	int ret = SCAP_SUCCESS;
	while(ret != SCAP_EOF)
	{
		ret = inspector->next(&evt);
		if(ret == SCAP_SUCCESS && evt->get_num() == evt_num)
		{
			return evt;
		}
	}
	return NULL;
}

sinsp_evt* search_evt_by_type_and_tid(sinsp* inspector, uint64_t type, int64_t tid)
{
	sinsp_evt* evt;
	int ret = SCAP_SUCCESS;
	while(ret != SCAP_EOF)
	{
		ret = inspector->next(&evt);
		if(ret == SCAP_SUCCESS && evt->get_type() == type && evt->get_tid() == tid)
		{
			return evt;
		}
	}
	return NULL;
}

TEST(parse_scap_file, simple_tree_with_prctl)
{
	/* Scap file:
	 *  - x86
	 *  - generated with kmod
	 *  - generated with libs version 0.11.0
	 */
	std::string path = LIBSINSP_TEST_SCAP_FILES_DIR + std::string("simple_tree_with_prctl.scap");
	sinsp m_inspector;
	m_inspector.open_savefile(path);

	/* The number of events, pids and all other info are obtained by analyzing the scap-file manually */

	/*
	 * `zsh` performs a clone and creates a child p1_t1
	 */
	sinsp_evt* evt = search_evt_by_num(&m_inspector, 44315);

	int64_t p1_t1_tid = 21104;
	int64_t p1_t1_pid = 21104;
	int64_t p1_t1_ptid = 6644; /* zsh */

	/* Parent clone exit event */
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_CLONE_20_X);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, 1, p1_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_ptid, 1, 1, p1_t1_tid);
	ASSERT_THREAD_INFO_COMM(p1_t1_tid, "zsh");

	/*
	 * `p1_t1` performs an execve calling the executable `example1`
	 */
	evt = search_evt_by_num(&m_inspector, 44450);

	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_EXECVE_19_X);
	ASSERT_THREAD_INFO_PIDS(p1_t1_tid, p1_t1_pid, p1_t1_ptid);
	ASSERT_THREAD_GROUP_INFO(p1_t1_pid, 1, false, 1, 1, p1_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_ptid, 1, 1, p1_t1_tid);
	ASSERT_THREAD_INFO_COMM(p1_t1_tid, "example1");

	/*
	 * `p1_t1` that creates a second thread `p1_t2`
	 */
	evt = search_evt_by_num(&m_inspector, 44661);

	int64_t p1_t2_tid = 21105;
	int64_t p1_t2_pid = p1_t1_pid;
	int64_t p1_t2_ptid = 6644; /* zsh */

	/* Parent clone exit event */
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_CLONE3_X);
	ASSERT_THREAD_INFO_PIDS(p1_t2_tid, p1_t2_pid, p1_t2_ptid);
	ASSERT_THREAD_GROUP_INFO(p1_t2_pid, 2, false, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_ptid, 2, 2, p1_t1_tid, p1_t2_tid);
	ASSERT_THREAD_INFO_COMM(p1_t2_tid, "example1");

	/*
	 * `p1_t2` calls prctl and sets its group as a reaper
	 */
	evt = search_evt_by_num(&m_inspector, 44692);

	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_PRCTL_X);
	ASSERT_THREAD_GROUP_INFO(p1_t2_pid, 2, true, 2, 2, p1_t1_tid, p1_t2_tid);

	// evt = search_evt_by_type_and_tid(&m_inspector, PPME_SYSCALL_PRCTL_X, p1_t2_tid);
	// printf("evt num: %ld\n", evt->get_num());

	/*
	 * `p1_t2` creates a new leader thread `p2_t1`
	 */
	evt = search_evt_by_num(&m_inspector, 44765);

	int64_t p2_t1_tid = 21106;
	int64_t p2_t1_pid = p2_t1_tid;
	int64_t p2_t1_ptid = p1_t2_tid;

	/* Parent clone exit event */
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_CLONE_20_X);
	ASSERT_THREAD_INFO_PIDS(p2_t1_tid, p2_t1_pid, p2_t1_ptid);
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 1, 1, p2_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t2_tid, 1, 1, p2_t1_tid);
	ASSERT_THREAD_INFO_COMM(p2_t1_tid, "example1");

	/*
	 * `p2_t1` creates a new leader thread `p3_t1`
	 */
	evt = search_evt_by_num(&m_inspector, 44845);

	int64_t p3_t1_tid = 21107;
	int64_t p3_t1_pid = p3_t1_tid;
	int64_t p3_t1_ptid = p2_t1_tid;

	/* Parent clone exit event */
	ASSERT_EQ(evt->get_type(), PPME_SYSCALL_CLONE_20_X);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p3_t1_ptid);
	ASSERT_THREAD_GROUP_INFO(p3_t1_pid, 1, false, 1, 1, p3_t1_tid);
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 1, 1, p3_t1_tid);
	ASSERT_THREAD_INFO_COMM(p3_t1_tid, "example1");

	/*
	 * `p2_t1` dies and `p3_t1` is reparented to `p1_t1`
	 */
	evt = search_evt_by_num(&m_inspector, 76892);
	ASSERT_EQ(evt->get_type(), PPME_PROCEXIT_1_E);

	/* We need to call the next event since the procexit happens at the next loop */
	search_evt_by_num(&m_inspector, 76892 + 1);
	ASSERT_MISSING_THREAD_INFO(p2_t1_tid, true);
	auto tginfo = m_inspector.m_thread_manager->get_thread_group_info(p2_t1_pid).get();
	ASSERT_FALSE(tginfo);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, p1_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 1, 1, p3_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t2_tid, 1, 0);

	/*
	 * `p1_t2` dies, no reparenting
	 */
	evt = search_evt_by_num(&m_inspector, 98898);
	ASSERT_EQ(evt->get_type(), PPME_PROCEXIT_1_E);

	/* We need to call the next event since the procexit happens at the next loop */
	search_evt_by_num(&m_inspector, 98898 + 1);
	ASSERT_MISSING_THREAD_INFO(p1_t2_tid, true);
	ASSERT_THREAD_GROUP_INFO(p1_t2_pid, 1, true, 2, 1, p1_t1_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_ptid, 2, 1, p1_t1_tid);

	/*
	 * `p1_t1` dies `p3_t1` is reparented to `init`
	 */
	evt = search_evt_by_num(&m_inspector, 135127);
	ASSERT_EQ(evt->get_type(), PPME_PROCEXIT_1_E);

	/* We need to call the next event since the procexit happens at the next loop */
	search_evt_by_num(&m_inspector, 135127 + 1);
	ASSERT_MISSING_THREAD_INFO(p1_t1_tid, true);
	tginfo = m_inspector.m_thread_manager->get_thread_group_info(p1_t1_pid).get();
	ASSERT_FALSE(tginfo);
	ASSERT_THREAD_INFO_PIDS(p3_t1_tid, p3_t1_pid, INIT_TID);

	/*
	 * `p3_t1` dies, no reparenting
	 */
	evt = search_evt_by_num(&m_inspector, 192655);
	ASSERT_EQ(evt->get_type(), PPME_PROCEXIT_1_E);

	/* We need to call the next event since the procexit happens at the next loop */
	search_evt_by_num(&m_inspector, 192655 + 1);
	ASSERT_MISSING_THREAD_INFO(p3_t1_tid, true);
	tginfo = m_inspector.m_thread_manager->get_thread_group_info(p3_t1_pid).get();
	ASSERT_FALSE(tginfo);
}

/*=============================== SCAP-FILES ===========================*/

/*=============================== EXPIRED_CHILDREN ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_expired_children)
{
	DEFAULT_TREE

	auto init_tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);

	/* Do nothing */
	init_tinfo->clean_expired_children();

	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);

	/* set the expired children threshold */
	sinsp_threadinfo::set_expired_children_threshold(2);
	ASSERT_EQ(sinsp_threadinfo::get_expired_children_threshold(), 2);

	/* Do nothing */
	init_tinfo->clean_expired_children();

	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);

	/* remove p1_t2. It has no children so the cleanup logic on INIT process
	 * is not called
	 */
	remove_thread(p1_t2_tid);

	/* Now one thread is expired */
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 4);

	/* Same for these threads, they have no children */
	remove_thread(p1_t1_tid);
	remove_thread(p2_t2_tid);
	remove_thread(p2_t3_tid);
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 1);

	/* p2_t1 has a child so we move it to the new reaper -> INIT.
	 * Since INIT has more than 2 (2 is the threshold) children
	 * in the list (expired or not). We will perform the cleanup.
	 *
	 * Please note that the cleanup is performed when p2_t1 is still alive.
	 * After remove_thread `p2_t1` is correctly removed so we will have a list of 2 elements where:
	 * - p2_t1 is expired
	 * - p3_t1 is alive
	 */
	remove_thread(p2_t1_tid);
	ASSERT_THREAD_CHILDREN(INIT_TID, 2, 1, p3_t1_tid);

	/* restore the threshold */
	sinsp_threadinfo::set_expired_children_threshold(DEFAULT_CHILDREN_THRESHOLD);
	ASSERT_EQ(sinsp_threadinfo::get_expired_children_threshold(), DEFAULT_CHILDREN_THRESHOLD);
}

/*=============================== EXPIRED_CHILDREN ===========================*/
