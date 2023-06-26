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

#include <test/helpers/threads_helpers.h>

/* These are a sort of e2e for the sinsp state, they assert some flows in sinsp */

TEST_F(sinsp_with_test_input, THRD_TABLE_check_default_tree)
{
	/* This test allow us to trust the DEFAULT TREE in other tests */

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

TEST_F(sinsp_with_test_input, THRD_TABLE_missing_init_in_proc)
{
	int64_t p1_t1_tid = 2;
	int64_t p1_t1_pid = 2;
	int64_t p1_t1_ptid = INIT_TID;
	add_simple_thread(p1_t1_tid, p1_t1_pid, p1_t1_ptid);

	/* with open_inspector we will create thread_dependencies for p1_t1_tid
	 * more in detail since we don't have `init` in the table we will create a fake one
	 */
	open_inspector();

	/* Check the fake init thread info just created */
	auto init_tinfo = m_inspector.get_thread_ref(INIT_TID, false).get();
	ASSERT_TRUE(init_tinfo);
	/* This is an invalid thread so we should expect the following values */;
	ASSERT_EQ(init_tinfo->m_ptid, -1);
	ASSERT_STREQ(init_tinfo->m_comm.c_str(), "<NA>");
}

TEST_F(sinsp_with_test_input, THRD_TABLE_check_init_process_creation)
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

TEST_F(sinsp_with_test_input, THRD_TABLE_create_thread_dependencies_after_proc_scan)
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

TEST_F(sinsp_with_test_input, THRD_TABLE_remove_inactive_threads)
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
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 1, false, 2, 2, p2_t1_tid, p2_t2_tid);

	/* Calling PRCTL on an unknown thread should generate an invalid thread */
	int64_t unknown_tid = 61103;
	add_event_advance_ts(increasing_ts(), unknown_tid, PPME_SYSCALL_PRCTL_X, 4, (int64_t)0,
			     PPM_PR_GET_CHILD_SUBREAPER, "<NA>", (int64_t)0);

	auto unknown_tinfo = m_inspector.get_thread_ref(unknown_tid, false).get();
	ASSERT_TRUE(unknown_tinfo);
	ASSERT_FALSE(unknown_tinfo->m_tginfo);
	ASSERT_EQ(unknown_tinfo->m_ptid, -1);

	/* This call should remove only invalid threads */
	remove_inactive_threads(80, 20);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, m_inspector.m_thread_manager->get_thread_count());

	/* successive remove call on `p2_t1` do nothing since it is a main thread */
	m_inspector.remove_thread(p2_t1_tid);
	m_inspector.remove_thread(p2_t1_tid);
	ASSERT_EQ(DEFAULT_TREE_NUM_PROCS - 1, m_inspector.m_thread_manager->get_thread_count());
}

TEST_F(sinsp_with_test_input, THRD_TABLE_traverse_default_tree)
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

	traverse_parents.clear();
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
	/* the reaper is the other thread in the group */
	remove_thread(p4_t2_tid, p4_t1_tid);
	ASSERT_THREAD_GROUP_INFO(p4_t1_pid, 1, true, 2, 1, p4_t1_tid)
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 2, 2, p5_t1_tid, p5_t2_tid)

	/* Remove p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 0, 0)
	remove_thread(p5_t2_tid, p5_t1_tid);
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid)

	/* Remove p5_t1 */
	remove_thread(p5_t1_tid, p4_t1_tid);

	/* Now p6_t1 should be assigned to p4_t1 since it is the reaper */
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 3, 1, p6_t1_tid)

	/* Set p2_t1 group as reaper, emulate prctl */
	auto tginfo = m_inspector.m_thread_manager->get_thread_group_info(p2_t1_pid).get();
	tginfo->set_reaper(true);

	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, true, 3, 3, p2_t1_tid, p2_t2_tid, p2_t3_tid)

	/* Remove p2_t1 */
	ASSERT_THREAD_CHILDREN(p2_t2_tid, 0, 0)
	remove_thread(p2_t1_tid, p2_t2_tid);
	ASSERT_THREAD_CHILDREN(p2_t2_tid, 1, 1, p3_t1_tid)

	/* Remove p2_t2 */
	ASSERT_THREAD_CHILDREN(p2_t3_tid, 0, 0)
	remove_thread(p2_t2_tid, p2_t3_tid);
	/* Please note that the parent of `p2_t2` is `init` since it was created with
	 * CLONE_PARENT flag.
	 */
	ASSERT_THREAD_CHILDREN(p2_t3_tid, 1, 1, p3_t1_tid)

	/* Remove p3_t1 */
	remove_thread(p3_t1_tid, p2_t3_tid);
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


/// QUESTI SONO ANCORA NELLA CLONE
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

/// QUESTA EXCVE
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

TEST_F(sinsp_with_test_input, THREAD_GROUP_create_thread_dependencies)
{
	open_inspector();

	auto tinfo = std::make_shared<sinsp_threadinfo>();
	tinfo.reset();

	/* The thread info is nullptr */
	EXPECT_THROW(m_inspector.m_thread_manager->create_thread_dependencies(tinfo), sinsp_exception);

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
	 * for init.
	 */
	tinfo->m_ptid = 3;
	m_inspector.m_thread_manager->create_thread_dependencies(tinfo);

	/* We created thread group info */
	ASSERT_THREAD_GROUP_INFO(tinfo->m_pid, 1, false, 1, 1);

	/* We set the parent to 0 */
	ASSERT_EQ(tinfo->m_ptid, 1);
}

TEST_F(sinsp_with_test_input, THREAD_GROUP_find_reaper_with_null_thread_group_info)
{
	open_inspector();
	/* This is the thread we will remove.
	 * This is an invalid thread (ptid==-1) so it won't have a thread group info
	 */
	auto thread_to_remove = add_thread_to_the_table(&m_inspector, 27, 25, -1);

	/* We need to set the thread as dead before calling the reaper function */
	thread_to_remove->set_dead();

	/* Call the reaper function without thread group info.
	 * We should search for init thread info, but init is not there so we create
	 * a mock threadinfo and we will obtain it as a new reaper.
	 */
	auto mock_init_tinfo = m_inspector.m_thread_manager->find_new_reaper(thread_to_remove);
	ASSERT_TRUE(mock_init_tinfo);
	ASSERT_EQ(mock_init_tinfo->m_tid, 1);
	ASSERT_EQ(mock_init_tinfo->m_pid, -1);
	ASSERT_EQ(mock_init_tinfo->m_ptid, -1);
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

TEST_F(sinsp_with_test_input, detect_a_loop_during_find_new_reaper)
{
	DEFAULT_TREE

	/* If we detect a loop the new reaper will be init.
	 * To be sure that init is the new reaper due to a loop and not
	 * because it is the real reaper, we set p2_t1 group as a reaper.
	 */
	auto p2_t1_tinfo = m_inspector.get_thread_ref(p2_t1_tid, false).get();
	ASSERT_TRUE(p2_t1_tinfo);
	p2_t1_tinfo->m_tginfo->set_reaper(true);

	/* We explicitly set p3_t1 ptid to p4_t1, so we create a loop */
	auto p3_t1_tinfo = m_inspector.get_thread_ref(p3_t1_tid, false).get();
	ASSERT_TRUE(p3_t1_tinfo);
	p3_t1_tinfo->m_ptid = p4_t1_tid;

	/* We will call find_new_reaper on p4_t1 but before doing this we need to
	 * remove p4_t2 otherwise we will have a valid thread in the same group as a new reaper
	 */
	remove_thread(p4_t2_tid, p4_t1_tid);

	/* We call find_new_reaper on p4_t1.
	 * The new reaper should be init since we detected a loop.
	 */
	auto p4_t1_tinfo = m_inspector.get_thread_ref(p4_t1_tid, false).get();
	ASSERT_TRUE(p4_t1_tinfo);
	auto init_tinfo = m_inspector.get_thread_ref(INIT_TID, false).get();
	ASSERT_TRUE(init_tinfo);
	ASSERT_EQ(m_inspector.m_thread_manager->find_new_reaper(p4_t1_tinfo), init_tinfo);
}

/*=============================== THREAD-GROUP-INFO ===========================*/

/*=============================== THREAD-INFO ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_assign_children_to_reaper)
{
	DEFAULT_TREE

	auto p3_t1_tinfo = m_inspector.get_thread_ref(p3_t1_tid, false).get();

	/* The reaper cannot be null */
	EXPECT_THROW(p3_t1_tinfo->assign_children_to_reaper(nullptr), sinsp_exception);

	/* The reaper cannot be the current process */
	EXPECT_THROW(p3_t1_tinfo->assign_children_to_reaper(p3_t1_tinfo), sinsp_exception);

	/* children of p3_t1 are p4_t1 and p4_t2 we can reparent them to p1_t1 */
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 0, 0);

	auto p1_t1_tinfo = m_inspector.get_thread_ref(p1_t1_tid, false).get();
	p3_t1_tinfo->assign_children_to_reaper(p1_t1_tinfo);

	/* all p3_t1 children should be removed */
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 0, 0);

	/* the new parent should be p1_t1 */
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t1_tid, p4_t1_pid, p1_t1_tid, p4_t1_vtid, p4_t1_vpid);
	ASSERT_THREAD_INFO_PIDS_IN_CONTAINER(p4_t2_tid, p4_t2_pid, p1_t1_tid, p4_t2_vtid, p4_t2_vpid);

	ASSERT_THREAD_CHILDREN(p1_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);

	/* Another call to the reparenting function should do nothing */
	p3_t1_tinfo->assign_children_to_reaper(p1_t1_tinfo);
	ASSERT_THREAD_CHILDREN(p3_t1_tid, 0, 0);
	ASSERT_THREAD_CHILDREN(p1_t1_tid, 2, 2, p4_t1_tid, p4_t2_tid);
}

/*=============================== THREAD-INFO ===========================*/

/*=============================== PROC_EXIT ENTER EVENT ===========================*/

TEST_F(sinsp_with_test_input, THRD_STATE_parse_proc_exit_not_existent_thread)
{
	DEFAULT_TREE

	/* Before this proc exit init had 5 children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);

	/* Scaffolding needed to call the PPME_PROCEXIT_1_E */
	int64_t not_relevant_64 = 0;
	uint8_t not_relevant_8 = 0;

	/* we call the proc_exit event on a not existing thread */
	int64_t unknown_tid = 50000;
	auto evt = add_event_advance_ts(increasing_ts(), unknown_tid, PPME_PROCEXIT_1_E, 5, not_relevant_64,
					not_relevant_64, not_relevant_8, not_relevant_8, INIT_TID);

	/* The thread info associated with the event should be null and INIT should have the same number of children */
	ASSERT_FALSE(evt->get_thread_info());
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_proc_exit_no_children)
{
	DEFAULT_TREE

	/* Before this proc exit init had 5 children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);

	/* Scaffolding needed to call the PPME_PROCEXIT_1_E */
	int64_t not_relevant_64 = 0;
	uint8_t not_relevant_8 = 0;

	/* we call the proc_exit event on thread without children */
	add_event_advance_ts(increasing_ts(), p5_t1_tid, PPME_PROCEXIT_1_E, 5, not_relevant_64, not_relevant_64,
			     not_relevant_8, not_relevant_8, INIT_TID);

	/* INIT should have the same number of children */
	ASSERT_THREAD_CHILDREN(INIT_TID, 5, 5);

	/* After the PROC_EXIT event we still have the thread but it is marked as dead */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2);

	/* The reaper of p5_t1_tinfo should be always -1, p5_t1 has no children so we don't set it */
	auto p5_t1_tinfo = m_inspector.get_thread_ref(p5_t1_tid, false).get();
	ASSERT_TRUE(p5_t1_tinfo);
	ASSERT_EQ(p5_t1_tinfo->m_reaper_tid, -1);
	ASSERT_THREAD_INFO_FLAG(p5_t1_tid, PPM_CL_CLOSED, true);

	/* After the next event, nothing should change, p5_t1 is a main thread */
	add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_GETCWD_E, 0);
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_proc_exit_reaper_0)
{
	DEFAULT_TREE

	/* Scaffolding needed to call the PPME_PROCEXIT_1_E */
	int64_t not_relevant_64 = 0;
	uint8_t not_relevant_8 = 0;

	/* we call the proc_exit with a reaper equal to 0
	 * our userspace logic should be able to assign the right
	 * reaper even if the kernel one is missing.
	 */
	int64_t empty_reaper = 0;
	add_event_advance_ts(increasing_ts(), p5_t2_tid, PPME_PROCEXIT_1_E, 5, not_relevant_64, not_relevant_64,
			     not_relevant_8, not_relevant_8, empty_reaper);

	/* we don't remove the children from p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);

	/* After the PROC_EXIT event we still have the thread but it is marked as dead */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2);

	auto p5_t2_tinfo = m_inspector.get_thread_ref(p5_t2_tid, false).get();
	ASSERT_TRUE(p5_t2_tinfo);
	ASSERT_EQ(p5_t2_tinfo->m_reaper_tid, 0);
	ASSERT_THREAD_INFO_FLAG(p5_t2_tid, PPM_CL_CLOSED, true);

	/* After the next event, we should reparent p5_t2 children to p5_t1 */
	add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_GETCWD_E, 0);

	/* p5_t2 should be expired and the reaper flag should not be set */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 1);

	/* p5_t1 is the reaper */
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_proc_exit_negative_reaper)
{
	DEFAULT_TREE

	/* Scaffolding needed to call the PPME_PROCEXIT_1_E */
	int64_t not_relevant_64 = 0;
	uint8_t not_relevant_8 = 0;

	/* Same behavior we have with reaper 0 */
	int64_t negative_reaper = -1;
	add_event_advance_ts(increasing_ts(), p5_t2_tid, PPME_PROCEXIT_1_E, 5, not_relevant_64, not_relevant_64,
			     not_relevant_8, not_relevant_8, negative_reaper);

	/* we don't remove the children from p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);

	/* After the PROC_EXIT event we still have the thread but it is marked as dead */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2);

	auto p5_t2_tinfo = m_inspector.get_thread_ref(p5_t2_tid, false).get();
	ASSERT_TRUE(p5_t2_tinfo);
	ASSERT_EQ(p5_t2_tinfo->m_reaper_tid, -1);
	ASSERT_THREAD_INFO_FLAG(p5_t2_tid, PPM_CL_CLOSED, true);

	/* After the next event, we should reparent p5_t2 children to p5_t1 */
	add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_GETCWD_E, 0);

	/* p5_t2 should be expired and the reaper flag should not be set */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 1);

	/* p5_t1 is the reaper */
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_proc_exit_valid_reaper_in_the_same_group)
{
	DEFAULT_TREE

	/* Scaffolding needed to call the PPME_PROCEXIT_1_E */
	int64_t not_relevant_64 = 0;
	uint8_t not_relevant_8 = 0;

	add_event_advance_ts(increasing_ts(), p5_t2_tid, PPME_PROCEXIT_1_E, 5, not_relevant_64, not_relevant_64,
			     not_relevant_8, not_relevant_8, p5_t1_tid);

	/* we don't remove the children from p5_t2 */
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);

	/* After the PROC_EXIT event we still have the thread but it is marked as dead */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2);

	auto p5_t2_tinfo = m_inspector.get_thread_ref(p5_t2_tid, false).get();
	ASSERT_TRUE(p5_t2_tinfo);
	ASSERT_EQ(p5_t2_tinfo->m_reaper_tid, p5_t1_tid);
	ASSERT_THREAD_INFO_FLAG(p5_t2_tid, PPM_CL_CLOSED, true);

	/* After the next event, we should reparent p5_t2 children to p5_t1 */
	add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_GETCWD_E, 0);

	/* p5_t2 should be expired and the reaper flag should not be set */
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 1);

	/* p5_t1 is the reaper */
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_proc_exit_valid_reaper_in_another_group)
{
	DEFAULT_TREE

	/* Initially p2_t1 doesn't belong to a reaper group, but after the kernel tells us
	 * it is, we mark it.
	 */
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, false, 3, 3);
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 1, 1, p3_t1_tid);

	/* Scaffolding needed to call the PPME_PROCEXIT_1_E */
	int64_t not_relevant_64 = 0;
	uint8_t not_relevant_8 = 0;

	add_event_advance_ts(increasing_ts(), p5_t2_tid, PPME_PROCEXIT_1_E, 5, not_relevant_64, not_relevant_64,
			     not_relevant_8, not_relevant_8, p2_t1_tid);

	auto p5_t2_tinfo = m_inspector.get_thread_ref(p5_t2_tid, false).get();
	ASSERT_TRUE(p5_t2_tinfo);
	ASSERT_EQ(p5_t2_tinfo->m_reaper_tid, p2_t1_tid);

	/* After the next event, we should reparent p5_t2 children to p2_t1 */
	add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_GETCWD_E, 0);

	/* now p2_t1 group is a reaper since the kernel tells it */
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, true, 3, 3);
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 2, 2, p6_t1_tid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_proc_exit_not_existent_reaper)
{
	DEFAULT_TREE

	/* Scaffolding needed to call the PPME_PROCEXIT_1_E */
	int64_t not_relevant_64 = 0;
	uint8_t not_relevant_8 = 0;

	/* not existent reaper, our userspace logic should be able
	 * to assign the right reaper.
	 */
	int64_t unknonw_repaer_tid = 50000;
	add_event_advance_ts(increasing_ts(), p2_t1_tid, PPME_PROCEXIT_1_E, 5, not_relevant_64, not_relevant_64,
			     not_relevant_8, not_relevant_8, unknonw_repaer_tid);

	auto p2_t1_tinfo = m_inspector.get_thread_ref(p2_t1_tid, false).get();
	ASSERT_TRUE(p2_t1_tinfo);
	/* right now the reaper tid is `unknonw_repaer_tid` */
	ASSERT_EQ(p2_t1_tinfo->m_reaper_tid, unknonw_repaer_tid);
	ASSERT_THREAD_INFO_FLAG(p2_t1_tid, PPM_CL_CLOSED, true);

	/* After the next event, we should reparent p2_t1 children to p2_t2 */
	add_event_advance_ts(increasing_ts(), INIT_TID, PPME_SYSCALL_GETCWD_E, 0);

	/* p2_t1 is not expired since it is a main thread and the reaper flag should not be set */
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 2, false, 3, 3);
	p2_t1_tinfo = m_inspector.get_thread_ref(p2_t1_tid, false).get();
	ASSERT_TRUE(p2_t1_tinfo);
	/* The reaper tid should be changed */
	ASSERT_EQ(p2_t1_tinfo->m_reaper_tid, p2_t2_tid);

	/* During the process we create also an invalid thread with id `unknonw_repaer_tid` */
	auto unknonw_repaer_tinfo = m_inspector.get_thread_ref(unknonw_repaer_tid, false).get();
	ASSERT_TRUE(unknonw_repaer_tinfo);
	ASSERT_TRUE(unknonw_repaer_tinfo->is_invalid());
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_proc_exit_old_event)
{
	DEFAULT_TREE

	/* This version of proc_exit event doesn't have the reaper info */
	add_event_advance_ts(increasing_ts(), p5_t2_tid, PPME_PROCEXIT_E, 0);

	auto p5_t2_tinfo = m_inspector.get_thread_ref(p5_t2_tid, false).get();
	ASSERT_TRUE(p5_t2_tinfo);
	ASSERT_EQ(p5_t2_tinfo->m_reaper_tid, -1);
	ASSERT_THREAD_INFO_FLAG(p5_t2_tid, PPM_CL_CLOSED, true);
	ASSERT_EQ(m_inspector.m_tid_to_remove, p5_t2_tid);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_proc_exit_lost_event)
{
	DEFAULT_TREE

	/* Let's imagine we miss the exit event on p5_t2. At a certain point
	 * we will try to remove it.
	 */
	m_inspector.remove_thread(p5_t2_tid);

	/* Thanks to userspace logic p5_t1 should be the new reaper */
	ASSERT_THREAD_GROUP_INFO(p5_t1_tid, 1, false, 2, 1);
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p5_t2_tid, true);
}

TEST_F(sinsp_with_test_input, THRD_STATE_parse_proc_exit_complete_flow)
{
	DEFAULT_TREE

	/* p5_t1 has no children, when p5_t2 dies p5_t1 receives p6_t1 as child */
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 0, 0);
	ASSERT_THREAD_CHILDREN(p5_t2_tid, 1, 1, p6_t1_tid);
	remove_thread(p5_t2_tid, p5_t1_tid);
	ASSERT_THREAD_CHILDREN(p5_t1_tid, 1, 1, p6_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p5_t2_tid, true);

	remove_thread(p4_t2_tid, p4_t1_tid);
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 1, 1, p5_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p4_t2_tid, true);

	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, false, 3, 3);
	/* The kernel says that p2_t1 is a new reaper */
	remove_thread(p4_t1_tid, p2_t1_tid);
	ASSERT_THREAD_CHILDREN(p2_t1_tid, 2, 2, p5_t1_tid);
	ASSERT_MISSING_THREAD_INFO(p4_t1_tid, true);

	/* the reaper flag should be set */
	ASSERT_THREAD_GROUP_INFO(p2_t1_pid, 3, true, 3, 3);
}

/*=============================== PROC_EXIT ENTER EVENT ===========================*/

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
