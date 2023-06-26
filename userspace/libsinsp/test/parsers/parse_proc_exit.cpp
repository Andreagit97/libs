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

/*=============================== PROC EXIT EVENT ===========================*/

TEST_F(sinsp_with_test_input, PROC_EXIT_non_existing_thread)
{
	add_default_init_thread();
	open_inspector();
	int64_t unknown_tid = 100;

	/* Here we don't care about the reaper value, nothing should happen */
	remove_thread(unknown_tid, -1);
	remove_thread(unknown_tid, 12);
}

TEST_F(sinsp_with_test_input, PROC_EXIT_check_dead_thread_is_not_a_reaper)
{
	DEFAULT_TREE

	/* Remove p5_t1, it is the main thread and it is only marked as dead
	 * Using `-1` we are saying to use our userspace logic to find the reaper.
	 */
	remove_thread(p5_t1_tid, -1);
	ASSERT_THREAD_GROUP_INFO(p5_t1_pid, 1, false, 2, 2, p5_t2_tid)
	ASSERT_THREAD_INFO_FLAG(p5_t1_tid, PPM_CL_CLOSED, true);

	/* Remove p5_t2
	 * p5_t1 is marked as dead so it shouldn't be considered as a reaper.
	 */
	remove_thread(p5_t2_tid, -1);
	ASSERT_THREAD_CHILDREN(p4_t1_tid, 1, 1, p6_t1_tid)
}


/*=============================== PROC EXIT EVENT ===========================*/
