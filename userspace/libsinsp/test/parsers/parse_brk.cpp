// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <sinsp_with_test_input.h>

TEST_F(sinsp_with_test_input, parse_brk) {
	add_default_init_thread();
	open_inspector();

	uint64_t res = 2808032;
	uint32_t vm_size = 294;
	uint32_t vm_rss = 295;
	uint32_t vm_swap = 296;
	uint64_t addr = 83983092;

	add_event_advance_ts(increasing_ts(),
	                     INIT_TID,
	                     PPME_SYSCALL_BRK,
	                     5,
	                     res,
	                     vm_size,
	                     vm_rss,
	                     vm_swap,
	                     addr);

	// Assert file descriptor presence
	sinsp_threadinfo* init_tinfo = m_inspector.get_thread_ref(INIT_TID, false, true).get();
	ASSERT_TRUE(init_tinfo);
	ASSERT_EQ(init_tinfo->m_vmsize_kb, vm_size);
	ASSERT_EQ(init_tinfo->m_vmrss_kb, vm_rss);
	ASSERT_EQ(init_tinfo->m_vmswap_kb, vm_swap);
}
