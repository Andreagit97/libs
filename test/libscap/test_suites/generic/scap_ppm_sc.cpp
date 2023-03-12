
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

#include <scap.h>
#include <gtest/gtest.h>
#include <sys/syscall.h>

TEST(scap_ppm_sc, scap_get_tp_from_events)
{
	{
		/* Failure cases */
		uint8_t events_array[PPM_EVENT_MAX] = {0};
		uint8_t tp_array[TP_VAL_MAX] = {0};

		ASSERT_EQ(scap_get_tp_from_events(NULL, tp_array), SCAP_FAILURE);
		ASSERT_EQ(scap_get_tp_from_events(events_array, NULL), SCAP_FAILURE);
		ASSERT_EQ(scap_get_tp_from_events(NULL, NULL), SCAP_FAILURE);
	}

	{
		/* Check memset */
		uint8_t events_array[PPM_EVENT_MAX] = {0};
		uint8_t tp_array[TP_VAL_MAX] = {0};
		for(int i = 0; i < TP_VAL_MAX; i++)
		{
			tp_array[i] = 1;
		}
		ASSERT_EQ(scap_get_tp_from_events(events_array, tp_array), SCAP_SUCCESS);
		for(int i = 0; i < TP_VAL_MAX; i++)
		{
			ASSERT_FALSE(tp_array[i]);
		}
	}

	{
		/* All tp */
		uint8_t events_array[PPM_EVENT_MAX] = {0};
		uint8_t tp_array[TP_VAL_MAX] = {0};
		/* This causes addition of `SYS_ENTER`/`SYS_EXIT`/`SCHED_PROC_EXEC` */
		events_array[PPME_SYSCALL_EXECVE_8_E] = 1;
		/* This causes addition of `SYS_ENTER`/`SYS_EXIT`/`SCHED_PROC_FORK` */
		events_array[PPME_SYSCALL_CLONE_16_X] = 1;
		/* This causes addition of `PROC_EXIT` */
		events_array[PPME_PROCEXIT_E] = 1;
		/* This causes addition of `SCHED_SWITCH` */
		events_array[PPME_SCHEDSWITCH_1_E] = 1;
		/* This causes addition of `SIGNAL_DELIVER` */
		events_array[PPME_SIGNALDELIVER_E] = 1;
		/* This causes addition of `PAGE_USER`/`PAGE_KERNEL` */
		events_array[PPME_PAGE_FAULT_E] = 1;

		ASSERT_EQ(scap_get_tp_from_events(events_array, tp_array), SCAP_SUCCESS);

		/* All tp should be enabled */
		for(int i = 0; i < TP_VAL_MAX; i++)
		{
			ASSERT_TRUE(tp_array[i]);
		}
	}

	{
		/* Only SYS_ENTER/SYS_EXIT */
		uint8_t events_array[PPM_EVENT_MAX] = {0};
		uint8_t tp_array[TP_VAL_MAX] = {0};
		/* This causes addition of `SYS_ENTER`/`SYS_EXIT` */
		events_array[PPME_SYSCALL_CLOSE_E] = 1;

		ASSERT_EQ(scap_get_tp_from_events(events_array, tp_array), SCAP_SUCCESS);

		for(int i = 0; i < TP_VAL_MAX; i++)
		{
			switch(i)
			{
			case SYS_ENTER:
			case SYS_EXIT:
				ASSERT_TRUE(tp_array[i]);
				break;

			default:
				ASSERT_FALSE(tp_array[i]);
				break;
			}
		}
	}

    {
		uint8_t events_array[PPM_EVENT_MAX] = {0};
		uint8_t tp_array[TP_VAL_MAX] = {0};
		/* This causes addition of `SYS_ENTER`/`SYS_EXIT` */
		events_array[PPME_SYSCALL_CLOSE_E] = 1;

		ASSERT_EQ(scap_get_tp_from_events(events_array, tp_array), SCAP_SUCCESS);

		for(int i = 0; i < TP_VAL_MAX; i++)
		{
			switch(i)
			{
			case SYS_ENTER:
			case SYS_EXIT:
				ASSERT_TRUE(tp_array[i]);
				break;

			default:
				ASSERT_FALSE(tp_array[i]);
				break;
			}
		}
	}
}
