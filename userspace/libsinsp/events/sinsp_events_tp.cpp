/*
Copyright (C) 2022 The Falco Authors.

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

#include "sinsp_events.h"

libsinsp::events::set<ppm_tp_code> libsinsp::events::sinsp_state_tp_set()
{
	static libsinsp::events::set<ppm_tp_code> tp_of_interest;
	if (tp_of_interest.empty())
	{
		std::vector<uint8_t> tp_vec(TP_VAL_MAX);
		/* Should never happen but just to be sure. */
		if(scap_get_modifies_state_tracepoints(tp_vec.data()) != SCAP_SUCCESS)
		{
			throw sinsp_exception("'tp_of_interest' is an unexpected NULL vector!");
		}
		for (int i = 0; i < TP_VAL_MAX; i++)
		{
			if (tp_vec[i])
			{
				tp_of_interest.insert((ppm_tp_code)i);
			}
		}
	}
	return tp_of_interest;
}

libsinsp::events::set<ppm_tp_code> libsinsp::events::enforce_simple_tp_set(libsinsp::events::set<ppm_tp_code> tp_of_interest)
{
	auto sinsp_state_tp = sinsp_state_tp_set();
	return tp_of_interest.merge(sinsp_state_tp);
}

libsinsp::events::set<ppm_tp_code> libsinsp::events::all_tp_set()
{
	static libsinsp::events::set<ppm_tp_code> ppm_tp_set;
	if (ppm_tp_set.empty())
	{
		for(uint32_t tp = 0; tp < TP_VAL_MAX; tp++)
		{
			ppm_tp_set.insert((ppm_tp_code)tp);
		}
	}
	return ppm_tp_set;
}

std::unordered_set<std::string> libsinsp::events::tp_set_to_names(const libsinsp::events::set<ppm_tp_code>& tp_set)
{
	std::unordered_set<std::string> tp_names_set;
	for (const auto& val : tp_set)
	{
		std::string tp_name = tp_names[val];
		tp_names_set.insert(tp_name);
	}
	return tp_names_set;
}

libsinsp::events::set<ppm_tp_code> event_names_to_tp_set(const std::unordered_set<std::string>& event_names)
{
	libsinsp::events::set<ppm_event_code> event_set;
	
	/* Get event codes from names */
	for(const auto& event_name : event_names)
	{
		for(int ev = 0; ev < PPM_EVENT_MAX; ev++)
		{
			if(event_name.compare(scap_get_event_info_table()[ev].name) == 0)
			{
				event_set.insert((ppm_event_code)ev);
			}
		}
	}

	/* Use scap API to convert from event to tp set */
	std::vector<uint8_t> tp_vec(TP_VAL_MAX, 0);
	if(scap_get_tp_from_events(event_set.data(), tp_vec.data()) != SCAP_SUCCESS)
	{
		throw sinsp_exception("`event_set.data()` or `tp_vec` is an unexpected NULL vector!");
	}

	libsinsp::events::set<ppm_tp_code> tp_set;
	for (int i = 0; i < TP_VAL_MAX; i++)
	{
		if(tp_vec[i])
		{
			tp_set.insert((ppm_tp_code)i);
		}
	}
	return tp_set;
}
