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

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <driver/ppm_events_public.h>
#include <libscap/scap_assert.h>

struct extract_value_t
{
	uint8_t* ptr = nullptr;
	uint32_t len = 0;
};

class extract_modifier
{
public:
	enum mod_type
	{
		MOD_TOUPPER = 0,
		MOD_TOLOWER = 1,
		MOD_BASE64 = 2,
	};

	void apply_mod(std::vector<extract_value_t>&, ppm_param_type&);

	extract_modifier(mod_type t): m_mod_type(t){};
	virtual ~extract_modifier() = default;

private:
	mod_type m_mod_type;
	std::vector<std::string> m_modified_string_values;

	void string_modifier(std::vector<extract_value_t>& vec, ppm_param_type t,
			     std::function<void(std::string&)> mod);

	inline std::string mod_name() const
	{
		switch(m_mod_type)
		{
		case MOD_TOUPPER:
			return "toupper()";

		case MOD_TOLOWER:
			return "tolower()";

		case MOD_BASE64:
			return "base64()";

		default:
			break;
		}
		ASSERT(false);
		return "unknown";
	}
};
