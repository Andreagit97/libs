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

#include <libsinsp/extract_modifier/extract_modifier.h>
#include <sinsp_exception.h>
#include <algorithm>

// Taken from
// https://github.com/ReneNyffenegger/cpp-base64/blob/07ae5045d67b5bf6ffb46646b8ac2370eff1ae3e/base64.cpp#L111
static const char* base64_chars[2] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				      "abcdefghijklmnopqrstuvwxyz"
				      "0123456789"
				      "+/",

				      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				      "abcdefghijklmnopqrstuvwxyz"
				      "0123456789"
				      "-_"};

// todo!: probably here we just want the url version with the `-_`
static std::string base64_encode(unsigned char const* bytes_to_encode, size_t in_len, bool url)
{

	size_t len_encoded = (in_len + 2) / 3 * 4;

	unsigned char trailing_char = url ? '.' : '=';

	//
	// Choose set of base64 characters. They differ
	// for the last two positions, depending on the url
	// parameter.
	// A bool (as is the parameter url) is guaranteed
	// to evaluate to either 0 or 1 in C++ therefore,
	// the correct character set is chosen by subscripting
	// base64_chars with url.
	//
	const char* base64_chars_ = base64_chars[url];

	std::string ret;
	ret.reserve(len_encoded);

	unsigned int pos = 0;

	while(pos < in_len)
	{
		ret.push_back(base64_chars_[(bytes_to_encode[pos + 0] & 0xfc) >> 2]);

		if(pos + 1 < in_len)
		{
			ret.push_back(base64_chars_[((bytes_to_encode[pos + 0] & 0x03) << 4) +
						    ((bytes_to_encode[pos + 1] & 0xf0) >> 4)]);

			if(pos + 2 < in_len)
			{
				ret.push_back(base64_chars_[((bytes_to_encode[pos + 1] & 0x0f) << 2) +
							    ((bytes_to_encode[pos + 2] & 0xc0) >> 6)]);
				ret.push_back(base64_chars_[bytes_to_encode[pos + 2] & 0x3f]);
			}
			else
			{
				ret.push_back(base64_chars_[(bytes_to_encode[pos + 1] & 0x0f) << 2]);
				ret.push_back(trailing_char);
			}
		}
		else
		{

			ret.push_back(base64_chars_[(bytes_to_encode[pos + 0] & 0x03) << 4]);
			ret.push_back(trailing_char);
			ret.push_back(trailing_char);
		}

		pos += 3;
	}

	return ret;
}

void extract_modifier::string_modifier(std::vector<extract_value_t>& vec, ppm_param_type t,
				       std::function<void(std::string&)> mod)
{

	switch(t)
	{
	// todo!: not sure we want to use it on paths
	case PT_CHARBUF:
	case PT_BYTEBUF:
	case PT_FSPATH:
	case PT_FSRELPATH:
		break;

	default:
		throw sinsp_exception("type '" + std::to_string(t) + "' is not supported by '" + mod_name() +
				      "' operator");
	}

	m_modified_string_values.clear();
	for(std::size_t i = 0; i < vec.size(); i++)
	{
		if(vec[i].ptr != nullptr)
		{
			auto tmp_string = std::string((char*)vec[i].ptr);
			mod(tmp_string);
			m_modified_string_values.push_back(std::move(tmp_string));
			vec[i].ptr = (uint8_t*)m_modified_string_values[i].c_str();
			vec[i].len = m_modified_string_values[i].size();
		}
	}
}

void extract_modifier::apply_mod(std::vector<extract_value_t>& vec, ppm_param_type& t)
{
	switch(m_mod_type)
	{

	case MOD_TOUPPER:
	{
		string_modifier(vec, t,
				[](std::string& s) { std::transform(s.begin(), s.end(), s.begin(), ::toupper); });
		return;
	}

	case MOD_TOLOWER:
	{
		string_modifier(vec, t,
				[](std::string& s) { std::transform(s.begin(), s.end(), s.begin(), ::tolower); });
		return;
	}

	case MOD_BASE64:
	{
		string_modifier(
			vec, t,
			[](std::string& s)
			{ s = base64_encode(reinterpret_cast<const unsigned char*>(s.c_str()), s.size(), true); });
		// As output we probably want to use `PT_CHARBUF`
		t = PT_CHARBUF;
		return;
	}

	default:
		throw sinsp_exception("modifier '" + std::to_string(m_mod_type) + "' is not supported");
	}
}
