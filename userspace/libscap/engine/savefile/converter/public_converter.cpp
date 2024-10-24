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
#include <converter/conversion_types.h>

extern conversion_result call_conversion(scap_evt *new_evt, scap_evt *evt_to_convert, char *error);

extern "C" conversion_result scap_convert_event(scap_evt *new_evt,
                                                scap_evt *evt_to_convert,
                                                char *error) {
	return call_conversion(new_evt, evt_to_convert, error);
}
