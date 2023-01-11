#
# Copyright (C) 2023 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set(LIBSCAP_UNIT_TESTS_SOURCES
    scap_event.ut.cpp
)

set(LIBSCAP_UNIT_TESTS_INCLUDE
  PRIVATE
  "${GTEST_INCLUDE}"
  ${CMAKE_CURRENT_SOURCE_DIR} # for engine utils
  ${CMAKE_CURRENT_SOURCE_DIR}/.. # this is for scap includes
)

set(LIBSCAP_UNIT_TESTS_LIBRARIES
	"${GTEST_LIB}"
	"${GTEST_MAIN_LIB}"
	"${CMAKE_THREAD_LIBS_INIT}"
	scap
)

set(LIBSCAP_UNIT_TESTS_DEPENDENCIES
	gtest
	scap
)

set(RUN_LIBSCAP_UNIT_TESTS_DEPENDENCIES unit-test-libscap)

# Add `gcov` to needed libraries
if (CMAKE_BUILD_TYPE STREQUAL "Coverage")
	list(APPEND LIBSCAP_UNIT_TESTS_LIBRARIES gcov)
endif()

if(BUILD_DRIVER)
	file(GLOB_RECURSE KMOD_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/engines/kmod/*.cpp)
	list(APPEND RUN_LIBSCAP_UNIT_TESTS_DEPENDENCIES driver)
	list(APPEND LIBSCAP_UNIT_TESTS_SOURCES "${KMOD_TEST_SUITE}")
endif()

if(BUILD_BPF)
	file(GLOB_RECURSE BPF_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/engines/bpf/*.cpp)
	list(APPEND RUN_LIBSCAP_UNIT_TESTS_DEPENDENCIES bpf)
	list(APPEND LIBSCAP_UNIT_TESTS_SOURCES "${BPF_TEST_SUITE}")
endif()

if(BUILD_LIBSCAP_MODERN_BPF)
	file(GLOB_RECURSE MODERN_BPF_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/test_suites/engines/modern_bpf/*.cpp)
	list(APPEND LIBSCAP_UNIT_TESTS_SOURCES "${MODERN_BPF_TEST_SUITE}")
endif()

if(BUILD_LIBSCAP_GVISOR)
	include(protobuf)
	list(APPEND LIBSCAP_UNIT_TESTS_SOURCES scap_gvisor_parsers.ut.cpp)
	include_directories(${CMAKE_CURRENT_BINARY_DIR}/..)
	include_directories(../engine/gvisor)
	include_directories(${CMAKE_CURRENT_BINARY_DIR}/../engine/gvisor)
endif()

file(GLOB_RECURSE LIBSCAP_UNIT_TESTS_UTILS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/utils/*cpp)

list(APPEND LIBSCAP_UNIT_TESTS_SOURCES "${LIBSCAP_UNIT_TESTS_UTILS_SOURCES}")

find_package(Threads)

add_executable(unit-test-libscap ${LIBSCAP_UNIT_TESTS_SOURCES})
target_include_directories(unit-test-libscap ${LIBSCAP_UNIT_TESTS_INCLUDE})
target_link_libraries(unit-test-libscap ${LIBSCAP_UNIT_TESTS_LIBRARIES})
add_dependencies(unit-test-libscap ${LIBSCAP_UNIT_TESTS_DEPENDENCIES})

## Probably we can remove these
add_custom_target(run-unit-test-libscap
	DEPENDS "${RUN_LIBSCAP_UNIT_TESTS_DEPENDENCIES}"
	COMMAND unit-test-libscap
)
