message(STATUS "Build scap example")

# Include `jsoncpp` library. This should be already set by sinsp.
include(jsoncpp RESULT_VARIABLE RESULT)
if(RESULT STREQUAL NOTFOUND)
    message(FATAL_ERROR "problem with jsoncpp.cmake in ${CMAKE_MODULE_PATH}")
endif()

set(SCAP_EXAMPLE_INCLUDE
  PRIVATE
  "${LIBSCAP_DIR}/userspace/libscap"
  "${LIBAUDIT_INCLUDE}"
  "${JSONCPP_INCLUDE}"
)

set(SCAP_EXAMPLE_SOURCES
    scap-example.cpp
    ${JSONCPP_LIB_SRC}
)

set(SCAP_EXAMPLE_LIBS
  scap
  "${JSONCPP_LIB}"
)

set(SCAP_EXAMPLE_DEPS
  scap
)

add_executable(scap-example ${SCAP_EXAMPLE_SOURCES})

target_include_directories(scap-example ${SCAP_EXAMPLE_INCLUDE})

target_link_libraries(scap-example ${SCAP_EXAMPLE_LIBS})

add_dependencies(scap-example ${SCAP_EXAMPLE_DEPS})
