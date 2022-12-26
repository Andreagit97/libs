#
# libaudit
#
option(USE_BUNDLED_LIBAUDIT "Enable building of the bundled libaudit" ${USE_BUNDLED_DEPS})

# This first case means that we have already included one time `libaudit` so we have
# already created a cmake target
if(LIBAUDIT_INCLUDE AND LIBAUDIT_LIB)
	message(STATUS "Using libaudit: include: ${LIBAUDIT_INCLUDE}, lib: ${LIBAUDIT_LIB}")
elseif(NOT USE_BUNDLED_LIBAUDIT)
    find_path(LIBAUDIT_INCLUDE libaudit.h)
    find_library(LIBAUDIT_LIB NAMES audit)
    if(LIBAUDIT_INCLUDE AND LIBAUDIT_LIB)
        message(STATUS "Found system libaudit: include: ${LIBAUDIT_INCLUDE}, lib: ${LIBAUDIT_LIB}")
    else()
        message(FATAL_ERROR "Couldn't find system libaudit")
    endif()
    add_custom_target(libaudit)
else()
    # todo build it from source
    find_path(LIBAUDIT_INCLUDE libaudit.h)
    find_library(LIBAUDIT_LIB NAMES audit)
    if(LIBAUDIT_INCLUDE AND LIBAUDIT_LIB)
        message(STATUS "Found system libaudit: include: ${LIBAUDIT_INCLUDE}, lib: ${LIBAUDIT_LIB}")
    else()
        message(FATAL_ERROR "Couldn't find system libaudit")
    endif()
    add_custom_target(libaudit)
endif()
