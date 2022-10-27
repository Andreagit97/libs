#
# LIBELF
#
option(USE_BUNDLED_LIBELF "Enable building of the bundled libelf" ${USE_BUNDLED_DEPS})

if(LIBELF_INCLUDE)
    # we already have LIBELF
elseif(NOT USE_BUNDLED_LIBELF)
    find_library(LIBELF_LIB NAMES elf)
    if(LIBELF_LIB)
        message(STATUS "Found LIBELF: include: ${LIBELF_INCLUDE}, lib: ${LIBELF_LIB}")
    else()
        message(FATAL_ERROR "Couldn't find system libelf")
    endif()
else()
    set(LIBELF_SRC "${PROJECT_BINARY_DIR}/libelf-prefix/src")
    set(LIBELF_INCLUDE "${LIBELF_SRC}/libelf/libelf")
    set(LIBELF_LIB "${LIBELF_SRC}/libelf/libelf/libelf.a")
    ExternalProject_Add(
            libelf
            PREFIX "${PROJECT_BINARY_DIR}/libelf-prefix"
            URL "https://sourceware.org/elfutils/ftp/0.187/elfutils-0.187.tar.bz2"
            #URL_HASH "SHA256=3d6afde67682c909e341bf194678a8969f17628705af25f900d5f68bd299cb03"
            CONFIGURE_COMMAND ./configure --libdir=${LIBELF_LIB} --includedir=${LIBELF_INCLUDE} --sysconfdir=/etc --program-prefix="eu-" --enable-deterministic-archives --disable-debuginfod --disable-libdebuginfod
            BUILD_IN_SOURCE 1
            BUILD_COMMAND ${CMD_MAKE}
            INSTALL_COMMAND ""
            UPDATE_COMMAND ""
    )
    message(STATUS "Using bundled libelf: include'${LIBELF_INCLUDE}', lib: ${LIBELF_LIB}")
    install(FILES "${LIBELF_LIB}" DESTINATION "${CMAKE_INSTALL_LIBDIR}/${LIBS_PACKAGE_NAME}"
            COMPONENT "libs-deps")
    install(DIRECTORY "${LIBELF_INCLUDE}" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${LIBS_PACKAGE_NAME}"
            COMPONENT "libs-deps")
endif()

include_directories(${LIBELF_INCLUDE})
