set(PMAN_SOURCES
    src/capture.c
    src/maps.c
    src/lifecycle.c
    src/programs.c
    src/ringbuffer.c
    src/configuration.c
    src/events_prog_names.c
    src/state.c
)

set(PMAN_PRIVATE_INCLUDES
    "${ZLIB_INCLUDES}"
    "${LIBBPF_INCLUDE}"
    "${SKEL_DIR}"
    "${LIBSCAP_DIR}/driver/" ## ppm_enum and tables
    "${LIBSCAP_DIR}/userspace/libscap" ## scap-stats struct
    "${LIBSCAP_DIR}/driver/modern_bpf/" ## bpf-shared structs
)

set(PMAN_PUBLIC_INCLUDES
    "./include"
)

set(PMAN_PRIVATE_LINK_LIBRARIES
    "${LIBBPF_LIB}"
    "${ZLIB_LIB}"
    scap_event_schema
    ${LIBELF}
)

set(PMAN_DEPENDENCIES
    ProbeSkeleton
)

if(USE_BUNDLED_LIBBPF)
    list(APPEND
        PMAN_DEPENDENCIES
        libbpf
    )
endif()

add_library(pman ${PMAN_SOURCES})

# With `BUNDLED_DEPS`, we enforce the usage of a static library
if(USE_BUNDLED_LIBELF)
    add_dependencies(pman libelf)
endif()

target_include_directories(pman
    INTERFACE
    ${PMAN_PUBLIC_INCLUDES}
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${PMAN_PRIVATE_INCLUDES}
    ${LIBELF_INCLUDE}
)

target_link_libraries(pman
    PRIVATE
    ${PMAN_PRIVATE_LINK_LIBRARIES}
    ${LIBELF_LIB}
)

add_dependencies(pman ${PMAN_DEPENDENCIES})
