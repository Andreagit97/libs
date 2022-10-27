include_directories(${LIBSCAP_INCLUDE_DIRS} ../noop)
add_library(scap_engine_bpf scap_bpf.c)
if(NOT MINIMAL_BUILD)
    include(libelf)

    # With `BUNDLED_DEPS`, we enforce the usage of a static library
    if(USE_BUNDLED_LIBELF)
        add_dependencies(scap_engine_bpf libelf)
    endif()
    target_link_libraries(scap_engine_bpf scap_event_schema scap_engine_util ${LIBELF_LIB})
    target_include_directories(scap_engine_bpf PRIVATE ${LIBELF_INCLUDE})

target_link_libraries(scap_engine_bpf scap_event_schema scap_engine_util ${LIBELF})
endif()
