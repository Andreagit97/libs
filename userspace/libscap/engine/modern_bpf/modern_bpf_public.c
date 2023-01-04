#include "modern_bpf_public.h"

const char *modern_bpf_buffer_mode_names[] = {
    [MODERN_PER_CPU_BUFFER] = MODERN_PER_CPU_BUFFER_NAME,
    [MODERN_PAIRED_BUFFER] = MODERN_PAIRED_BUFFER_NAME,
    [MODERN_SINGLE_BUFFER] = MODERN_SINGLE_BUFFER_NAME,
};

const char* get_modern_bpf_buffer_mode_name(enum modern_bpf_buffer_mode mode)
{
    return modern_bpf_buffer_mode_names[mode];
}
