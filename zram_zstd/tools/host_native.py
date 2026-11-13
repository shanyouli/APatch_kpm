"""Host adapters for ARM64 hook frames and typed assembly entries; no production assertions are replaced."""
NATIVE_ENTRIES = ('compress', 'decompress', 'create_zstd', 'create_lz4', 'create_lz4kd', 'destroy',
                  'setup_zstd', 'setup_lz4', 'setup_lz4kd', 'release')


def native_source(module, source):
    # Only the privileged register read is modeled; production TG1 decoding stays intact.
    source = source.replace('#include <cache.h>', 'static uint64_t read_tcr(uint32_t el);')
    aliases = '\n'.join(f'#define zs_native_{name} zs_native_{name}_impl' for name in NATIVE_ENTRIES)
    source = source.replace('#include "zs_native.h"', aliases + '\n' + (module / 'zs_native.h').read_text())
    source = source.replace('#include "zs_native.c"', (module / 'zs_native.c').read_text())
    return source.replace('#include "zs_native_btf.c"', (module / 'zs_native_btf.c').read_text())


def hook_frame(source, native_fixture=False):
    """为宿主夹具提供 SDK 四参数调用帧及 unwrap 桩，返回生成源码，不替换业务断言。"""
    frame = ('typedef struct { void* chain; int skip_origin; uint64_t local[8]; uint64_t ret; '
             'uint64_t arg0, arg1, arg2, arg3; } hook_fargs4_t;\n'
             'typedef hook_fargs4_t hook_fargs2_t;')
    source = source.replace('typedef struct { uint64_t arg0, arg1, ret; } hook_fargs2_t;', frame)
    stub = 'static void hook_unwrap(void* func, void* before, void* after);\n'
    if not native_fixture:
        stub = 'static void hook_unwrap(void* func, void* before, void* after) { __builtin_trap(); }\n'
    return stub + source
