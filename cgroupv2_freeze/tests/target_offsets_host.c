/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 在宿主上直接执行生产偏移代码；输入为选定 Image 与相对偏移符号表。
 * 这里只验证机器码窗口匹配，不执行任何目标内核函数，也不操作设备。
 */
#include <stdarg.h>
#include <stddef.h>
typedef long ssize_t;

#if defined(__APPLE__)
#define HOST_NAME(name) "_" name
#else
#define HOST_NAME(name) name
#endif

#include "../cgroupv2_freeze.h"
#include <linux/kernel.h>
#include <linux/printk.h>
#include "../../kpm_utils.h"
#include "../cfv2_utils.h"

/* 宿主 libc 转接只用于仪器 I/O；不引入宿主的 dev_t/mode_t 等定义，
 * 不替换任何生产结构体。别名避免与 SDK 的同名 kfunc 包装冲突。
 */
typedef void FILE;
extern FILE* host_fopen(const char*, const char*) __asm__(HOST_NAME("fopen"));
extern int host_fseek(FILE*, long, int) __asm__(HOST_NAME("fseek"));
extern long host_ftell(FILE*) __asm__(HOST_NAME("ftell"));
extern void host_rewind(FILE*) __asm__(HOST_NAME("rewind"));
extern size_t host_fread(void*, size_t, size_t, FILE*) __asm__(HOST_NAME("fread"));
extern int host_fclose(FILE*) __asm__(HOST_NAME("fclose"));
extern char* host_fgets(char*, int, FILE*) __asm__(HOST_NAME("fgets"));
extern int host_sscanf(const char*, const char*, ...) __asm__(HOST_NAME("sscanf"));
extern void* host_malloc(size_t) __asm__(HOST_NAME("malloc"));
extern char* host_strdup(const char*) __asm__(HOST_NAME("strdup"));
extern int host_strcmp(const char*, const char*) __asm__(HOST_NAME("strcmp"));
extern int host_strncmp(const char*, const char*, size_t) __asm__(HOST_NAME("strncmp"));
extern size_t host_strlen(const char*) __asm__(HOST_NAME("strlen"));
extern char* host_strstr(const char*, const char*) __asm__(HOST_NAME("strstr"));
extern void* host_memset(void*, int, size_t) __asm__(HOST_NAME("memset"));
extern int host_printf(const char*, ...) __asm__(HOST_NAME("printf"));
extern int host_vprintf(const char*, va_list) __asm__(HOST_NAME("vprintf"));
#define fopen host_fopen
#define fseek host_fseek
#define ftell host_ftell
#define rewind host_rewind
#define fread host_fread
#define fclose host_fclose
#define fgets host_fgets
#undef sscanf
#define sscanf host_sscanf
#define malloc host_malloc
#define strdup host_strdup
#define strcmp host_strcmp
#define strncmp host_strncmp
#define strlen host_strlen
#define strstr host_strstr
#define memset host_memset
#define printf host_printf
#define vprintf host_vprintf
#define SEEK_END 2

#define IZERO (1UL << 0x10)
#define UZERO (1UL << 0x20)

static void* css_task_iter_start;
static void* cgroup_kn_lock_live;
static void* cgroup_init_cftypes;
static void* kf_call_usermodehelper_exec;
static struct css_set* cfv2_init_css_set;
static struct cftype* cfv2_base_files;
static uint64_t css_task_iter_start_ver5 = UZERO, cgroup_kn_lock_live_ver5 = UZERO,
    cftype_ver5 = UZERO, cgroup_base_files_ver5 = UZERO;
struct struct_offset struct_offset = {
    .task_struct_state = -1, .css_set_dfl_cgrp = -1, .cgroup_kn = -1, .css_flags = -1};

struct symbol_entry {
  unsigned long offset;
  char* name;
};
static struct symbol_entry symbols[200000];
static size_t symbol_count, image_size;
static unsigned char* image;

/* 按输入名字返回镜像地址；name 为符号名，未找到或越界返回 0，不解引用 BSS。 */
unsigned long kallsyms_lookup_name_by_suffix(const char* name) {
  size_t len = strlen(name);
  for (size_t i = 0; i < symbol_count; i++) {
    const char* candidate = symbols[i].name;
    if ((!strcmp(candidate, name)
         || (!strncmp(candidate, name, len) && (candidate[len] == '$' || candidate[len] == '.')
             && !strstr(candidate + len, ".cfi")))
        && symbols[i].offset < image_size)
      return (unsigned long)(image + symbols[i].offset);
  }
  return 0;
}

/* 转接生产诊断；fmt/可变参数同 printf，无返回值，仅写宿主 stdout。 */
static void host_printk(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}
void (*printk)(const char* fmt, ...) = host_printk;

#include "../cfv2_offsets.c"

/* 装载指定只读输入，执行生产推导并与目标独立使用点参考值比较。
 * argv[3] 可为 negative，用全零替换本工具副本中的注册锚点窗口；返回 0 表示
 * 正例匹配或负例明确拒绝，其他返回值是宿主自检失败，不是设备测试结果。
 */
int main(int argc, char** argv) {
  if (argc < 3)
    return 2;
  FILE* input = fopen(argv[1], "rb");
  if (!input)
    return 2;
  fseek(input, 0, SEEK_END);
  long size = ftell(input);
  if (size <= 0 || size > 100000000)
    return 2;
  image_size = (size_t)size;
  image = malloc(image_size);
  if (!image)
    return 2;
  rewind(input);
  if (fread(image, 1, image_size, input) != image_size)
    return 2;
  fclose(input);
  input = fopen(argv[2], "r");
  if (!input)
    return 2;
  char line[2048], name[1024], kind;
  unsigned long offset;
  while (fgets(line, sizeof(line), input)) {
    if (sscanf(line, "%lx %c %1023s", &offset, &kind, name) != 3)
      continue;
    if (symbol_count >= sizeof(symbols) / sizeof(symbols[0]))
      return 2;
    symbols[symbol_count++] = (struct symbol_entry){offset, strdup(name)};
  }
  fclose(input);

  css_task_iter_start = (void*)kallsyms_lookup_name_by_suffix("css_task_iter_start");
  cgroup_kn_lock_live = (void*)kallsyms_lookup_name_by_suffix("cgroup_kn_lock_live");
  cgroup_init_cftypes = (void*)kallsyms_lookup_name_by_suffix("cgroup_init_cftypes");
  kf_call_usermodehelper_exec = (void*)kallsyms_lookup_name_by_suffix("call_usermodehelper_exec");
  unsigned char* initial = (void*)kallsyms_lookup_name_by_suffix("init_css_set");
  if (!css_task_iter_start || !cgroup_kn_lock_live || !cgroup_init_cftypes || !kf_call_usermodehelper_exec
      || !initial || initial + 128 > image + image_size)
    return 2;
  /* ELF 重定位未应用时数据指针为零；测试只把已知 dom_cset 自引用换成宿主
   * 地址，让生产代码可执行同一对象关系检查。0x40 来自该目标初始化器重定位，
   * 不写入生产偏移，不把宿主指针当作目标布局证据。
   */
  *(unsigned long*)(initial + 0x40) = (unsigned long)initial;
  bool negative = argc > 3 && !strcmp(argv[3], "negative");
  if (negative) {
    unsigned char* anchor = (void*)kallsyms_lookup_name_by_suffix("cgroup_path_ns_locked");
    if (!anchor || anchor + 0xa0 > image + image_size)
      return 2;
    memset(anchor, 0, 0xa0);
  }
  long rc = calculate_offsets();
  printf("calculate_offsets=%ld jobctl=%d signal=%d flags=%d state=%d seq.private=%d css_set.dfl=%d "
         "cgroup.flags=%d cgroup.kn=%d css.flags=%d sighand.siglock=%d\n", rc, struct_offset.task_struct_jobctl,
         struct_offset.task_struct_signal, struct_offset.task_struct_flags, struct_offset.task_struct_state,
         struct_offset.seq_file_private, struct_offset.css_set_dfl_cgrp, struct_offset.cgroup_flags,
         struct_offset.cgroup_kn, struct_offset.css_flags, struct_offset.sighand_siglock);
  if (negative)
    return rc < 0 ? 0 : 1;
  return rc || struct_offset.task_struct_jobctl != 1400 || struct_offset.task_struct_signal != 1992
      || struct_offset.task_struct_flags != 68 || struct_offset.task_struct_state != 48
      || struct_offset.seq_file_private != 120 || struct_offset.css_set_dfl_cgrp != 72
      || struct_offset.cgroup_flags != 184 || struct_offset.cgroup_kn != 232 || struct_offset.css_flags != 108
      || struct_offset.sighand_siglock != 2056;
}
