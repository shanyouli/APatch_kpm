/* SPDX-License-Identifier: MIT */
/* 只读用户态探针：输出NMRD+长度+read字节+mmap字节；不接触内核布局。 */
#define __BITS_PER_LONG 64
#include "../../KernelPatch/kernel/linux/include/uapi/asm-generic/unistd.h"

#ifdef HOST_TEST
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#endif

static unsigned char buffer[65536];

/* 按AArch64 Linux ABI调用六参数syscall；返回原始值/负errno，无libc依赖。
 * HOST_TEST仅把同一业务逻辑适配到宿主系统调用，不用于真机结论。 */
static long raw6(long nr, long a0, long a1, long a2, long a3, long a4, long a5) {
#ifdef HOST_TEST
  long rc;
  switch (nr) {
  case __NR_openat: rc = open((const char*)a1, (int)a2); break;
  case __NR_read: rc = read((int)a0, (void*)a1, (unsigned long)a2); break;
  case __NR_write: rc = write((int)a0, (void*)a1, (unsigned long)a2); break;
  case __NR_close: rc = close((int)a0); break;
  case __NR_lseek: rc = lseek((int)a0, a1, (int)a2); break;
  case __NR_mmap: {
    void* addr = mmap((void*)a0, (unsigned long)a1, (int)a2, MAP_PRIVATE, (int)a4, a5);
    return addr == MAP_FAILED ? -errno : (long)addr;
  }
  case __NR_munmap: rc = munmap((void*)a0, (unsigned long)a1); break;
  default: return -EINVAL;
  }
  return rc < 0 ? -errno : rc;
#else
  register long x0 __asm__("x0") = a0, x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2, x3 __asm__("x3") = a3;
  register long x4 __asm__("x4") = a4, x5 __asm__("x5") = a5;
  register long x8 __asm__("x8") = nr;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
  return x0;
#endif
}

/* 向fd完整写出data/count，处理短写；成功0，错误返回负值，不重试其他操作。 */
static long put(long fd, const unsigned char* data, unsigned long count) {
  while (count) {
    long n = raw6(__NR_write, fd, (long)data, (long)count, 0, 0, 0);
    if (n <= 0) return n ? n : -5;
    data += n;
    count -= (unsigned long)n;
  }
  return 0;
}

/* 将失败stage写到stderr，返回1；不回退到普通读取冒充映射成功。 */
static int failure(const char* stage) {
  unsigned long n = 0;
  while (stage[n]) n++;
  put(2, (const unsigned char*)stage, n);
  put(2, (const unsigned char*)" failed\n", 8);
  return 1;
}

/* 记录实际探针的UID与SELinux域，必须为UID2000/shell；成功0，失败1。
 * HOST_TEST只验证协议/读取逻辑，不模拟Android身份，故跳过本段。 */
static int credentials(void) {
#ifndef HOST_TEST
  long uid = raw6(__NR_getuid, 0, 0, 0, 0, 0, 0);
  if (uid != 2000) return failure("probe UID");
  put(2, (const unsigned char*)"uid=2000\ncontext=", 17);
  long fd = raw6(__NR_openat, -100, (long)"/proc/self/attr/current", 0, 0, 0, 0);
  if (fd < 0) return failure("probe domain open");
  unsigned char context[128];
  long n = raw6(__NR_read, fd, (long)context, sizeof(context), 0, 0, 0);
  raw6(__NR_close, fd, 0, 0, 0, 0, 0);
  if (n <= 0) return failure("probe domain read");
  put(2, context, (unsigned long)n);
  put(2, (const unsigned char*)"\n", 1);
  const char* expected = "u:r:shell:s0";
  for (unsigned int i = 0; expected[i]; i++)
    if (i >= (unsigned long)n || context[i] != (unsigned char)expected[i]) return failure("probe domain");
#endif
  return 0;
}

/* 打开path只读，要求恰好64KiB，执行一次read和PROT_READ/MAP_PRIVATE。
 * 输出二进制证据供宿主逐字节比较；成功0，失败1；不写测试文件或试图写映射。 */
static int probe(const char* path) {
  if (credentials()) return 1;
  long fd = raw6(__NR_openat, -100, (long)path, 0, 0, 0, 0);
  if (fd < 0) return failure("open");
  long size = raw6(__NR_lseek, fd, 0, 2, 0, 0, 0);
  if (size != (long)sizeof(buffer) || raw6(__NR_lseek, fd, 0, 0, 0, 0, 0) != 0) {
    raw6(__NR_close, fd, 0, 0, 0, 0, 0);
    return failure("size/seek");
  }
  unsigned long got = 0;
  while (got < sizeof(buffer)) {
    long n = raw6(__NR_read, fd, (long)(buffer + got), sizeof(buffer) - got, 0, 0, 0);
    if (n <= 0) {
      raw6(__NR_close, fd, 0, 0, 0, 0, 0);
      return failure("read");
    }
    got += (unsigned long)n;
  }
  const unsigned char header[8] = {'N','M','R','D',0,0,1,0};
  if (put(1, header, sizeof(header)) || put(1, buffer, sizeof(buffer))) {
    raw6(__NR_close, fd, 0, 0, 0, 0, 0);
    return failure("read evidence");
  }
  long addr = raw6(__NR_mmap, 0, sizeof(buffer), 1, 2, fd, 0);
  if ((unsigned long)addr >= (unsigned long)-4095L) {
    raw6(__NR_close, fd, 0, 0, 0, 0, 0);
    return failure("mmap");
  }
  long result = put(1, (const unsigned char*)addr, sizeof(buffer));
  long unmap = raw6(__NR_munmap, addr, sizeof(buffer), 0, 0, 0, 0);
  long close = raw6(__NR_close, fd, 0, 0, 0, 0, 0);
  return result || unmap || close ? failure("mapped evidence/unmap/close") : 0;
}

#ifdef HOST_TEST
/* 宿主逻辑测试入口：argc/argv仅接受一个文件路径，返回probe状态。 */
int main(int argc, char** argv) {
  return argc == 2 ? probe(argv[1]) : failure("arguments");
}
#else
/* Linux初始栈入口：sp[0]=argc、随后argv，执行并以状态退出；绝不返回加载器。 */
__attribute__((used, noreturn)) void probe_entry(long* sp) {
  int status = sp[0] == 2 ? probe((const char*)sp[2]) : failure("arguments");
  raw6(__NR_exit, status, 0, 0, 0, 0, 0);
  for (;;) {}
}
/* 裸入口仅传入初始SP，不在C序言改栈后猜argv；由probe_entry终止进程。 */
__attribute__((naked, used, noreturn)) void _start(void) {
  __asm__ volatile("mov x0, sp\nbl probe_entry\n");
}
#endif
