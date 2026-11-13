/* SPDX-License-Identifier: GPL-2.0-only */
#include <cache.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/zstd.h>

#include "../kpm_utils.h"
#include "upstream/lz4/lz4.h"
#include "upstream/lz4kd/lz4kd.h"
#include "zs_native.h"
#include "zs_structs.h"
#include "zs_zstd_config.h"

KPM_NAME("zram_zstd");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_INFO(zstd_version, "1.5.7", 16);
KPM_INFO(lz4_version, LZ4_VERSION_STRING, 16);
KPM_INFO(lz4kd_version, "2022.03.20", 16);
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("ZSTD, LZ4 and LZ4KD for zram. Deferred boot initialization; DO NOT UNLOAD.");
#ifdef CONFIG_KPM_BASELINES
KPM_INFO(offset_mode, "static", 16);
#else
KPM_INFO(offset_mode, "dynamic", 16);
#endif

#define logkm(fmt, ...) printk("zram_zstd: " fmt, ##__VA_ARGS__)
#define CRYPTO_ALG_TYPE_COMPRESS 2
#define CRYPTO_ALG_TYPE_MASK 15

struct zstd_ctx {
  ZSTD_CCtx* cctx;
  ZSTD_DCtx* dctx;
  void* cwksp;
  void* dwksp;
};

static unsigned char zstd_alg[1024] __attribute__((aligned(128)));
static unsigned char lz4_alg[1024] __attribute__((aligned(128)));
static unsigned char lz4kd_alg[1024] __attribute__((aligned(128)));
static bool registered;
// 仅跟踪早期嵌入路径；普通加载仍沿用 Crypto API 的名字冲突检查。
enum zs_deferred_state { ZS_DEFER_IDLE, ZS_DEFER_WAITING, ZS_DEFER_INITIALIZING, ZS_DEFER_READY, ZS_DEFER_FAILED };
static int deferred_state;
static long deferred_error;
static bool deferred_hook_installed;
// 注册前取得一次；0 表示页大小未确认，两个前端只读取此缓存。
static unsigned int zs_page_size;
#define ZS_CODEC_COUNT 3
static bool algorithm_registered[ZS_CODEC_COUNT];

#define ZS_ZSTD_NAME "zstd-kpm"
#define ZS_LZ4_NAME "lz4-kpm"
#define ZS_LZ4KD_NAME "lz4kd-kpm"

static int kfunc_def(crypto_has_alg)(const char* name, u32 type, u32 mask);
static int kfunc_def(crypto_register_alg)(void* alg);
static void* kfunc_def(vzalloc)(unsigned long size);
static void kfunc_def(vfree)(const void* ptr);

#include "zs_display.c"
#include "zs_offsets.c"

static struct zstd_ctx* zstd_context(struct crypto_tfm* tfm) {
  return (struct zstd_ctx*)((uintptr_t)tfm + struct_offset.crypto_tfm_ctx);
}

static void zstd_release(struct zstd_ctx* ctx) {
  if (ctx->cwksp)
    kfunc(vfree)(ctx->cwksp);
  if (ctx->dwksp)
    kfunc(vfree)(ctx->dwksp);
  ctx->cwksp = NULL;
  ctx->dwksp = NULL;
}

// 与原生 crypto/zstd 一致：level=3、未知输入大小取得显式参数。
static ZSTD_parameters zstd_params(void) { return ZSTD_getParams(3, 0, 0); }

static int zstd_prepare(struct zstd_ctx* ctx) {
  ZSTD_parameters params = zstd_params();
  size_t csize = ZSTD_estimateCCtxSize_usingCParams(params.cParams);
  size_t dsize = ZSTD_estimateDCtxSize();
  if (zs_zstd_is_error(csize) || zs_zstd_is_error(dsize))
    return -EINVAL;
  ctx->cwksp = kfunc(vzalloc)(csize);
  ctx->dwksp = kfunc(vzalloc)(dsize);
  if (!ctx->cwksp || !ctx->dwksp) {
    zstd_release(ctx);
    return -ENOMEM;
  }
  ctx->cctx = ZSTD_initStaticCCtx(ctx->cwksp, csize);
  ctx->dctx = ZSTD_initStaticDCtx(ctx->dwksp, dsize);
  if (!ctx->cctx || !ctx->dctx) {
    zstd_release(ctx);
    return -EINVAL;
  }
  return 0;
}

static int zstd_init(struct crypto_tfm* tfm) { return zstd_prepare(zstd_context(tfm)); }

static void zstd_exit(struct crypto_tfm* tfm) { zstd_release(zstd_context(tfm)); }

static size_t zstd_encode(ZSTD_CCtx* cctx, void* dst, size_t capacity, const void* src, size_t size) {
  ZSTD_parameters params = zstd_params();
  size_t rc = ZSTD_CCtx_reset(cctx, ZSTD_reset_session_and_parameters);
  if (zs_zstd_is_error(rc))
    return rc;
  rc = ZSTD_CCtx_setPledgedSrcSize(cctx, size);
  if (zs_zstd_is_error(rc))
    return rc;
  // 批量 API 写入与原生逐字段 setter 相同的七项压缩参数和三项 frame 参数。
  rc = ZSTD_CCtx_setParams(cctx, params);
  if (zs_zstd_is_error(rc))
    return rc;
  return ZSTD_compress2(cctx, dst, capacity, src, size);
}

static int zstd_compress(struct crypto_tfm* tfm, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  struct zstd_ctx* ctx = zstd_context(tfm);
  size_t size = zstd_encode(ctx->cctx, dst, *dlen, src, slen);
  if (zs_zstd_is_error(size))
    return -EINVAL;
  *dlen = size;
  return 0;
}

static int zstd_decompress(struct crypto_tfm* tfm, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  struct zstd_ctx* ctx = zstd_context(tfm);
  size_t size = ZSTD_decompressDCtx(ctx->dctx, dst, *dlen, src, slen);
  if (zs_zstd_is_error(size))
    return -EINVAL;
  *dlen = size;
  return 0;
}

static long codec_check(void) {
  struct zstd_ctx ctx = {0};
  int rc = zstd_prepare(&ctx);
  if (rc)
    return rc;
  unsigned char* pages = kfunc(vzalloc)(4096 * 4);
  if (!pages) {
    zstd_release(&ctx);
    return -ENOMEM;
  }
  for (unsigned int i = 0; i < 4096; i++) pages[i] = i % 251;
  size_t size = zstd_encode(ctx.cctx, pages + 4096, 8192, pages, 4096);
  if (zs_zstd_is_error(size)) {
    rc = -EINVAL;
  } else {
    size_t decoded = ZSTD_decompressDCtx(ctx.dctx, pages + 12288, 4096, pages + 4096, size);
    if (decoded != 4096 || memcmp(pages, pages + 12288, 4096))
      rc = -EINVAL;
  }
  kfunc(vfree)(pages);
  zstd_release(&ctx);
  logkm("codec check=%d\n", rc);
  return rc;
}

// LZ4块间没有字典状态；仅压缩哈希表需要工作区，避免把约16 KiB放在内核栈上。
struct lz4_ctx {
  void* workspace;
};

static struct lz4_ctx* lz4_context(struct crypto_tfm* tfm) {
  return (struct lz4_ctx*)((uintptr_t)tfm + struct_offset.crypto_tfm_ctx);
}

static int lz4_prepare(struct lz4_ctx* ctx) {
  ctx->workspace = kfunc(vzalloc)(LZ4_sizeofState());
  return ctx->workspace ? 0 : -ENOMEM;
}

static void lz4_release(struct lz4_ctx* ctx) {
  kfunc(vfree)(ctx->workspace);
  ctx->workspace = NULL;
}

static int lz4_encode(struct lz4_ctx* ctx, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  if (slen > LZ4_MAX_INPUT_SIZE || *dlen > 0x7fffffffU)
    return -EINVAL;
  int size = LZ4_compress_fast_extState(ctx->workspace, (const char*)src, (char*)dst, slen, *dlen, 1);
  if (!size)
    return -EINVAL;
  *dlen = size;
  return 0;
}

static int lz4_init(struct crypto_tfm* tfm) { return lz4_prepare(lz4_context(tfm)); }
static void lz4_exit(struct crypto_tfm* tfm) { lz4_release(lz4_context(tfm)); }
static int lz4_compress(struct crypto_tfm* tfm, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  return lz4_encode(lz4_context(tfm), src, slen, dst, dlen);
}

static int lz4_decompress(struct crypto_tfm* tfm, const u8* src, unsigned int slen, u8* dst, unsigned int* dlen) {
  if (slen > 0x7fffffffU || *dlen > 0x7fffffffU)
    return -EINVAL;
  int size = LZ4_decompress_safe((const char*)src, (char*)dst, slen, *dlen);
  if (size < 0)
    return -EINVAL;
  *dlen = size;
  return 0;
}

#include "zs_lz4kd.c"

struct zs_algorithm {
  const char* name;
  unsigned char* storage;
  unsigned int ctxsize;
  int (*compress)(struct crypto_tfm*, const u8*, unsigned int, u8*, unsigned int*);
  int (*decompress)(struct crypto_tfm*, const u8*, unsigned int, u8*, unsigned int*);
  int (*init)(struct crypto_tfm*);
  void (*exit)(struct crypto_tfm*);
};

static const struct zs_algorithm algorithms[] = {
    {ZS_ZSTD_NAME, zstd_alg, sizeof(struct zstd_ctx), zstd_compress, zstd_decompress, zstd_init, zstd_exit},
    {ZS_LZ4_NAME, lz4_alg, sizeof(struct lz4_ctx), lz4_compress, lz4_decompress, lz4_init, lz4_exit},
    {ZS_LZ4KD_NAME, lz4kd_alg, sizeof(struct lz4kd_ctx), lz4kd_compress, lz4kd_decompress, lz4kd_init, lz4kd_exit},
};

#include "zs_native.c"

static int prepare_algorithm(const struct zs_algorithm* codec) {
  size_t len = strlen(codec->name) + 1;
  int name_size = struct_offset.crypto_alg_driver_name - struct_offset.crypto_alg_name;
  if (len > name_size)
    return -EINVAL;
  unsigned char* storage = codec->storage;
  memset(storage, 0, sizeof(zstd_alg));
  struct zs_crypto_alg_prefix* alg = (struct zs_crypto_alg_prefix*)storage;
  alg->cra_flags = CRYPTO_ALG_TYPE_COMPRESS;
  alg->cra_ctxsize = codec->ctxsize;
  memcpy(storage + struct_offset.crypto_alg_name, codec->name, len);
  memcpy(storage + struct_offset.crypto_alg_driver_name, codec->name, len);
  struct zs_compress_alg* compress = (struct zs_compress_alg*)(storage + struct_offset.crypto_alg_compress);
  compress->coa_compress = codec->compress;
  compress->coa_decompress = codec->decompress;
  struct zs_alg_lifecycle* lifecycle = (struct zs_alg_lifecycle*)(storage + struct_offset.crypto_alg_init);
  lifecycle->cra_init = codec->init;
  lifecycle->cra_exit = codec->exit;
  // cra_module保持NULL；KPM不属于原生LKM，成功注册后必须常驻。
  return 0;
}

// 内核 TTBR1 的页粒度；TG1=0 是保留编码，不套用 4 KiB 默认值。
static unsigned int zs_detect_page_size(void) {
  unsigned int tg1 = (read_tcr(1) >> 30) & 3;
  return tg1 == 2 ? 4096U : tg1 == 1 ? 16384U : tg1 == 3 ? 65536U : 0;
}

/* 完成库自检和 Crypto 注册；无参数，返回初始化结果，只能在允许睡眠的上下文执行。 */
static long zram_zstd_activate(void) {
  kfunc_lookup_name(crypto_has_alg);
  if (!kfunc(crypto_has_alg))
    return -ENOENT;
  for (unsigned int i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
    if (kfunc(crypto_has_alg)(algorithms[i].name, CRYPTO_ALG_TYPE_COMPRESS, CRYPTO_ALG_TYPE_MASK)) {
      logkm("%s already available; skip loading\n", algorithms[i].name);
      return -EEXIST;
    }
  }
  kfunc_lookup_name(crypto_register_alg);
  kfunc_lookup_name(vzalloc);
  if (!kfunc(vzalloc)) {
    // Target vmalloc.h maps vzalloc(size) to this same-ABI allocation entry.
    kfunc(vzalloc) = (typeof(kfunc(vzalloc)))kallsyms_lookup_name_by_suffix("vzalloc_noprof");
    if (kfunc(vzalloc))
      logkm("allocator: vzalloc_noprof\n");
  }
  kfunc_lookup_name(vfree);
  if (!kfunc(crypto_register_alg) || !kfunc(vzalloc) || !kfunc(vfree)) {
    logkm("required helpers missing: crypto_register_alg=%d vzalloc=%d vfree=%d\n", !!kfunc(crypto_register_alg),
          !!kfunc(vzalloc), !!kfunc(vfree));
    return -ENOENT;
  }
  long rc = calculate_offsets();
  if (rc)
    return rc;
  rc = codec_check();
  if (rc)
    return rc;
  for (unsigned int i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
    rc = prepare_algorithm(&algorithms[i]);
    if (rc)
      return rc;
  }
  zs_page_size = zs_detect_page_size();
  if (zs_page_size != ZS_LZ4KD_BLOCK)
    logkm("page size=%u (0=unknown); skip %s, requires 4 KiB\n", zs_page_size, ZS_LZ4KD_NAME);
  // 首项失败时尚未公开资源，可以拒载；一旦注册成功，模块必须常驻。
  for (unsigned int i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
    if (i == 2 && zs_page_size != ZS_LZ4KD_BLOCK)
      continue;
    rc = kfunc(crypto_register_alg)(algorithms[i].storage);
    if (rc) {
      logkm("registration failed for %s: %ld\n", algorithms[i].name, rc);
      if (!registered)
        return rc;
      continue;
    }
    algorithm_registered[i] = true;
    registered = true;
  }
  // 注册即公开callback。旧Crypto API注销不会等待活跃transform，不能用回滚释放KPM。
  // 后续算法注册失败时保持关闭，显示层只发布真正可选的名字。
  start_zram_display();
  logkm("registration: %s=%d (ZSTD 1.5.7), %s=%d (LZ4 " LZ4_VERSION_STRING
        "), %s=%d (LZ4KD %s, max 4 KiB). DO NOT UNLOAD\n",
        ZS_ZSTD_NAME, algorithm_registered[0], ZS_LZ4_NAME, algorithm_registered[1], ZS_LZ4KD_NAME,
        algorithm_registered[2], lz4kd_version());
  return 0;
}

/* kernel_init 的 after 回调：args 是原始调用帧，udata 不使用；不改原返回值。
 * 此接入点由 KP 的普通 hook 链调用，不在模块事件通知的 RCU 读侧内；只允许一个调用者激活。
 * hook 成功后始终常驻，即使晚期初始化失败，也不能让加载器释放仍被链表引用的代码。
 */
static void zram_zstd_after_kernel_init(hook_fargs4_t* args, void* udata) {
  int expected = ZS_DEFER_WAITING;
  if (!__atomic_compare_exchange_n(&deferred_state, &expected, ZS_DEFER_INITIALIZING, false, __ATOMIC_ACQ_REL,
                                   __ATOMIC_ACQUIRE))
    return;
  long rc = args->skip_origin || args->ret ? -ECANCELED : zram_zstd_activate();
  __atomic_store_n(&deferred_error, rc, __ATOMIC_RELEASE);
  __atomic_store_n(&deferred_state, rc ? ZS_DEFER_FAILED : ZS_DEFER_READY, __ATOMIC_RELEASE);
  logkm("deferred init=%ld after kernel_init; DO NOT UNLOAD\n", rc);
}

/* 在真正的 pre-kernel-init 嵌入阶段追加返回后回调；无参数，成功表示等待而非算法已注册。
 * 该阶段在 kernel_init 的 before 链中串行执行，追加完成后原函数才开始；不调用 Crypto 或库分配器。
 * 查找/安装失败时尚未公开模块资源，返回错误并允许加载器释放本实例。
 */
static long zram_zstd_defer(void) {
  int expected = ZS_DEFER_IDLE;
  if (!__atomic_compare_exchange_n(&deferred_state, &expected, ZS_DEFER_WAITING, false, __ATOMIC_ACQ_REL,
                                   __ATOMIC_ACQUIRE))
    return -EBUSY;
  void* target = (void*)kallsyms_lookup_name_by_suffix("kernel_init");
  long rc = target ? hook_wrap(target, 4, NULL, zram_zstd_after_kernel_init, NULL) : -ENOENT;
  if (rc) {
    __atomic_store_n(&deferred_state, ZS_DEFER_IDLE, __ATOMIC_RELEASE);
    logkm("deferred hook unavailable: %ld\n", rc);
    return rc;
  }
  deferred_hook_installed = true;
  logkm("waiting for kernel_init return; algorithms not registered yet; DO NOT UNLOAD\n");
  return 0;
}

/* KPM 加载入口：args/reserved 沿用接口但不消费；event 决定早期等待或普通初始化。
 * 返回 0 可能仅表示等待，必须以最终注册日志与 /proc/crypto 判定激活；等待实例不能另行初始化。
 */
static long zram_zstd_init(const char* args, const char* event, void* reserved) {
  if (event && !strcmp(event, "pre-kernel-init"))
    return zram_zstd_defer();
  if (__atomic_load_n(&deferred_state, __ATOMIC_ACQUIRE) != ZS_DEFER_IDLE)
    return -EBUSY;
  return zram_zstd_activate();
}

static long zram_zstd_ctl0(const char* args, char __user* out_msg, int outlen) {
  static const char reply[] = "_(._.)_";
  if (!out_msg || outlen < (int)sizeof(reply))
    return -EINVAL;
  return compat_copy_to_user(out_msg, reply, sizeof(reply)) == sizeof(reply) ? 0 : -EFAULT;
}

/* 退出接口只记录常驻警告；reserved 不使用，返回 0 不表示允许热卸载。
 * 已发布的 Crypto 回调或早期 hook 均持有模块字节，本入口不注销、不撤回在途回调。
 */
static long zram_zstd_exit(void* reserved) {
  if (registered || deferred_hook_installed)
    logkm("DO NOT UNLOAD: crypto or boot hook may retain module callbacks\n");
  return 0;
}

KPM_INIT(zram_zstd_init);
KPM_CTL0(zram_zstd_ctl0);
KPM_EXIT(zram_zstd_exit);
