/* SPDX-License-Identifier: GPL-2.0-only */
/* 实际 KP 分发 + 生产启动控制；激活函数仅作模型，不证明 Crypto、CFI 或设备行为。 */
#define HOOK_CHAIN_NUM 16
#define HOOK_NO_ERR 0
#define HOOK_DUPLICATED 4094
#define HOOK_CHAIN_FULL 4090
#define CHAIN_ITEM_STATE_EMPTY 0
#define CHAIN_ITEM_STATE_BUSY 2
#define CHAIN_ITEM_STATE_READY 1
#define dsb(scope) __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define logkv(...) ((void)0)
typedef int hook_err_t;
typedef void (*hook_chain4_callback)(hook_fargs4_t*, void*);
// 字段模型只供实际函数访问，不把宿主偏移当作 KP 二进制布局。
typedef struct {
  struct { uint64_t func_addr, relo_addr; } hook;
  int chain_items_max;
  int8_t states[HOOK_CHAIN_NUM];
  void* udata[HOOK_CHAIN_NUM];
  void* befores[HOOK_CHAIN_NUM];
  void* afters[HOOK_CHAIN_NUM];
} hook_chain_t;
static hook_chain_t boot_chain;
static int original_completed, rcu_depth, load_in_before, hook_queries, kernel_visible = 1;
static int activation_calls, before_calls, after_calls;
static long activation_result, first_load_rc, repeated_load_rc, ordinary_during_wait_rc;
static uint64_t original_result;

/* 无参数，返回本次宿主链；不用于证明原生链查找 ABI。 */
static hook_chain_t* current_inline_hook_chain(void) { return &boot_chain; }
/* HOOK_CHAIN_CODE */

static void* lookup(const char* name);
static uintptr_t kallsyms_lookup_name_by_suffix(const char* name) { return (uintptr_t)lookup(name); }
static int hook_wrap(void* func, int args, void* before, void* after, void* data);
static long zram_zstd_activate(void);
/* PRODUCTION_STARTUP */

/* 激活模型仅检查调用上下文并返回指定结果；不模拟通过真正的编解码或注册测试。 */
static long zram_zstd_activate(void) {
  assert(original_completed && !rcu_depth);
  activation_calls++;
  registered = !activation_result;
  return activation_result;
}
/* 原函数模型核对四参数并标记完成；返回指定值，不激活模块。 */
static uint64_t kernel_original(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
  assert(a == 11 && b == 22 && c == 33 && d == 44 && !rcu_depth);
  original_completed = 1;
  return original_result;
}
/* 实际 before 分发中加载并重入追加 after；早期不得调用激活函数。 */
static void foundation_before(hook_fargs4_t* args, void* data) {
  assert(!original_completed && !rcu_depth && !data);
  before_calls++;
  if (!load_in_before) return;
  first_load_rc = zram_zstd_init("", "pre-kernel-init", NULL);
  repeated_load_rc = zram_zstd_init("", "pre-kernel-init", NULL);
  ordinary_during_wait_rc = zram_zstd_init("", "post-kernel-init", NULL);
  assert(first_load_rc == 0 && repeated_load_rc == -EBUSY && ordinary_during_wait_rc == -EBUSY);
  assert(deferred_state == ZS_DEFER_WAITING && deferred_hook_installed && !activation_calls && !registered);
  assert(args->arg0 == 11 && args->arg3 == 44 && !args->skip_origin);
  assert(zram_zstd_exit(NULL) == 0 && deferred_state == ZS_DEFER_WAITING && boot_chain.chain_items_max == 2);
}
/* 模拟随后 KP 模块事件的 RCU 通知；激活已在另一 after 中结束，通知不触发激活。 */
static void foundation_after(hook_fargs4_t* args, void* data) {
  assert(original_completed && !data && args->ret == original_result);
  int old_calls = activation_calls;
  rcu_depth++;
  after_calls++;
  assert(deferred_state == ZS_DEFER_READY || deferred_state == ZS_DEFER_FAILED);
  assert(activation_calls == old_calls);
  rcu_depth--;
}
/* 查找只接受 kernel_init；其他名字会触发断言，禁止早期隐藏的 Crypto 查找。 */
static void* lookup(const char* name) {
  assert(!strcmp(name, "kernel_init"));
  return kernel_visible ? kernel_original : NULL;
}
/* 在既有链上调用实际 KP hook_chain_add，成功与满链均由原实现决定。 */
static int hook_wrap(void* func, int args, void* before, void* after, void* data) {
  assert(func == kernel_original && args == 4 && !before && after == zram_zstd_after_kernel_init && !data);
  assert(!original_completed && !rcu_depth);
  hook_queries++;
  return hook_chain_add(&boot_chain, before, after, data);
}
/* 模拟新 KPM 实例与已有 KP 基础 hook；重置夹具状态，不改变生产架构。 */
static void fresh(void) {
  memset(&boot_chain, 0, sizeof(boot_chain));
  boot_chain.hook.func_addr = (uintptr_t)kernel_original;
  boot_chain.hook.relo_addr = (uintptr_t)kernel_original;
  assert(hook_chain_add(&boot_chain, foundation_before, foundation_after, NULL) == 0);
  deferred_state = ZS_DEFER_IDLE;
  deferred_error = 0;
  deferred_hook_installed = registered = false;
  original_completed = rcu_depth = load_in_before = hook_queries = 0;
  kernel_visible = 1;
  activation_calls = before_calls = after_calls = 0;
  activation_result = first_load_rc = repeated_load_rc = ordinary_during_wait_rc = 0;
  original_result = 0;
}
/* 并发 after 入口返回 NULL；原子控制须保证仅一位调用者进入激活模型。 */
static void* concurrent_after(void* unused) {
  hook_fargs4_t args = {.ret = 0};
  zram_zstd_after_kernel_init(&args, NULL);
  assert(args.ret == 0 && !args.skip_origin);
  return NULL;
}
/* 执行真实重入分发及控制正反例，成功返回 0；不涉及外部资源或真机。 */
int main(void) {
  fresh();
  kernel_visible = 0;
  assert(zram_zstd_init("", "pre-kernel-init", NULL) == -ENOENT);
  assert(deferred_state == ZS_DEFER_IDLE && !deferred_hook_installed && !hook_queries && !activation_calls);

  fresh();
  for (unsigned int i = 1; i < HOOK_CHAIN_NUM; i++) boot_chain.states[i] = CHAIN_ITEM_STATE_READY;
  assert(zram_zstd_init("", "pre-kernel-init", NULL) == -HOOK_CHAIN_FULL);
  assert(deferred_state == ZS_DEFER_IDLE && !deferred_hook_installed && hook_queries == 1 && !activation_calls);

  fresh();
  load_in_before = 1;
  assert(_transit4(11, 22, 33, 44) == 0);
  assert(deferred_state == ZS_DEFER_READY && deferred_error == 0 && registered && deferred_hook_installed);
  assert(activation_calls == 1 && before_calls == 1 && after_calls == 1);
  assert(boot_chain.chain_items_max == 2 && hook_queries == 1);
  original_completed = 0;
  load_in_before = 0;
  assert(_transit4(11, 22, 33, 44) == 0 && activation_calls == 1);
  assert(zram_zstd_init("", "post-kernel-init", NULL) == -EBUSY);

  const long errors[] = {-ENOENT, -EIO, 0};
  for (unsigned int i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
    fresh();
    activation_result = errors[i];
    load_in_before = 1;
    assert(_transit4(11, 22, 33, 44) == 0);
    assert(deferred_error == errors[i] && deferred_state == (errors[i] ? ZS_DEFER_FAILED : ZS_DEFER_READY));
    assert(deferred_hook_installed && registered == !errors[i] && activation_calls == 1);
    assert(zram_zstd_exit(NULL) == 0 && boot_chain.chain_items_max == 2);
    hook_fargs4_t repeat = {.ret = 0};
    zram_zstd_after_kernel_init(&repeat, NULL);
    assert(activation_calls == 1 && deferred_error == errors[i]);
  }

  for (int mode = 0; mode < 3; mode++) {
    fresh();
    assert(zram_zstd_init("", "pre-kernel-init", NULL) == 0);
    hook_fargs4_t args = {.ret = mode == 1 ? 7 : mode == 2 ? (uint64_t)-EIO : 0, .skip_origin = mode == 0};
    uint64_t original_ret = args.ret;
    zram_zstd_after_kernel_init(&args, NULL);
    assert(deferred_state == ZS_DEFER_FAILED && deferred_error == -ECANCELED && deferred_hook_installed);
    assert(!activation_calls && args.ret == original_ret);
  }

  for (int failure = 0; failure < 2; failure++) {
    fresh();
    assert(zram_zstd_init("", "pre-kernel-init", NULL) == 0);
    original_completed = 1;
    activation_result = failure ? -EIO : 0;
    pthread_t threads[8];
    for (unsigned int i = 0; i < 8; i++) assert(!pthread_create(&threads[i], NULL, concurrent_after, NULL));
    for (unsigned int i = 0; i < 8; i++) assert(!pthread_join(threads[i], NULL));
    assert(activation_calls == 1 && deferred_state == (failure ? ZS_DEFER_FAILED : ZS_DEFER_READY));
    assert(deferred_error == activation_result);
  }

  fresh();
  original_completed = 1;
  assert(zram_zstd_init("", "post-kernel-init", NULL) == 0 && registered && activation_calls == 1);
  assert(deferred_state == ZS_DEFER_IDLE && !deferred_hook_installed && !hook_queries);
  puts("PASS: production startup controller + real KP reentrant before/after dispatch; no early activation");
  puts("PASS: missing target/full chain, duplicate/ordinary waiting, unchanged origin return and skipped origin");
  puts("PASS: single activation, late error/residency, eight-thread races, normal path; activation is modeled");
  return 0;
}
