/* 指定 mefi 镜像的离线指纹；非结构体偏移表。 */
static struct fgp_site sites[] = {
  {.name = "sys_getpriority", .size = 544, .call_offset = 0xac, .fingerprint = 0x74952e81f69da19eULL},
  {.name = "sys_setpriority", .size = 800, .call_offset = 0xa8, .fingerprint = 0xe6fe33a32e1fec0aULL},
  {.name = "sys_ioprio_get", .size = 1080, .call_offset = 0x64, .fingerprint = 0xe59513b989880115ULL},
  {.name = "sys_ioprio_set", .size = 584, .call_offset = 0xac, .fingerprint = 0x1ca36a50cbc8557fULL},
};
#define FGP_LOADER_DELTA 0x15e10UL
#define FGP_LOADER_SIZE 0x1a0
#define FGP_LOADER_HASH 0x05ebc2e15093bdf2ULL
/* 以下帧和撤销契约来自本次 KP 字节，先核验后使用；不按版本号猜测。 */
#define FGP_TRANSIT4_DELTA (-0x3560L)
#define FGP_TRANSIT4_SIZE 0x118
#define FGP_TRANSIT4_HASH 0xd905df6f1739c80bULL
#define FGP_TRANSIT_SAVED_LR_BACK 0x40
#define FGP_CHAIN_TRANSIT_OFFSET 0x280
#define FGP_WRAP_SIZE 0x31c
#define FGP_WRAP_HASH 0x28cc4238f94780c0ULL
#define FGP_UNWRAP_SIZE 0x188
#define FGP_UNWRAP_HASH 0x4a0d3293bd67d619ULL
