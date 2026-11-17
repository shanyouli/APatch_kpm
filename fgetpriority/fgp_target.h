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
