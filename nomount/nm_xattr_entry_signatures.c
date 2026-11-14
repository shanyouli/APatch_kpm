/* SPDX-License-Identifier: GPL-2.0-only */
/* 真实plain2删除入口与syscall内部list入口；不按版本选择原型。 */
enum {
  NM_XATTR_REMOVE_WORDS = 29,
  NM_XATTR_REMOVE_LOCKED_WORDS = 16,
  NM_XATTR_REMOVE_SECURITY_WORDS = 9,
  NM_XATTR_INTERNAL_LIST_WORDS = 25,
  NM_XATTR_LIST_SECURITY_WORDS = 9,
  NM_XATTR_INLINE_REMOVE_WORDS = 50,
  NM_XATTR_INLINE_LIST_WORDS = 40
};

/* 核对src的内联permission/security/remove二参入口，layout/helpers绑定源锁。
 * 固定50条含通知后的解锁；返回0/负错误，不调用任何原生函数或省略通知路径。
 */
static int nm_find_xattr_inline_remove2(const uint32_t* src, unsigned count, const struct nm_setattr_layout* layout,
                                       const uintptr_t helpers[4], uintptr_t permission, uintptr_t security,
                                       uintptr_t remove, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_INLINE_REMOVE_WORDS || !layout || layout->context || layout->lock_kind != 1)
    return -EOPNOTSUPP;
  for (unsigned i = 0; i < 4; i++)
    if (!nm_xattr_signature_frame(src[i]))
      return -EOPNOTSUPP;
  if (!nm_load_at(src[4], 19, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_move(src[5], 20, 0)
      || !nm_movz_value(src[6], 0, 2, 2) || !nm_move(src[7], 21, 1) || !nm_move(src[8], 0, 19)
      || !nm_xattr_signature_call(&src[9], permission, start, end) || !nm_move32(src[10], 22, 0)
      || !inst_is_cbnz(src[11]) || inst_get_cbnz_sf(src[11]) || inst_get_cbnz_rt(src[11])
      || inst_get_cbnz_label(src[11]) != 156 || !nm_add_at(src[12], 19, 19, layout->lock_offset)
      || !nm_move(src[13], 0, 19) || !nm_xattr_signature_call(&src[14], helpers[0], start, end))
    return -EOPNOTSUPP;
  const unsigned calls[] = {17, 22};
  const uintptr_t targets[] = {security, remove};
  for (unsigned i = 0; i < 2; i++) {
    unsigned call = calls[i];
    if (!nm_move(src[call - 2], 0, 20) || !nm_move(src[call - 1], 1, 21)
        || !nm_xattr_signature_call(&src[call], targets[i], start, end) || !nm_move32(src[call + 1], 22, 0)
        || !inst_is_cbnz(src[call + 2]) || inst_get_cbnz_sf(src[call + 2]) || inst_get_cbnz_rt(src[call + 2])
        || inst_get_cbnz_label(src[call + 2]) != (48 - (int)(call + 2)) * 4)
      return -EOPNOTSUPP;
  }
  if (!nm_move(src[48], 0, 19) || !nm_xattr_signature_call(&src[49], helpers[1], start, end))
    return -EOPNOTSUPP;
  int kind = 0, offset = nm_find_inode_lock(src, count, 0, helpers, start, end, &kind);
  return offset < 0 ? offset : offset == layout->lock_offset && kind == layout->lock_kind ? 0 : -EINVAL;
}

static int nm_find_xattr_remove2(const uint32_t* src, unsigned int count, const struct nm_setattr_layout* layout,
                                 const uintptr_t helpers[4], uintptr_t locked, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_REMOVE_WORDS || !layout || layout->context || layout->lock_kind != 1)
    return -EOPNOTSUPP;
  for (unsigned int i = 0; i < 7; i++)
    if (!nm_vfs_frame_save(src[i]))
      return -EOPNOTSUPP;
  int kind = 0, offset = nm_find_inode_lock(src, count, 0, helpers, start, end, &kind);
  if (offset < 0)
    return offset;
  if (offset != layout->lock_offset || kind != layout->lock_kind)
    return -EINVAL;
  if (!inst_is_adrp(src[7]) || inst_get_adrp_rd(src[7]) != 8 || !nm_move(src[8], 19, 1) || !nm_move(src[9], 20, 0)
      || !nm_load(src[10], 3, 8) || inst_get_ldr_imm_rt(src[10]) != 8 || !nm_store_at(src[11], 3, 8, 31, 8)
      || !nm_load_at(src[12], 23, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_store_at(src[13], 3, 31, 31, 0)
      || !inst_is_b(src[14]) || inst_get_b_label(src[14]) != 24 || !nm_add_at(src[20], 0, 23, offset)
      || !nm_add_at(src[22], 2, 31, 0) || !nm_move(src[23], 0, 20) || !nm_move(src[24], 1, 19)
      || !nm_xattr_signature_call(&src[25], locked, start, end))
    return -EOPNOTSUPP;
  return 0;
}

static int nm_find_xattr_remove_locked(const uint32_t* src, unsigned int count, uintptr_t permission,
                                       uintptr_t security, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_REMOVE_LOCKED_WORDS)
    return -EINVAL;
  for (unsigned int i = 0; i < 5; i++)
    if (!nm_vfs_frame_save(src[i]))
      return -EOPNOTSUPP;
  if (!nm_load_at(src[5], 22, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_move(src[6], 21, 2)
      || !nm_move(src[7], 19, 0) || !inst_is_movz_imm(src[8]) || inst_get_movz_imm_sf(src[8])
      || inst_get_movz_imm_hw(src[8]) || inst_get_movz_imm_rd(src[8]) != 2 || inst_get_movz_imm_imm16(src[8]) != 2
      || !nm_move(src[9], 20, 1) || !nm_move(src[10], 0, 22)
      || !nm_xattr_signature_call(&src[11], permission, start, end) || !inst_is_cbnz(src[12])
      || inst_get_cbnz_sf(src[12]) || inst_get_cbnz_rt(src[12]) || inst_get_cbnz_label(src[12]) != 20
      || !nm_move(src[13], 0, 19) || !nm_move(src[14], 1, 20)
      || !nm_xattr_signature_call(&src[15], security, start, end))
    return -EOPNOTSUPP;
  return 0;
}

// 两个security入口有相同的dentry→inode→S_PRIVATE前部，跳转距离由目标分别确认。
static int nm_find_xattr_security_pair(const uint32_t* src, unsigned int count, int branch) {
  if (!src || count != 9)
    return -EINVAL;
  for (unsigned int i = 0; i < 6; i++)
    if (!nm_vfs_frame_save(src[i]))
      return -EOPNOTSUPP;
  return nm_load_at(src[6], 8, 0, offsetof(struct nm_dentry_head, d_inode)) && nm_load(src[7], 0, 8)
                 && inst_get_ldr_imm_rt(src[7]) == 8
                 && inst_get_ldr_imm_imm(src[7]) == offsetof(struct nm_inode_owner_prefix, i_flags) + 1
                 && inst_is_tbnz(src[8]) && inst_get_tbnz_rt(src[8]) == 8 && inst_get_tbnz_bit(src[8]) == 1
                 && inst_get_tbnz_label(src[8]) == branch
             ? 0
             : -EOPNOTSUPP;
}

/* 根据context/layout确认原生删除ABI；旧locked见证不变，新内联二参用独立完整锁链。
 * 返回0或负错误，不按版本或缺helper直接猜签名，不执行删除。
 */
static int calculate_function_xattr_remove(int context, const struct nm_setattr_layout* layout) {
  if (context || !layout || (struct_offset.permission_abi != 0 && struct_offset.permission_abi != 1))
    return -EOPNOTSUPP;
  uintptr_t start = kallsyms_lookup_name("_stext"), end = kallsyms_lookup_name("_etext");
  const uint32_t* entry = (const void*)nm_xattr_signature_body(kallsyms_lookup_name_by_suffix("vfs_removexattr"),
                                                             NM_XATTR_REMOVE_WORDS, start, end);
  if (entry && nm_add_at(entry[3], 29, 31, 0)
      && nm_load_at(entry[4], 19, 0, offsetof(struct nm_dentry_head, d_inode)) && nm_move(entry[5], 20, 0)) {
    const char* inline_names[] = {"vfs_removexattr", "security_inode_removexattr", "xattr_permission",
                                  "__vfs_removexattr", "down_write", "up_write"};
    const unsigned inline_words[] = {50, 8, 2, 2, 2, 2};
    uintptr_t body[6];
    for (unsigned i = 0; i < 6; i++) {
      body[i] = nm_xattr_signature_body(kallsyms_lookup_name_by_suffix(inline_names[i]), inline_words[i], start, end);
      if (!body[i])
        return -ENOENT;
      for (unsigned j = 0; j < i; j++)
        if (body[i] == body[j])
          return -EINVAL;
    }
    uintptr_t helpers[4] = {body[4], body[5], 0, 0};
    int rc = nm_find_xattr_inline_remove2((const void*)body[0], 50, layout, helpers, body[2], body[1], body[3], start, end);
    if (!rc)
      rc = nm_find_xattr_inline_security((const void*)body[1], 8, 5, 160);
    if (!rc)
      nm_log_info("layout: removexattr inline plain2, source lock + permission/security/remove witnesses\n");
    return rc;
  }
  const char* names[] = {
      "vfs_removexattr", "__vfs_removexattr_locked", "security_inode_removexattr", "xattr_permission", "down_write",
      "up_write"};
  const unsigned int words[] = {
      NM_XATTR_REMOVE_WORDS, NM_XATTR_REMOVE_LOCKED_WORDS, NM_XATTR_REMOVE_SECURITY_WORDS, 2, 2, 2};
  uintptr_t bodies[6];
  for (unsigned int i = 0; i < 6; i++) {
    bodies[i] = nm_xattr_signature_body(kallsyms_lookup_name_by_suffix(names[i]), words[i], start, end);
    if (!bodies[i])
      return -ENOENT;
    for (unsigned int j = 0; j < i; j++)
      if (bodies[i] == bodies[j])
        return -EINVAL;
  }
  uintptr_t helpers[4] = {bodies[4], bodies[5], 0, 0};
  int rc = nm_find_xattr_remove2((const void*)bodies[0], words[0], layout, helpers, bodies[1], start, end);
  if (!rc)
    rc = nm_find_xattr_remove_locked((const void*)bodies[1], words[1], bodies[3], bodies[2], start, end);
  if (!rc)
    rc = nm_find_xattr_security_pair((const void*)bodies[2], words[2], 144);
  if (!rc)
    nm_log_info("layout: removexattr plain2/dentry arg0, lock + permission/security witnesses\n");
  return rc;
}

// x0=dentry、x1=user buffer、x2=size；零长度支路保留NULL内核buffer并继续原生查询。
static int nm_find_xattr_internal_list(const uint32_t* src, unsigned int count, uintptr_t allocation,
                                       uintptr_t security, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_INTERNAL_LIST_WORDS)
    return -EINVAL;
  for (unsigned int i = 0; i < 6; i++)
    if (!nm_vfs_frame_save(src[i]))
      return -EOPNOTSUPP;
  if (!nm_move(src[6], 20, 1) || !nm_move(src[7], 21, 0) || !inst_is_cbz(src[8]) || !inst_get_cbz_sf(src[8])
      || inst_get_cbz_rt(src[8]) != 2 || inst_get_cbz_label(src[8]) != 48 || !inst_is_subs_imm(src[9])
      || !inst_get_subs_imm_sf(src[9]) || inst_get_subs_imm_rd(src[9]) != 31 || inst_get_subs_imm_rn(src[9]) != 2
      || inst_get_subs_imm_imm(src[9]) != 65536 || !inst_is_movz_imm(src[10]) || inst_get_movz_imm_sf(src[10])
      || inst_get_movz_imm_rd(src[10]) != 8 || inst_get_movz_imm_hw(src[10]) != 1
      || inst_get_movz_imm_imm16(src[10]) != 1 || !inst_is_movz_imm(src[11]) || inst_get_movz_imm_sf(src[11])
      || inst_get_movz_imm_rd(src[11]) != 1 || inst_get_movz_imm_hw(src[11]) || inst_get_movz_imm_imm16(src[11]) != 0xc0
      || !inst_is_csel(src[12]) || !inst_get_csel_sf(src[12]) || inst_get_csel_rd(src[12]) != 22
      || inst_get_csel_rn(src[12]) != 2 || inst_get_csel_rm(src[12]) != 8 || inst_get_csel_cond(src[12]) != 3
      || !inst_is_movk_imm(src[13]) || inst_get_movk_imm_sf(src[13]) || inst_get_movk_imm_rd(src[13]) != 1
      || inst_get_movk_imm_hw(src[13]) != 1 || inst_get_movk_imm_imm16(src[13]) != 0x60 || !inst_is_movn_imm(src[14])
      || inst_get_movn_imm_sf(src[14]) || inst_get_movn_imm_rd(src[14]) != 2 || inst_get_movn_imm_hw(src[14])
      || inst_get_movn_imm_imm16(src[14]) || !nm_move(src[15], 0, 22)
      || !nm_xattr_signature_call(&src[16], allocation, start, end) || !inst_is_cbz(src[17])
      || !inst_get_cbz_sf(src[17]) || inst_get_cbz_rt(src[17]) || inst_get_cbz_label(src[17]) != 236
      || !nm_move(src[18], 19, 0) || !inst_is_b(src[19]) || inst_get_b_label(src[19]) != 12 || !nm_zero64(src[20], 22)
      || !nm_zero64(src[21], 19) || !nm_load_at(src[22], 23, 21, offsetof(struct nm_dentry_head, d_inode))
      || !nm_move(src[23], 0, 21) || !nm_xattr_signature_call(&src[24], security, start, end))
    return -EOPNOTSUPP;
  return 0;
}

/* 从src的ADRP/ADD取得静态对象地址，仅验证rd及64位构造，不解引用；失败0。
 * 此地址只作同一LSM hook head的两个具名使用点交叉验证，不推导对象尺寸。
 */
static uintptr_t nm_xattr_static_address(const uint32_t* src, int rd) {
  return nm_page_address(src, rd) ? ((uintptr_t)src & ~(uintptr_t)4095) + inst_get_adrp_label(src[0])
                                  + inst_get_add_imm_imm(src[1]) : 0;
}

/* 核对listxattr三参入口的分配长度、原始用户buffer和内联LSM dentry来源。
 * src固定40条止于首个LSM调用；security为具名独立LSM入口，allocation绑定kvmalloc_node。
 * 成功0/缺证据负错误，不执行LSM或分配，不用最低寄存器号推测额外参数。
 */
static int nm_find_xattr_inline_list3(const uint32_t* src, unsigned count, uintptr_t allocation,
                                     const uint32_t* security, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_INLINE_LIST_WORDS || !security)
    return -EINVAL;
  for (unsigned i = 0; i < 7; i++)
    if (!nm_xattr_signature_frame(src[i]))
      return -EOPNOTSUPP;
  if (!nm_move(src[7], 20, 1) || !nm_move(src[8], 22, 0) || !inst_is_cbz(src[9]) || !inst_get_cbz_sf(src[9])
      || inst_get_cbz_rt(src[9]) != 2 || inst_get_cbz_label(src[9]) != 48 || !inst_is_subs_imm(src[10])
      || !inst_get_subs_imm_sf(src[10]) || inst_get_subs_imm_rd(src[10]) != 31 || inst_get_subs_imm_rn(src[10]) != 2
      || inst_get_subs_imm_imm(src[10]) != 65536 || !inst_is_movz_imm(src[11]) || inst_get_movz_imm_sf(src[11])
      || inst_get_movz_imm_rd(src[11]) != 8 || inst_get_movz_imm_hw(src[11]) != 1 || inst_get_movz_imm_imm16(src[11]) != 1
      || !inst_is_csel(src[12]) || !inst_get_csel_sf(src[12]) || inst_get_csel_rd(src[12]) != 21
      || inst_get_csel_rn(src[12]) != 2 || inst_get_csel_rm(src[12]) != 8 || inst_get_csel_cond(src[12]) != 3
      || !nm_movz_value(src[13], 0, 1, 0xc0) || !inst_is_movk_imm(src[14]) || inst_get_movk_imm_sf(src[14])
      || inst_get_movk_imm_rd(src[14]) != 1 || inst_get_movk_imm_hw(src[14]) != 1
      || inst_get_movk_imm_imm16(src[14]) != 0x140 || !inst_is_movn_imm(src[15]) || inst_get_movn_imm_sf(src[15])
      || inst_get_movn_imm_rd(src[15]) != 2 || inst_get_movn_imm_hw(src[15]) || inst_get_movn_imm_imm16(src[15])
      || !nm_move(src[16], 0, 21) || !nm_xattr_signature_call(&src[17], allocation, start, end)
      || !inst_is_cbz(src[18]) || !inst_get_cbz_sf(src[18]) || inst_get_cbz_rt(src[18]) || inst_get_cbz_label(src[18]) != 348
      || !nm_move(src[19], 19, 0) || !inst_is_b(src[20]) || inst_get_b_label(src[20]) != 12
      || !nm_zero64(src[21], 21) || !nm_zero64(src[22], 19)
      || !nm_load_at(src[23], 23, 22, offsetof(struct nm_dentry_head, d_inode)) || !nm_load(src[24], 0, 23)
      || inst_get_ldr_imm_rt(src[24]) != 8
      || inst_get_ldr_imm_imm(src[24]) != offsetof(struct nm_inode_owner_prefix, i_flags) + 1
      || !inst_is_tbnz(src[25]) || inst_get_tbnz_rt(src[25]) != 8 || inst_get_tbnz_bit(src[25]) != 1
      || inst_get_tbnz_label(src[25]) != 116)
    return -EOPNOTSUPP;
  if (nm_find_xattr_inline_security(security, 8, 5, 120))
    return -EOPNOTSUPP;
  uintptr_t head = nm_xattr_static_address(&src[26], 24), named = nm_xattr_static_address(&security[8], 20);
  if (!head || head != named || !nm_load_at(src[28], 25, 24, 0) || !nm_compare(src[29], 25, 24)
      || !inst_is_b_cond(src[30]) || inst_get_b_cond_cond(src[30]) || inst_get_b_cond_label(src[30]) != 96
      || !nm_page_address(&src[31], 26) || !nm_load_at(src[33], 8, 25, 24) || !inst_is_sub_reg(src[34])
      || !inst_get_sub_reg_sf(src[34]) || inst_get_sub_reg_rd(src[34]) != 9 || inst_get_sub_reg_rn(src[34]) != 8
      || inst_get_sub_reg_rm(src[34]) != 26 || inst_get_sub_reg_shift(src[34]) || inst_get_sub_reg_imm6(src[34])
      || !inst_is_extr(src[35]) || !inst_get_extr_sf(src[35]) || !inst_get_extr_n(src[35])
      || inst_get_extr_rd(src[35]) != 9 || inst_get_extr_rn(src[35]) != 9 || inst_get_extr_rm(src[35]) != 9
      || inst_get_extr_imm6(src[35]) != 2 || !inst_is_subs_imm(src[36]) || !inst_get_subs_imm_sf(src[36])
      || inst_get_subs_imm_rd(src[36]) != 31 || inst_get_subs_imm_rn(src[36]) != 9 || inst_get_subs_imm_imm(src[36]) != 9
      || !inst_is_b_cond(src[37]) || inst_get_b_cond_cond(src[37]) != 2 || inst_get_b_cond_label(src[37]) != 32
      || !nm_move(src[38], 0, 22) || !inst_is_blr(src[39]) || inst_get_blr_rn(src[39]) != 8)
    return -EOPNOTSUPP;
  return 0;
}

/* context限定plain接口，成功返回0，未知函数/窗口/LSM链冲突返回负错误。
 * 保留旧25条外调security见证，新40条内联见证只由其实际入口形态选择。
 */
static int calculate_function_xattr_internal_list(int context) {
  if (context)
    return -EOPNOTSUPP;
  uintptr_t start = kallsyms_lookup_name("_stext"), end = kallsyms_lookup_name("_etext");
  uintptr_t list =
      nm_xattr_signature_body(kallsyms_lookup_name_by_suffix("listxattr"), NM_XATTR_INTERNAL_LIST_WORDS, start, end);
  uintptr_t security = nm_xattr_signature_body(kallsyms_lookup_name_by_suffix("security_inode_listxattr"),
                                               NM_XATTR_LIST_SECURITY_WORDS, start, end);
  uintptr_t allocation = nm_xattr_signature_body(kallsyms_lookup_name_by_suffix("kvmalloc_node"), 2, start, end);
  if (!list || !security || !allocation)
    return -ENOENT;
  if (list == security || list == allocation || security == allocation)
    return -EINVAL;
  const uint32_t* entry = (const void*)list;
  if (nm_move(entry[7], 20, 1) && nm_move(entry[8], 22, 0)) {
    list = nm_xattr_signature_body(list, NM_XATTR_INLINE_LIST_WORDS, start, end);
    security = nm_xattr_signature_body(security, 10, start, end);
    if (!list || !security)
      return -EOPNOTSUPP;
    int rc = nm_find_xattr_inline_list3((const void*)list, 40, allocation, (const void*)security, start, end);
    if (!rc)
      nm_log_info("layout: syscall listxattr inline3, allocation + shared LSM head witnesses\n");
    return rc;
  }
  int rc =
      nm_find_xattr_internal_list((const void*)list, NM_XATTR_INTERNAL_LIST_WORDS, allocation, security, start, end);
  if (!rc)
    rc = nm_find_xattr_security_pair((const void*)security, NM_XATTR_LIST_SECURITY_WORDS, 108);
  if (!rc)
    nm_log_info("layout: syscall listxattr3/dentry arg0, size + security witnesses\n");
  return rc;
}
