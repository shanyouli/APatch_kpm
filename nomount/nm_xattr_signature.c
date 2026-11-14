/* SPDX-License-Identifier: GPL-2.0-only */
/* 无BTF的plain5已观察形态；六参路径等待可验证目标，不按版本分支。 */
enum {
  NM_XATTR_SET_WORDS = 36, NM_XATTR_LOCKED_WORDS = 24, NM_XATTR_SECURITY_WORDS = 11, NM_XATTR_RO_WORDS = 8,
  NM_XATTR_INLINE_SET_WORDS = 37
};

// 序言不得隐蔽保存额外的x5..x7或改写入口参数；只收已观察的非参数栈保存。
static bool nm_xattr_signature_frame(uint32_t inst) {
  if (!nm_vfs_frame_save(inst))
    return false;
  if (inst_is_stp(inst))
    return inst_get_stp_rt(inst) >= 19 && inst_get_stp_rt2(inst) >= 19;
  return true;
}

static uintptr_t nm_xattr_signature_body(uintptr_t at, unsigned int words, uintptr_t start, uintptr_t end) {
  at = nm_inode_lock_body(at, start, end);
  return at && end - at >= words * sizeof(uint32_t) ? at : 0;
}

static bool nm_xattr_signature_call(const uint32_t* at, uintptr_t target, uintptr_t start, uintptr_t end) {
  return inst_is_bl(*at) && nm_code_matches((uintptr_t)at + inst_get_bl_label(*at), target, start, end);
}

/* src/count为内联permission/security/noperm的五参入口；layout和helpers绑定已确认源锁。
 * 固定37条至解锁BL，分别核对name/value/size/flags位宽和两个拒绝出口。
 * 返回0或负错误，不执行任何目标函数，不通过noperm绕过原生permission/security。
 */
static int nm_find_xattr_inline_set5(const uint32_t* src, unsigned int count, const struct nm_setattr_layout* layout,
                                    const uintptr_t helpers[4], uintptr_t permission, uintptr_t security,
                                    uintptr_t noperm, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_INLINE_SET_WORDS || !layout || layout->context || layout->lock_kind != 1)
    return -EOPNOTSUPP;
  for (unsigned i = 0; i < 6; i++)
    if (!nm_xattr_signature_frame(src[i]))
      return -EOPNOTSUPP;
  if (!nm_load_at(src[6], 24, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_move(src[7], 21, 2)
      || !nm_move(src[8], 22, 0) || !nm_movz_value(src[9], 0, 2, 2) || !nm_move(src[10], 0, 24)
      || !nm_move32(src[11], 19, 4) || !nm_move(src[12], 20, 3) || !nm_move(src[13], 23, 1)
      || !nm_xattr_signature_call(&src[14], permission, start, end) || !nm_move32(src[15], 25, 0)
      || !inst_is_cbnz(src[16]) || inst_get_cbnz_sf(src[16]) || inst_get_cbnz_rt(src[16])
      || inst_get_cbnz_label(src[16]) != 84 || !nm_add_at(src[17], 24, 24, layout->lock_offset)
      || !nm_move(src[18], 0, 24) || !nm_xattr_signature_call(&src[19], helpers[0], start, end))
    return -EOPNOTSUPP;
  const unsigned calls[] = {25, 33};
  const uintptr_t targets[] = {security, noperm};
  for (unsigned i = 0; i < 2; i++) {
    unsigned at = calls[i] - 5;
    if (!nm_move(src[at], 0, 22) || !nm_move(src[at + 1], 1, 23) || !nm_move(src[at + 2], 2, 21)
        || !nm_move(src[at + 3], 3, 20) || !nm_move32(src[at + 4], 4, 19)
        || !nm_xattr_signature_call(&src[calls[i]], targets[i], start, end) || !nm_move32(src[calls[i] + 1], 25, 0))
      return -EOPNOTSUPP;
  }
  if (!inst_is_cbnz(src[27]) || inst_get_cbnz_sf(src[27]) || inst_get_cbnz_rt(src[27])
      || inst_get_cbnz_label(src[27]) != 32 || !nm_move(src[35], 0, 24)
      || !nm_xattr_signature_call(&src[36], helpers[1], start, end))
    return -EOPNOTSUPP;
  int kind = 0, offset = nm_find_inode_lock(src, count, 0, helpers, start, end, &kind);
  return offset < 0 ? offset : offset == layout->lock_offset && kind == layout->lock_kind ? 0 : -EINVAL;
}

/* 核对src的非参数栈帧及dentry→inode→低字节S_PRIVATE守卫；frames/guard为已取证窗口。
 * count必须恰好覆盖守卫，成功0/未知负错误；不跳读LSM链或调用回调。
 */
static int nm_find_xattr_inline_security(const uint32_t* src, unsigned count, unsigned frames, int guard) {
  if (!src || count != frames + 3 || (frames != 5 && frames != 7))
    return -EINVAL;
  for (unsigned i = 0; i < frames; i++)
    if (!nm_xattr_signature_frame(src[i]))
      return -EOPNOTSUPP;
  return nm_load_at(src[frames], 8, 0, offsetof(struct nm_dentry_head, d_inode)) && nm_load(src[frames + 1], 0, 8)
         && inst_get_ldr_imm_rt(src[frames + 1]) == 8
         && inst_get_ldr_imm_imm(src[frames + 1]) == offsetof(struct nm_inode_owner_prefix, i_flags) + 1
         && inst_is_tbnz(src[frames + 2]) && inst_get_tbnz_rt(src[frames + 2]) == 8
         && inst_get_tbnz_bit(src[frames + 2]) == 1 && inst_get_tbnz_label(src[frames + 2]) == guard
             ? 0 : -EOPNOTSUPP;
}

// 第一个见证：entry x0的d_inode进入已独立准备的锁；五个输入按原位宽传给locked。
static int nm_find_xattr_plain5(const uint32_t* src, unsigned int count, const struct nm_setattr_layout* layout,
                                const uintptr_t helpers[4], uintptr_t locked, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_SET_WORDS || !layout || layout->context || layout->lock_offset < 0
      || layout->lock_kind != 1)
    return -EOPNOTSUPP;
  for (unsigned int i = 0; i < 8; i++)
    if (!nm_xattr_signature_frame(src[i]))
      return -EOPNOTSUPP;
  if (!inst_is_adrp(src[8]) || inst_get_adrp_rd(src[8]) != 8 || !nm_load(src[11], 3, 8)
      || inst_get_ldr_imm_rt(src[11]) != 8 || !nm_store_at(src[15], 3, 8, 31, 8))
    return -EOPNOTSUPP;
  int kind = 0;
  int offset = nm_find_inode_lock(src, count, 0, helpers, start, end, &kind);
  if (offset < 0)
    return offset;
  if (offset != layout->lock_offset || kind != layout->lock_kind)
    return -EINVAL;
  // 只接受已观察的参数保存/转发，不把最高读寄存器泛化成任意C原型恢复器。
  if (!nm_move32(src[9], 19, 4) || !nm_move(src[10], 20, 3) || !nm_move(src[12], 21, 2) || !nm_move(src[13], 22, 0)
      || !nm_move(src[14], 23, 1) || !nm_load_at(src[16], 26, 0, offsetof(struct nm_dentry_head, d_inode))
      || !nm_store_at(src[17], 3, 31, 31, 0) || !inst_is_b(src[18]) || inst_get_b_label(src[18]) != 24
      || !nm_add_at(src[24], 0, 26, offset) || !nm_add_at(src[26], 5, 31, 0) || !nm_move(src[27], 0, 22)
      || !nm_move(src[28], 1, 23) || !nm_move(src[29], 2, 21) || !nm_move(src[30], 3, 20) || !nm_move32(src[31], 4, 19)
      || !nm_xattr_signature_call(&src[32], locked, start, end))
    return -EOPNOTSUPP;
  return 0;
}

// 独立函数中的第二个见证：同一个转发dentry→d_inode进入xattr_permission，
// 原dentry/name/value/size/flags原样传给完整security_inode_setxattr。
static int nm_find_xattr_locked_plain5(const uint32_t* src, unsigned int count, uintptr_t permission,
                                       uintptr_t security, uintptr_t start, uintptr_t end) {
  if (!src || count != NM_XATTR_LOCKED_WORDS)
    return -EINVAL;
  for (unsigned int i = 0; i < 7; i++)
    if (!nm_xattr_signature_frame(src[i]))
      return -EOPNOTSUPP;
  if (!nm_load_at(src[7], 25, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_move(src[8], 22, 0)
      || !nm_move(src[9], 21, 2) || !inst_is_movz_imm(src[10]) || inst_get_movz_imm_sf(src[10])
      || inst_get_movz_imm_rd(src[10]) != 2 || inst_get_movz_imm_hw(src[10]) || inst_get_movz_imm_imm16(src[10]) != 2
      || !nm_move(src[11], 23, 5) || !nm_move32(src[12], 19, 4) || !nm_move(src[13], 0, 25) || !nm_move(src[14], 20, 3)
      || !nm_move(src[15], 24, 1) || !nm_xattr_signature_call(&src[16], permission, start, end)
      || !inst_is_cbnz(src[17]) || inst_get_cbnz_sf(src[17]) || inst_get_cbnz_rt(src[17]) != 0
      || inst_get_cbnz_label(src[17]) != 148 || !nm_move(src[18], 0, 22) || !nm_move(src[19], 1, 24)
      || !nm_move(src[20], 2, 21) || !nm_move(src[21], 3, 20) || !nm_move32(src[22], 4, 19)
      || !nm_xattr_signature_call(&src[23], security, start, end))
    return -EOPNOTSUPP;
  return 0;
}

// security入口自身再次使用同一dentry的inode标志，拒绝仅同名但不同ABI的入口。
static int nm_find_xattr_security_plain5(const uint32_t* src, unsigned int count) {
  if (!src || count != NM_XATTR_SECURITY_WORDS)
    return -EINVAL;
  for (unsigned int i = 0; i < 8; i++)
    if (!nm_xattr_signature_frame(src[i]))
      return -EOPNOTSUPP;
  if (!nm_load_at(src[8], 8, 0, offsetof(struct nm_dentry_head, d_inode)) || !nm_load(src[9], 0, 8)
      || inst_get_ldr_imm_rt(src[9]) != 8
      || inst_get_ldr_imm_imm(src[9]) != offsetof(struct nm_inode_owner_prefix, i_flags) + 1 || !inst_is_tbnz(src[10])
      || inst_get_tbnz_rt(src[10]) != 8 || inst_get_tbnz_bit(src[10]) != 1 || inst_get_tbnz_label(src[10]) != 180)
    return -EOPNOTSUPP;
  return 0;
}

/* src/count为完整8条只读判断，核对MNT_READONLY与SB_RDONLY低位及bool返回。
 * 目标低位读取可用LDRB/LDR W；AND仍须为32位bit0，未知字段/宽度返回负错误。
 * 成功0，不执行函数或推断其他s_flags位的布局。
 */
static int nm_find_xattr_readonly(const uint32_t* src, unsigned int count) {
  if (!src || count != NM_XATTR_RO_WORDS)
    return -EINVAL;
  if (!nm_load(src[0], 0, 0) || inst_get_ldr_imm_rt(src[0]) != 8
      || inst_get_ldr_imm_imm(src[0]) != offsetof(struct nm_mount_context_head, flags) || !inst_is_tbnz(src[1])
      || inst_get_tbnz_rt(src[1]) != 8 || inst_get_tbnz_bit(src[1]) != 6 || inst_get_tbnz_label(src[1]) != 20
      || !nm_load_at(src[2], 8, 0, offsetof(struct nm_mount_context_head, super))
      || (!nm_load(src[3], 0, 8) && !nm_load(src[3], 2, 8))
      || inst_get_ldr_imm_rt(src[3]) != 8 || inst_get_ldr_imm_imm(src[3]) != offsetof(struct nm_super_head, s_flags)
      || !inst_is_and_imm(src[4]) || inst_get_and_imm_sf(src[4]) || inst_get_and_imm_rd(src[4]) != 0
      || inst_get_and_imm_rn(src[4]) != 8 || inst_get_and_imm_imm(src[4]) != 1 || !inst_is_ret(src[5])
      || inst_get_ret_rn(src[5]) != 30 || !inst_is_movz_imm(src[6]) || inst_get_movz_imm_sf(src[6])
      || inst_get_movz_imm_rd(src[6]) != 0 || inst_get_movz_imm_hw(src[6]) || inst_get_movz_imm_imm16(src[6]) != 1
      || !inst_is_ret(src[7]) || inst_get_ret_rn(src[7]) != 30)
    return -EOPNOTSUPP;
  return 0;
}

/* 根据context/layout和实际入口确认setxattr五参ABI，成功0/缺证据负错误。
 * 旧locked见证不变；新增内联见证只在明确前部匹配时采用，不按版本或缺符号猜ABI。
 */
static int calculate_function_xattr_write(int context, const struct nm_setattr_layout* layout) {
  if (context || !layout || (struct_offset.permission_abi != 0 && struct_offset.permission_abi != 1))
    return -EOPNOTSUPP;
  if (kallsyms_lookup_name_by_suffix("do_set_acl"))
    return -EOPNOTSUPP;  // 具名独立ACL入口的非BTF原型尚未覆盖。
  uintptr_t start = kallsyms_lookup_name("_stext"), end = kallsyms_lookup_name("_etext");
  const uint32_t* entry = (const void*)nm_xattr_signature_body(kallsyms_lookup_name_by_suffix("vfs_setxattr"),
                                                             NM_XATTR_SET_WORDS, start, end);
  if (entry && nm_add_at(entry[5], 29, 31, 0)
      && nm_load_at(entry[6], 24, 0, offsetof(struct nm_dentry_head, d_inode)) && nm_move(entry[8], 22, 0)) {
    const char* inline_names[] = {"vfs_setxattr", "xattr_permission", "security_inode_setxattr",
                                  "__vfs_setxattr_noperm", "__mnt_is_readonly", "down_write", "up_write"};
    const unsigned inline_words[] = {37, 2, 10, 2, 8, 2, 2};
    uintptr_t body[7];
    for (unsigned i = 0; i < 7; i++) {
      body[i] = nm_xattr_signature_body(kallsyms_lookup_name_by_suffix(inline_names[i]), inline_words[i], start, end);
      if (!body[i])
        return -ENOENT;
      for (unsigned j = 0; j < i; j++)
        if (body[i] == body[j])
          return -EINVAL;
    }
    uintptr_t helpers[4] = {body[5], body[6], 0, 0};
    int rc = nm_find_xattr_inline_set5((const void*)body[0], 37, layout, helpers, body[1], body[2], body[3], start, end);
    if (!rc)
      rc = nm_find_xattr_inline_security((const void*)body[2], 10, 7, 184);
    if (!rc)
      rc = nm_find_xattr_readonly((const void*)body[4], 8);
    if (!rc)
      nm_log_info("layout: setxattr inline plain5, source lock + permission/security/noperm witnesses\n");
    return rc;
  }
  const char* names[] = {"vfs_setxattr",      "__vfs_setxattr_locked", "security_inode_setxattr",
                         "__mnt_is_readonly", "xattr_permission",      "down_write",
                         "up_write"};
  const unsigned int words[] = {
      NM_XATTR_SET_WORDS, NM_XATTR_LOCKED_WORDS, NM_XATTR_SECURITY_WORDS, NM_XATTR_RO_WORDS, 2, 2, 2};
  uintptr_t bodies[7];
  for (unsigned int i = 0; i < 7; i++) {
    bodies[i] = nm_xattr_signature_body(kallsyms_lookup_name_by_suffix(names[i]), words[i], start, end);
    if (!bodies[i])
      return -ENOENT;
    for (unsigned int j = 0; j < i; j++)
      if (bodies[i] == bodies[j])
        return -EINVAL;
  }
  uintptr_t helpers[4] = {bodies[5], bodies[6], 0, 0};
  int rc = nm_find_xattr_plain5((const void*)bodies[0], words[0], layout, helpers, bodies[1], start, end);
  if (!rc)
    rc = nm_find_xattr_locked_plain5((const void*)bodies[1], words[1], bodies[4], bodies[2], start, end);
  if (!rc)
    rc = nm_find_xattr_security_plain5((const void*)bodies[2], words[2]);
  if (!rc)
    rc = nm_find_xattr_readonly((const void*)bodies[3], words[3]);
  if (!rc)
    nm_log_info("layout: setxattr plain5/dentry arg0, lock + permission/security witnesses, readonly bool\n");
  return rc;
}
