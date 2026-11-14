#!/usr/bin/env python3
"""源inode锁及内联xattr/DAC入口的公共宿主自检；不执行内核代码或弱化旧Oracle。"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
from test_dentry_entry import function
ROOT = Path(__file__).resolve().parents[2]
WORDS = {
 'set': 'a9bb7bfd f9000bf9 a9025ff8 a90357f6 a9044ff4 910003fd f9401818 aa0203f5 aa0003f6 52800042 aa1803e0 2a0403f3 aa0303f4 aa0103f7 9400001e 2a0003f9 350002a0 9102a318 aa1803e0 943d6983 aa1603e0 aa1703e1 aa1503e2 aa1403e3 2a1303e4 94073590 2a0003f9 35000100 aa1603e0 aa1703e1 aa1503e2 aa1403e3 2a1303e4 97ffff3b 2a0003f9 aa1803e0 97f8f405',
 'remove': 'a9bd7bfd a90157f6 a9024ff4 910003fd f9401813 aa0003f4 52800042 aa0103f5 aa1303e0 97fffc85 2a0003f6 350004e0 9102a273 aa1303e0 943d65ea aa1403e0 aa1503e1 940732ce 2a0003f6 350003a0 aa1403e0 aa1503e1 97ffff93 2a0003f6 35000300 f9401a95 52800089 794002a8 12140d08 7140111f 52800088 72a80008 1a890116 b5000074 52800108 f9400114 aa1f03e0 aa1403e1 2a1603e2 943db255 52800043 aa1503e0 2a1603e1 aa1503e2 aa1f03e4 2a1f03e5 94009b53 2a1f03f6 aa1303e0 97f8f05a',
 'truncate': 'd10243ff a9067bfd a90757f6 a9084ff4 910183fd b00106c8 f947fd08 f81f83a8 b7f80402 aa0103f3 aa0003f4 321d0076 f9000fe2 b9000bf6 b40000a4 52840108 2a080076 f9002be4 b9000bf6 aa1303e0 9400bf29 2a0003f5 37f80260 34000095 2a1502c8 32170108 b9000be8 f9401a68 9102a100 943e604f 910023e2 aa1403e0 aa1303e1 aa1f03e3 9400c3b3 f9401a68 2a0003f5 9102a100 97f9ead9',
 'security_set': 'd10183ff a9017bfd a90267fa a9035ff8 a90457f6 a9054ff4 910043fd f9401808 39403508 370805c8',
 'security_remove': 'a9bc7bfd f9000bf7 a90257f6 a9034ff4 910003fd f9401808 39403508 37080508',
 'security_list': 'd10103ff a9017bfd a90257f6 a9034ff4 910043fd f9401808 39403508 370803c8 d000b234 91098294',
 'readonly': '39404008 373000a8 f9400408 b9405108 12000100 d65f03c0 52800020 d65f03c0',
 'list': 'd10183ff a9017bfd a90267fa a9035ff8 a90457f6 a9054ff4 910043fd aa0103f4 aa0003f6 b4000182 f140405f 52a00028 9a883055 52801801 72a02801 12800002 aa1503e0 97fda4fa b4000ae0 aa0003f3 14000003 aa1f03f5 aa1f03f3 f9401ad7 394036e8 370803a8 d000c098 91098318 f9400319 eb18033f 54000300 b0007bba 911ee35a f9400f28 cb1a0109 93c90929 f100253f 54000102 aa1603e0 d63f0100',
 'dac': 'a9bc7bfd a9015ff8 a90257f6 a9034ff4 910003fd 2a0203f3 aa0103f4 37080542 39400a88 36000648 aa1403e0 2a1303e1 97ffff7f',
}


def main():
    """提取当前生产函数及静态依赖，运行入口、来源、位宽、分支和保护页断言。

    --output可选保存PASS回执并拒绝覆盖；所有目标调用重定位到可读占位，绝不执行。
    旧直接ADD契约、旧字节只读判断和39条DAC形态保持额外正例覆盖。
    """
    p = argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);a=p.parse_args()
    cc=shutil.which('clang')
    if not cc:raise RuntimeError('没有已安装Clang，未执行测试')
    paths=('nomount/nm_offsets.c','nomount/nm_permission_shape.c','nomount/nm_xattr_signature.c','nomount/nm_xattr_entry_signatures.c')
    texts={name:(ROOT/name).read_text() for name in paths};full='\n'.join(texts.values());selected={}
    def collect(name):
        """收集name的静态定义/依赖，缺失或宏不重写；按原生产顺序组合，不插桩函数。"""
        if name in selected:return
        try:body=function(full,name)
        except ValueError:return
        selected[name]=body
        for called in re.findall(r'\b((?:nm_|calculate_)\w+)\s*\(',body):
            if called!=name:collect(called)
    for name in ('nm_find_inode_lock','calculate_function_setattr','nm_find_xattr_inline_set5','nm_find_xattr_inline_remove2',
                 'nm_find_xattr_inline_list3','nm_find_xattr_inline_security','nm_find_xattr_readonly','nm_find_generic_dac_call',
                 'nm_confirm_generic_dac_abi','calculate_function_xattr_write','calculate_function_xattr_remove',
                 'calculate_function_xattr_internal_list'):
        collect(name)
    flow=full[full.index('struct nm_inode_lock_flow {'):];flow=flow[:flow.index('};')+2]
    source=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define nm_log_info(...) ((void)0)
#define nm_log_error(...) ((void)0)
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
static uintptr_t low,high;
static uint32_t *set,*remove_entry,*truncate_entry,*security_set,*security_remove,*security_list,*readonly,*list,*dac;
static uint32_t *down,*up,*permission,*noperm,*native_remove,*allocation,*generic,*other;
static unsigned long kallsyms_lookup_name(const char* name){
 if(!strcmp(name,"_stext"))return low;if(!strcmp(name,"_etext"))return high;
 if(!strcmp(name,"vfs_setxattr"))return(uintptr_t)set;if(!strcmp(name,"vfs_removexattr"))return(uintptr_t)remove_entry;
 if(!strcmp(name,"do_truncate2"))return(uintptr_t)truncate_entry;
 if(!strcmp(name,"down_write"))return(uintptr_t)down;if(!strcmp(name,"up_write"))return(uintptr_t)up;
 if(!strcmp(name,"xattr_permission"))return(uintptr_t)permission;
 if(!strcmp(name,"security_inode_setxattr"))return(uintptr_t)security_set;
 if(!strcmp(name,"security_inode_removexattr"))return(uintptr_t)security_remove;
 if(!strcmp(name,"security_inode_listxattr"))return(uintptr_t)security_list;
 if(!strcmp(name,"__vfs_setxattr_noperm"))return(uintptr_t)noperm;
 if(!strcmp(name,"__vfs_removexattr"))return(uintptr_t)native_remove;
 if(!strcmp(name,"__mnt_is_readonly"))return(uintptr_t)readonly;
 if(!strcmp(name,"listxattr"))return(uintptr_t)list;if(!strcmp(name,"kvmalloc_node"))return(uintptr_t)allocation;
 if(!strcmp(name,"generic_permission"))return(uintptr_t)generic;
 if(!strcmp(name,"__inode_permission2"))return(uintptr_t)dac;
 return 0;
}
static unsigned long kallsyms_lookup_name_by_suffix(const char* name){return kallsyms_lookup_name(name);}
'''
    source+=(ROOT/'kpm_utils.h').read_text().split('// instruction\n',1)[1].rsplit('#endif',1)[0]
    source+=(ROOT/'nomount/nm_structs.h').read_text()
    source+=texts['nomount/nm_offsets.c'].split('// int保留',1)[0].replace('__attribute__((section(".data.re_offsets"), used))','')+flow+'\n'
    # 这些接口的两参分支依赖普通permission分类；此测试的输入明确限定Android三参。
    source+='static int calculate_function_permission_abi(void){assert(!"unexpected plain branch");return-EINVAL;}\n'
    # 防止收集到普通分类器：它不属于本用例，且只在ABI=1分支调用。
    selected.pop('calculate_function_permission_abi',None)
    for name in ('nomount/nm_xattr_signature.c','nomount/nm_xattr_entry_signatures.c'):
        source+=re.search(r'enum\s*\{.*?\};',texts[name],re.S)[0]+'\n'
    source+=''.join(selected[n] for n in sorted(selected,key=lambda n:full.index(selected[n].rstrip())))
    for name,words in WORDS.items():source+='static const uint32_t '+name+'_words[]={'+','.join('0x'+x+'U' for x in words.split())+'};\n'
    source+=r'''
/* 只编码同一映射内的调用/地址关系，不执行ARM64指令。 */
static void call_to(uint32_t* at,const uint32_t* to){intptr_t delta=(intptr_t)(uintptr_t)to-(intptr_t)(uintptr_t)at;
 assert(delta%4==0&&delta>=-(1L<<27)&&delta<(1L<<27));*at=0x94000000U|((uint32_t)(delta/4)&0x3ffffffU);}
static void address_to(uint32_t* at,int rd,uintptr_t to){intptr_t pages=((intptr_t)(to&~(uintptr_t)4095)-(intptr_t)((uintptr_t)at&~(uintptr_t)4095))/4096;
 uint32_t v=(uint32_t)pages&0x1fffffU;at[0]=0x90000000U|rd|((v&3)<<29)|((v>>2)<<5);at[1]=0x91000000U|rd|(rd<<5)|((to&4095)<<10);}
static struct nm_setattr_layout layout={168,1,112,0};static uintptr_t helpers[4];
static unsigned load(unsigned which,uint32_t* code){
 const uint32_t* src[]={set_words,remove_words,truncate_words,security_set_words,security_remove_words,security_list_words,readonly_words,list_words,dac_words};
 const unsigned size[]={37,50,39,10,8,10,8,40,13};memcpy(code,src[which],size[which]*4);
 if(which<3){for(unsigned i=0;i<size[which];i++)if(inst_is_bl(code[i]))call_to(code+i,other);}
 if(which==0){call_to(code+14,permission);call_to(code+19,down);call_to(code+25,security_set);call_to(code+33,noperm);call_to(code+36,up);}
 if(which==1){call_to(code+9,permission);call_to(code+14,down);call_to(code+17,security_remove);call_to(code+22,native_remove);call_to(code+49,up);}
 if(which==2){call_to(code+29,down);call_to(code+38,up);}
 if(which==5)address_to(code+8,20,low+12000);
 if(which==7){call_to(code+17,allocation);address_to(code+26,24,low+12000);}
 if(which==8)call_to(code+12,generic);
 return size[which];
}
/* 单独运行当前生产识别器；所有参数指向可读宿主缓冲，原生函数不执行。 */
static int run(unsigned which,const uint32_t* code){int kind=0;
 if(which<3){int off=nm_find_inode_lock(code,which==0?37:which==1?50:39,which==2?1:0,helpers,low,high,&kind);return off<0?off:off==168&&kind==1?0:-EINVAL;}
 if(which==3)return nm_find_xattr_inline_security(code,10,7,184);
 if(which==4)return nm_find_xattr_inline_security(code,8,5,160);
 if(which==5){int rc=nm_find_xattr_inline_security(code,8,5,120);return rc?rc:nm_xattr_static_address(code+8,20)==low+12000?0:-EINVAL;}
 if(which==6)return nm_find_xattr_readonly(code,8);
 if(which==7)return nm_find_xattr_inline_list3(code,40,(uintptr_t)allocation,security_list,low,high);
 return nm_find_generic_dac_call(code,13,false,(uintptr_t)generic,low,high);
}
int main(void){
 unsigned char arena[32768] __attribute__((aligned(4096)))={0};low=(uintptr_t)arena;high=low+sizeof(arena);
 set=(void*)(arena+0);remove_entry=(void*)(arena+512);truncate_entry=(void*)(arena+1024);security_set=(void*)(arena+1536);
 security_remove=(void*)(arena+2048);security_list=(void*)(arena+2560);readonly=(void*)(arena+3072);list=(void*)(arena+3584);dac=(void*)(arena+4096);
 down=(void*)(arena+8192);up=down+4;permission=down+8;noperm=down+12;native_remove=down+16;allocation=down+20;generic=down+24;other=down+28;
 for(unsigned i=0;i<32;i++)down[i]=0xd65f03c0U;helpers[0]=(uintptr_t)down;helpers[1]=(uintptr_t)up;
 uint32_t* code[]={set,remove_entry,truncate_entry,security_set,security_remove,security_list,readonly,list,dac};
 for(unsigned i=0;i<9;i++)load(i,code[i]);
 struct_offset.getattr_context_kind=0;struct_offset.permission_abi=0;
 struct nm_setattr_layout derived={0};assert(!calculate_function_setattr(&derived,112)&&derived.lock_offset==168&&derived.lock_kind==1);
 assert(!calculate_function_xattr_write(0,&layout));assert(!calculate_function_xattr_remove(0,&layout));
 assert(!calculate_function_xattr_internal_list(0));assert(!nm_confirm_generic_dac_abi());
 // 三个独立来源冲突或同体别名必须失败，不投票选择大多数偏移。
 uint32_t old_add=set[17];set[17]+=8U<<10;assert(calculate_function_setattr(&derived,112)==-EINVAL);set[17]=old_add;
 uint32_t* old_remove=remove_entry;remove_entry=set;assert(calculate_function_setattr(&derived,112)==-EINVAL);remove_entry=old_remove;
 struct nm_inode_lock_flow merged={.lock=1,.lock_offset=168,.reached=true};
 struct nm_inode_lock_flow conflict={.lock=1,.lock_offset=176,.reached=true};assert(nm_inode_lock_merge(&merged,conflict,true)==-EINVAL);
 for(unsigned i=0;i<9;i++){unsigned count=load(i,code[i]);assert(!run(i,code[i]));
   for(unsigned j=0;j<count;j++){uint32_t saved=code[i][j];code[i][j]=0xd503201fU;
     assert(run(i,code[i])<0);code[i][j]=saved;}}
 // 新ABI函数另测每条来源、参数宽度及调用身份，不能只通过锁链推断原型。
 for(unsigned i=0;i<37;i++){uint32_t saved=set[i];set[i]=0xd503201fU;
   assert(nm_find_xattr_inline_set5(set,37,&layout,helpers,(uintptr_t)permission,(uintptr_t)security_set,(uintptr_t)noperm,low,high)<0);set[i]=saved;}
 const unsigned args5[]={7,8,10,11,12,13,20,21,22,23,24,28,29,30,31,32};
 for(unsigned i=0;i<ARRAY_SIZE(args5);i++){unsigned at=args5[i];uint32_t saved=set[at];set[at]^=1U<<31;
   assert(nm_find_xattr_inline_set5(set,37,&layout,helpers,(uintptr_t)permission,(uintptr_t)security_set,(uintptr_t)noperm,low,high)<0);set[at]=saved;}
 for(unsigned i=0;i<40;i++){uint32_t saved=list[i];list[i]=0xc8087c83U;assert(run(7,list)<0);list[i]=saved;}
 // 保留旧直接ADD形态及其错误：MOV32或BL不能传承源，跳入BL不能绕过定义。
 uint32_t direct[]={0xaa0003f3U,0xf9401a74U,0x9102a280U,0,0x9102a280U,0};call_to(direct+3,down);call_to(direct+5,up);
 int kind=0;assert(nm_find_inode_lock(direct,6,0,helpers,low,high,&kind)==168&&kind==1);
 uint32_t saved=direct[1];direct[1]^=1U<<30;assert(nm_find_inode_lock(direct,6,0,helpers,low,high,&kind)<0);direct[1]=saved;
 direct[2]=0x9102a680U;assert(nm_find_inode_lock(direct,6,0,helpers,low,high,&kind)==-EINVAL);direct[2]=0x9102a280U;
 assert(nm_find_inode_lock(direct,44,0,helpers,low,high,&kind)==-EINVAL);
 uint32_t mutation[64];load(0,mutation);call_to(mutation+18,other);assert(nm_find_inode_lock(mutation,37,0,helpers,low,high,&kind)<0);
 load(0,mutation);mutation[18]=0x2a1803e0U;assert(nm_find_inode_lock(mutation,37,0,helpers,low,high,&kind)<0);
 load(0,mutation);mutation[16]=0x35000060U;assert(nm_find_inode_lock(mutation,37,0,helpers,low,high,&kind)<0);
 load(0,mutation);mutation[35]=0xaa0003e0U;assert(nm_find_inode_lock(mutation,37,0,helpers,low,high,&kind)<0);
 load(1,mutation);mutation[31]=(mutation[31]&~31U)|19U;assert(nm_find_inode_lock(mutation,50,0,helpers,low,high,&kind)<0);
 load(1,mutation);mutation[32]=(mutation[32]&~31U)|19U;assert(nm_find_inode_lock(mutation,50,0,helpers,low,high,&kind)<0);
 load(2,mutation);mutation[28]+=8U<<10;assert(nm_find_inode_lock(mutation,39,1,helpers,low,high,&kind)==-EINVAL);
 // 原readonly字节读取、原DAC半字读取与39条形态均保留。
 readonly[3]=0x39414108U;assert(!nm_find_xattr_readonly(readonly,8));load(6,readonly);
 dac[8]=0x79400688U;assert(!run(8,dac));load(8,dac);
 uint32_t old_dac[39]={0};old_dac[0]=0xa9bc7bfdU;old_dac[1]=0xaa0003e4U;old_dac[2]=old_dac[3]=old_dac[4]=0xa9024ff4U;
 old_dac[5]=0x2a0203f4U;old_dac[6]=0xaa0103f3U;old_dac[7]=0x36080094U;old_dac[11]=0x79400660U;
 old_dac[12]=0x37000300U;old_dac[36]=0xaa1303e0U;old_dac[37]=0x2a1403e1U;call_to(old_dac+38,generic);
 assert(!nm_find_generic_dac_call(old_dac,39,true,(uintptr_t)generic,low,high));
 // 每个新窗口恰好贴保护页，越过已声明边界会触发宿主保护。
 long page=sysconf(_SC_PAGESIZE);assert(page>256);unsigned char* pages=mmap(NULL,page*20,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(pages!=MAP_FAILED);for(unsigned i=1;i<18;i+=2)assert(!mprotect(pages+i*page,page,PROT_NONE));
 uintptr_t saved_low=low,saved_high=high;low=(uintptr_t)pages;high=low+page*20;
 uint32_t* functions=(void*)(pages+page*18);for(unsigned i=0;i<32;i++)functions[i]=0xd65f03c0U;
 down=functions;up=down+4;permission=down+8;noperm=down+12;native_remove=down+16;allocation=down+20;generic=down+24;other=down+28;
 helpers[0]=(uintptr_t)down;helpers[1]=(uintptr_t)up;
 uint32_t* safe_security=(void*)(pages+page*19);load(5,safe_security);security_list=safe_security;
 security_set=safe_security+32;security_remove=safe_security+64;load(3,security_set);load(4,security_remove);
 const unsigned count[]={37,50,39,10,8,10,8,40,13};
 for(unsigned i=0;i<9;i++){uint32_t* guarded=(void*)(pages+(i*2+1)*page-count[i]*4);load(i,guarded);assert(!run(i,guarded));
   for(unsigned j=0;j<count[i];j++){uint32_t before=guarded[j];guarded[j]=0xd503201fU;assert(run(i,guarded)<0);guarded[j]=before;}}
 assert(!munmap(pages,page*20));low=saved_low;high=saved_high;
 puts("source lock/business entries: three anchors, arguments, scalar widths, dispatch, legacy and guard pages passed");return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix='nomount-business-entry-') as d:
        d=Path(d);(d/'test.c').write_text(source)
        r=subprocess.run([cc,'-std=gnu11','-Wall','-Werror','-Wno-unused-function','-fsanitize=address,undefined',str(d/'test.c'),'-o',str(d/'test')],text=True,capture_output=True)
        if r.returncode:print(r.stderr)
        r.check_returncode();subprocess.run([str(d/'test')],check=True)
    if a.output:
        receipt={'role':'Developer','scope':'生产源锁和短ABI入口宿主自检，原生调用/安全语义/实际ADD未执行','sources':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in paths},'tool_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'windows':WORDS,'result':'PASS'}
        with a.output.open('x') as f:json.dump(receipt,f,ensure_ascii=False,indent=2);f.write('\n')
    return 0
if __name__=='__main__':raise SystemExit(main())
