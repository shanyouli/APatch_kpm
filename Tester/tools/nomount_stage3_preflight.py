#!/usr/bin/env python3
"""已加载NoMount的探索性只读预检；每个adb请求有硬超时，不加载/卸载/重启。

输出只写tester-raw的新目录。非空pstore仅接受维护者本轮明确批准的两个归档哈希。
该工具未冻结，不产生独立审计或交付验收结论。
"""
import hashlib
import json
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tempfile
import re

ROOT = Path(__file__).resolve().parents[2]


def main():
    """执行只读预检并返回0/2/3/90；90表示adb超时，随后不再请求设备。"""
    adb = shutil.which('adb')
    if not adb:
        print('adb unavailable', file=sys.stderr)
        return 2
    folder = ROOT/'local/keep/evidence/tester-raw'
    folder.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='nomount-stage3-preflight-', dir=folder))
    records = []

    def run(tag, args, timeout=15):
        """执行args并保存tag输出，返回(rc,文本)；超时退出90且无重试，不记录序列号。"""
        try:
            p = subprocess.run(args, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            (out/(tag+'.stdout')).write_bytes(e.stdout or b'')
            (out/(tag+'.stderr')).write_bytes(e.stderr or b'')
            (out/'STOP.json').write_text(json.dumps({'reason':'device request timed out','tag':tag,'timeout':timeout}))
            print('STOP: device request timed out; no retry', tag, file=sys.stderr)
            raise SystemExit(90)
        (out/(tag+'.stdout')).write_bytes(p.stdout)
        (out/(tag+'.stderr')).write_bytes(p.stderr)
        records.append({'tag':tag,'argv':args,'rc':p.returncode})
        return p.returncode, p.stdout.decode(errors='replace').strip()

    rc, state = run('state', [adb,'get-state'])
    if rc or state != 'device':
        print('device unavailable', file=sys.stderr)
        return 2
    # get-serialno结果仅在内存中取hash；不用通用run，序列号不写入日志。
    try:
        p = subprocess.run([adb,'get-serialno'],capture_output=True,timeout=8)
    except subprocess.TimeoutExpired:
        print('STOP: device identity query timed out', file=sys.stderr)
        return 90
    if p.returncode:
        return 2
    fingerprint = hashlib.sha256(p.stdout.strip()).hexdigest()[:8]
    results = {'fingerprint':fingerprint,'role':'Tester','exploration':True,
               'authorization':'用户确认Tester探索测试并保留归档pstore；当前方案为无APK原生只读mmap，禁止KPM重载/卸载/重启/清日志/自动注入',
               'tool_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    for tag, cmd, root in (
        ('shell-id','id',False),('root-id','id',True),
        ('boot-id','cat /proc/sys/kernel/random/boot_id',False),
        ('uptime','cat /proc/uptime',False),('kernel','uname -r',False),
        ('selinux','getenforce',False),('pstore-list','ls -la /sys/fs/pstore',True),
        ('pstore-hash','sha256sum /sys/fs/pstore/console-ramoops /sys/fs/pstore/pmsg-ramoops-0',True),
        ('client-hash','sha256sum /data/local/tmp/nomount-nm05',True),
        ('version','/data/local/tmp/nomount-nm05 version',True),
        ('rules','/data/local/tmp/nomount-nm05 rule list',True),
        ('manager-uid','pm list packages -U me.yuki.folk',False),
        ('kpatch-paths','for p in /data/local/tmp/kpatch /data/adb/ap/bin/kpatch /data/adb/kpatch; do [ ! -x "$p" ] || printf "%s\\n" "$p"; done',True),
        ('manager-path','pm path me.yuki.folk',False),
        ('dmesg-before','dmesg',True),
    ):
        argv = [adb,'shell','su -c '+shlex.quote(cmd)] if root else [adb,'shell',cmd]
        rc, text = run(tag, argv)
        results[tag] = {'rc':rc,'text':text}
        if rc:
            (out/'preflight.json').write_text(json.dumps(results,ensure_ascii=False,indent=2))
            print('preflight failed',tag,rc,file=sys.stderr)
            return 2
    uid_match = re.search(r'uid:(\d+)', results['manager-uid']['text'])
    package_path = results['manager-path']['text'].removeprefix('package:')
    if not uid_match or not package_path.endswith('/base.apk'):
        print('STOP: manager identity unavailable', file=sys.stderr)
        return 3
    tool = package_path.rsplit('/',1)[0]+'/lib/arm64/libkpatch.so'
    cmd = 'su '+uid_match[1]+' -c '+shlex.quote(shlex.quote(tool)+' su kpm list')
    rc, text = run('kpm-list',[adb,'shell','su -c '+shlex.quote(cmd)])
    results['kpm-list'] = {'rc':rc,'text':text}
    results['requests'] = records
    (out/'preflight.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n')
    if rc or 'NoMount' not in text.splitlines():
        print('STOP: module list does not confirm NoMount', file=sys.stderr)
        return 3
    if re.search(r'Kernel panic|Call trace:|Unable to handle kernel|\bBUG:|WARNING: CPU:|CFI failure|CFI check failed|soft lockup|hard LOCKUP',results['dmesg-before']['text'],re.I):
        print('STOP: kernel anomaly in current baseline; preserve evidence',file=sys.stderr)
        return 3
    expected = {'990b4f4ca563a83d9152750b7bb1e2545020060483c81db957cba43f5853f429',
                '948c94af0fa95cca1d2e821beba633594e54919c1fb9c88facdfd02639b2c145'}
    actual = {line.split()[0] for line in results['pstore-hash']['text'].splitlines()}
    if actual != expected:
        print('STOP: pstore differs from explicitly accepted baseline',file=sys.stderr)
        return 3
    if results['rules']['text']:
        print('STOP: existing rules; preserve them, do not clear',file=sys.stderr)
        return 3
    if not results['version']['text'].startswith('22 (KPM 2.2.0-20261108)'):
        print('STOP: unexpected version',file=sys.stderr)
        return 3
    print('Evidence:', out.relative_to(ROOT))
    print('Fingerprint:', fingerprint)
    for tag in ('shell-id','root-id','uptime','kernel','selinux','version','client-hash','manager-uid','kpatch-paths'):
        print(tag+':',results[tag]['text'])
    print('pstore: accepted archived hashes; rules: empty')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
