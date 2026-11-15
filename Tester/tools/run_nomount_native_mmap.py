#!/usr/bin/env python3
"""无APK、复用已加载NoMount的UID2000只读mmap探索；硬超时、无KPM重载。

必须指定刚完成的只读预检目录和已宿主核验的探针。基线/ADD/DEL逐字节核对；
只修改本轮临时目录和UID2000精确规则。设备异常则不清现场、不重试、不重启。
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
NM = '/data/local/tmp/nomount-nm05'
FEATURES = re.compile(rb'Kernel panic|Unable to handle kernel|\bBUG:|WARNING: CPU:|Call trace:|CFI failure|CFI check failed|soft lockup|hard LOCKUP', re.I)


class Stop(Exception):
    """携带退出码及原因；danger表示设备/内核异常，禁止追加设备操作。"""
    def __init__(self, reason, code=1, danger=False):
        """记录reason/code/danger，不触设备，供顶层决定是否保现场。"""
        super().__init__(reason)
        self.code, self.danger = code, danger


def decode_probe(stdout, stderr):
    """解析exec-out合并流，返回(read,mapped)；必须精确UID/domain/header/长度。

    参数为adb原始两流；此设备exec-out把探针stderr合入stdout，域结尾允许
    Linux attr/current的单个NUL。拒绝任何其他域、污染、截短或额外字节。
    """
    meta = re.match(rb'uid=2000\ncontext=u:r:shell:s0\x00?\n', stdout)
    if stderr or not meta:
        raise Stop('probe UID/domain transport mismatch')
    data = stdout[meta.end():]
    if len(data) != 8+2*65536 or data[:8] != b'NMRD'+struct.pack('<I',65536):
        raise Stop('probe evidence length/header mismatch')
    return data[8:8+65536],data[8+65536:]


def main():
    """解析两个输入路径并执行一次探索；返回0/1/3/90，不构成验收。"""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--preflight',type=Path,required=True)
    p.add_argument('--probe',type=Path,required=True)
    a = p.parse_args()
    pre = json.loads((a.preflight/'preflight.json').read_text())
    blob = a.probe.read_bytes()
    if blob[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H',blob,18)[0] != 183:
        raise Stop('not an ARM64 ELF')
    out = Path(tempfile.mkdtemp(prefix='nomount-native-mmap-',dir=ROOT/'local/keep/evidence/tester-raw'))
    remote = '/data/local/tmp/'+out.name
    target, source, executable = remote+'/virtual.dat', remote+'/source.dat', remote+'/probe'
    expected = {'original':b'O'*65536,'replacement':b'R'*65536}
    for name,data in (('original.dat',expected['original']),('replacement.dat',expected['replacement'])):
        (out/name).write_bytes(data)
    lock, finish = threading.RLock(), threading.Event()
    requests, samples, cases = [], [], []
    asynchronous = []
    before_boot = pre['boot-id']['text']
    previous_up = [float(pre['uptime']['text'].split()[0])]
    active, created, danger, result, reason = False, False, False, 0, 'PASS'

    def run(tag, cmd=None, root=False, argv=None, check=True):
        """有界执行adb并保存原始输出；返回CompletedProcess，超时/信号即停止90。"""
        with lock:
            if asynchronous:
                raise asynchronous[0]
            args = argv or ['adb','shell',('su -c '+shlex.quote(cmd)) if root else cmd]
            try:
                r = subprocess.run(args,capture_output=True,timeout=15)
            except subprocess.TimeoutExpired as e:
                (out/(tag+'.stdout')).write_bytes(e.stdout or b'')
                (out/(tag+'.stderr')).write_bytes(e.stderr or b'')
                raise Stop('adb timeout: '+tag,90,True)
            (out/(tag+'.stdout')).write_bytes(r.stdout)
            (out/(tag+'.stderr')).write_bytes(r.stderr)
            requests.append({'tag':tag,'argv':args,'rc':r.returncode,'time':time.time()})
            if r.returncode < 0 or r.returncode >= 128:
                raise Stop('request interrupted: '+tag,90,True)
            if check and r.returncode:
                raise Stop('command failure: '+tag+' rc='+str(r.returncode))
            return r

    def state(tag):
        """保存并验证boot_id/uptime；返回uptime，新启动或倒退即保现场停止。"""
        r = run(tag,'cat /proc/sys/kernel/random/boot_id; cat /proc/uptime')
        lines = r.stdout.decode().strip().splitlines()
        if len(lines) != 2:
            raise Stop('invalid state response',1,True)
        up = float(lines[1].split()[0])
        if lines[0] != before_boot or up < previous_up[0]:
            raise Stop('boot changed or uptime decreased',1,True)
        previous_up[0] = up
        samples.append({'time':time.time(),'uptime':up,'same_boot':True})
        return up

    def logs(tag):
        """完整保存本次dmesg快照；发现所选内核异常即停止，返回原始日志。"""
        r = run(tag,'dmesg',True)
        if FEATURES.search(r.stdout):
            raise Stop('kernel anomaly in '+tag,1,True)
        return r.stdout

    def observe():
        """后台每5秒采样状态和dmesg；与功能请求串行，错误传给主线程。"""
        i = 0
        while not finish.wait(5):
            try:
                state('monitor-state-'+str(i))
                logs('monitor-dmesg-'+str(i))
            except Stop as e:
                asynchronous.append(e)
                return
            i += 1

    def pause(seconds):
        """观察seconds秒，期间异常即传播；不执行功能重试。"""
        end = time.monotonic()+seconds
        while time.monotonic() < end:
            if asynchronous:
                raise asynchronous[0]
            time.sleep(.2)

    def verify(tag, key):
        """以shell执行原生probe，核对read/mmap各64KiB；不以普通读回退放行。"""
        r = run(tag,argv=['adb','exec-out',shlex.quote(executable)+' '+shlex.quote(target)])
        read, mapped = decode_probe(r.stdout,r.stderr)
        cases.append({'stage':tag,'rc':r.returncode,'read_sha256':hashlib.sha256(read).hexdigest(),
                      'mmap_sha256':hashlib.sha256(mapped).hexdigest(),'bytes':65536,'uid':2000,'domain':'shell'})
        if read != expected[key] or mapped != expected[key]:
            raise Stop('read/mmap bytes mismatch: '+tag)
        labels = run(tag+'-labels','ls -lZ '+shlex.quote(target)+' '+shlex.quote(source))
        contexts = re.findall(rb'u:object_r:\S+',labels.stdout)
        if len(contexts) != 2 or contexts[0] != contexts[1]:
            raise Stop('source/virtual SELinux labels differ: '+tag)
        print(tag,'read/mmap PASS',cases[-1]['mmap_sha256'])
        state(tag+'-state')
        logs(tag+'-dmesg')

    worker = threading.Thread(target=observe,daemon=True)
    started = time.time()
    try:
        state('initial-state')
        logs('initial-dmesg')
        if run('getenforce','getenforce').stdout.strip() != b'Enforcing':
            raise Stop('SELinux not Enforcing',3)
        hashes = run('pstore-before','sha256sum /sys/fs/pstore/console-ramoops /sys/fs/pstore/pmsg-ramoops-0',True).stdout
        if hashes.strip() != pre['pstore-hash']['text'].encode().strip():
            raise Stop('pstore baseline changed',3,True)
        if run('initial-rules',shlex.quote(NM)+' rule list',True).stdout.strip():
            raise Stop('existing rules; preserve them',3)
        # 捕获完整日志，不清空；串行采样与下面所有功能请求共享lock。
        run('initial-logcat',argv=['adb','logcat','-d','-v','threadtime'])
        worker.start()
        pause(20)
        run('mkdir','mkdir '+shlex.quote(remote)+' && chmod 755 '+shlex.quote(remote))
        created = True
        for local,dest in ((out/'original.dat',target),(out/'replacement.dat',source),(a.probe,executable)):
            run('push-'+Path(dest).name,argv=['adb','push',str(local),dest])
        run('permissions','chmod 644 '+shlex.quote(target)+' '+shlex.quote(source)+'; chmod 755 '+shlex.quote(executable))
        run('device-probe-hash','sha256sum '+shlex.quote(executable))
        if hashlib.sha256(blob).hexdigest().encode() not in (out/'device-probe-hash.stdout').read_bytes():
            raise Stop('probe hash mismatch')
        verify('baseline','original')
        cmd = shlex.quote(NM)+' rule add '+shlex.quote(target)+' '+shlex.quote(source)+' --uid 2000'
        run('add',cmd,True)
        active = True
        listed = run('rules-after-add',shlex.quote(NM)+' rule list',True).stdout.decode()
        if target not in listed or source not in listed:
            raise Stop('added rule absent from list')
        verify('redirect','replacement')
        run('del',shlex.quote(NM)+' rule del '+shlex.quote(target)+' --uid 2000',True)
        active = False
        if run('rules-after-del',shlex.quote(NM)+' rule list',True).stdout.strip():
            raise Stop('rules remained after deletion')
        verify('restored','original')
        pause(40)
    except Stop as e:
        result, reason, danger = e.code, str(e), e.danger
    finally:
        finish.set()
        if worker.is_alive():
            worker.join(35)
        if asynchronous:
            result,reason,danger = asynchronous[0].code,str(asynchronous[0]),asynchronous[0].danger
        if not danger:
            try:
                if active:
                    run('cleanup-rule',shlex.quote(NM)+' rule del '+shlex.quote(target)+' --uid 2000',True)
                    active = False
                if created:
                    run('cleanup-restrict','chmod 644 '+shlex.quote(executable)+'; chown 0:0 '+shlex.quote(remote)+'; chmod 700 '+shlex.quote(remote),True)
                    run('cleanup-files','rm -f '+shlex.quote(executable)+' '+shlex.quote(target)+' '+shlex.quote(source)+'; rmdir '+shlex.quote(remote),True)
                state('final-state')
                logs('final-dmesg')
                run('final-logcat',argv=['adb','logcat','-d','-v','threadtime'])
                run('pstore-after','sha256sum /sys/fs/pstore/console-ramoops /sys/fs/pstore/pmsg-ramoops-0',True)
                run('final-rules',shlex.quote(NM)+' rule list',True)
            except Stop as e:
                result,reason,danger = e.code,str(e),e.danger
        receipt = {'role':'Tester','exploration':True,'same_implementation_session':True,
                   'scope':'UID2000/shell native read+PROT_READ/MAP_PRIVATE mmap, no APK/application/ART coverage',
                   'fingerprint':pre['fingerprint'],'tool_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'probe_sha256':hashlib.sha256(blob).hexdigest(),'preflight':str(a.preflight),
                   'provided_kpm_sha256':'608c4310e1d4841292ba9401d53779172e33884c3b674f9164ea08d67a6d8630',
                   'runtime_artifact_hash_verified':False,'instance_id':None,
                   'start_time':started,'end_time':time.time(),'samples':samples,'cases':cases,
                   'requests':requests,'result':result,'reason':reason,'danger':danger,
                   'temporary_rule_active':active,'remote_directory':remote}
        (out/'result.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n')
        print('Evidence:',out.relative_to(ROOT))
        print('Result:',result,reason)
    return result


if __name__ == '__main__':
    raise SystemExit(main())
