#!/usr/bin/env python3
"""只测试原生探针的exec-out合并流解析；不请求设备，不弱化身份或数据边界。"""
import struct
from run_nomount_native_mmap import decode_probe, Stop


def main():
    """对确定的元数据/两段64KiB协议做正反例，成功返回0，否则抛AssertionError。"""
    original = b'O'*65536
    mapped = b'R'*65536
    frame = b'NMRD'+struct.pack('<I',65536)+original+mapped
    for meta in (b'uid=2000\ncontext=u:r:shell:s0\n',b'uid=2000\ncontext=u:r:shell:s0\x00\n'):
        packet = meta+frame
        assert decode_probe(packet,b'') == (original,mapped)
        bad = [packet.replace(b'uid=2000',b'uid=0',1),
               packet.replace(b'u:r:shell:s0',b'u:r:magisk:s0',1),
               packet.replace(b'context=',b'garbage=',1),
               b'noise\n'+packet,packet[:-1],packet+b'x',
               meta+b'BAD!'+frame[4:],meta+b'NMRD'+struct.pack('<I',65535)+frame[8:]]
        for value in bad:
            try:decode_probe(value,b'')
            except Stop:pass
            else:raise AssertionError('negative packet accepted')
        try:decode_probe(packet,b'error')
        except Stop:pass
        else:raise AssertionError('unexpected stderr accepted')
    print('exec-out protocol: exact identity, two buffers, header, truncation and contamination PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
