#!/usr/bin/env python3
"""验证生成 WebUI 的真实脚本、shell 参数及配套 CLI 载荷；不操作设备。"""
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from build_zip import adapt_cli, adapt_webui

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / 'upstream/nomount'

NODE_TEST = r'''
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const cp = require('node:child_process');
class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.textContent = ''; this.value = ''; this.style = {}; }
    append(...nodes) { this.children.push(...nodes); }
    before(node) { this.previous = node; }
    replaceChildren(...nodes) { this.children = nodes; }
    setAttribute() {}
    set innerHTML(value) { throw Error('Paths must not enter HTML'); }
}
const modules = new Element('div');
const document = {documentElement: {lang: 'zh', setAttribute() {}, style: {setProperty() {}, removeProperty() {}}}, createElement: tag => new Element(tag),
    getElementById: id => id === 'modules-list' ? modules : null, addEventListener() {}};
const context = vm.createContext({document, console, localStorage: {getItem() { return null; }},
    history: {replaceState() {}}, window: {addEventListener() {}, confirm: () => true},
    assert, cp, fs, customElements: {define() {}}, HTMLElement: Element,
    matchMedia: () => ({matches: false, addEventListener() {}}),
    getComputedStyle: () => ({getPropertyValue: () => '#6750a4'})});
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), context);
vm.runInContext(`
let testRules = [], calls = [], mutations = [], notices = [], failCommand = false, failList = false, badStatus = false;
let modulesRefresh = 0, homeRefresh = 0;
loadModules = async () => { modulesRefresh++; };
loadHome = async () => { homeRefresh++; };
showToast = message => notices.push(message);
exec = async command => {
    calls.push(command);
    if (command.includes('rule list --json')) {
        if (failList) return {errno: 0, stdout: '[]', stderr: 'nm_path_status=9\\n'};
        return {errno: 0, stdout: JSON.stringify(testRules), stderr: 'nm_path_status=0\\n'};
    }
    mutations.push(command);
    if (failCommand) return {errno: 0, stdout: '', stderr: 'failed\\nnm_path_status=7\\n'};
    if (badStatus) return {errno: 0, stdout: '', stderr: ''};
    const parsed = cp.spawnSync('/bin/sh', ['-c', command.replace("'/data/adb/modules/nomount/bin/nm'", "printf '%s\\\\0'")]);
    const args = parsed.stdout.toString().split('\\0').slice(0, -1);
    const action = args[1], record = {};
    let index = 2;
    while (args[index]?.startsWith('--')) {
        const option = args[index++];
        if (option === '--uid-range') [record.uid, record.uid_end] = args[index++].split('-').map(Number);
        else if (option === '--uid-excluded') [record.deny_start, record.deny_end] = args[index++].split('-').map(Number);
        else record[{'--whiteout': 'whiteout', '--virtual-dir': 'virtual_dir', '--opaque': 'opaque'}[option]] = true;
    }
    record.virtual = args[index++];
    if (args[index]) record.real = args[index];
    testRules = testRules.filter(item => item.virtual !== record.virtual ||
        ['uid', 'uid_end', 'deny_start', 'deny_end'].some(key => (item[key] || 0) !== (record[key] || 0)));
    if (action === 'add') testRules.push(record);
    return {errno: 0, stdout: '', stderr: 'nm_path_status=0\\n'};
};
`, context);
const tests = `
(async () => {
    const rule = {virtual: "/system/a ' \\n$HOME " + String.fromCharCode(96) + 'id' + String.fromCharCode(96) + ' <img>', real: '/data/adb/modules/demo/source', uid: 10000, uid_end: 10010, deny_start: 10002, deny_end: 10003};
    const other = {...rule, uid: 20000, uid_end: 20000, deny_start: 0, deny_end: 0};
    testRules = [rule, other, {virtual: '/hidden', whiteout: true}, {virtual: '/directory', virtual_dir: true}, {virtual: '/opaque', real: '/source', opaque: true}];
    await nmRefreshRules();
    assert.equal(nmMountState.panel.rows.children.length, 5);
    assert.equal(nmMountState.panel.rows.children[0].children[1].textContent, '目标: ' + rule.virtual);
    nmMountState.panel.search.value = 'DEMO'; nmRenderRules();
    assert.equal(nmMountState.panel.rows.children.length, 2);
    nmMountState.panel.search.value = 'no-such-path'; nmRenderRules();
    assert.equal(nmMountState.panel.rows.children[0].textContent, '没有匹配的路径');
    nmMountState.panel.search.value = '';
    const quoted = nmRuleCommand(rule, false);
    // 用真正的 shell 解出参数，路径中的命令替换不可执行。
    const args = cp.spawnSync('/bin/sh', ['-c', quoted.replace("'/data/adb/modules/nomount/bin/nm'", "printf '%s\\\\0'" )]);
    assert.equal(args.status, 0);
    assert.deepEqual(args.stdout.toString().split('\\0').slice(0, -1), ['rule', 'del', '--uid-range', '10000-10010', '--uid-excluded', '10002-10003', rule.virtual]);
    assert(nmRuleCommand({virtual: '/a', whiteout: true}, true).includes("'--whiteout' '/a'"));
    assert(nmRuleCommand({virtual: '/a', virtual_dir: true}, true).includes("'--virtual-dir' '/a'"));
    assert(nmRuleCommand({virtual: '/a', real: '/b', opaque: true}, true).includes("'--opaque' '/a' '/b'"));
    assert(nmRuleCommand({virtual: '/a', real: '/b', uid: 0, uid_end: 4294967295}, true).includes("'--uid-range' '0-4294967295'"));
    assert(!nmRuleCommand({virtual: '/a', real: '/b'}, true).includes('--uid-range'));
    for (const invalid of [{uid: -1}, {uid: '2'}, {uid_end: 4294967296}, {uid: 9, uid_end: 1}, {deny_start: 2}, {virtual: 'relative'}])
        assert.throws(() => nmRuleCommand({...rule, ...invalid}, false));
    window.confirm = () => false;
    await nmChangeRule(rule, false); assert.equal(mutations.length, 0);
    window.confirm = () => true;
    testRules = [rule, other];
    await nmChangeRule(rule, false);
    assert.equal(mutations.length, 1);
    assert(nmMountState.removed.has(nmRuleKey(rule)));
    assert.equal(nmMountState.active.length, 1);
    assert.equal(nmMountState.active[0].uid, 20000);
    assert.equal(modulesRefresh, 1); assert.equal(homeRefresh, 1);
    const before = mutations.length;
    testRules = [{...rule, real: '/someone-else'}];
    await nmChangeRule(rule, true); assert.equal(mutations.length, before);
    assert(notices.at(-1).includes('规则已变化'));
    testRules = []; failCommand = true;
    await nmChangeRule(rule, true);
    assert(nmMountState.removed.has(nmRuleKey(rule))); assert(notices.at(-1).includes('failed'));
    failCommand = false;
    await nmChangeRule(rule, true);
    assert(!nmMountState.removed.has(nmRuleKey(rule)));
    assert.equal(nmMountState.active[0].virtual, rule.virtual);
    assert.equal(nmMountState.active[0].real, rule.real);
    assert(mutations.at(-1).includes("'add' '--uid-range' '10000-10010' '--uid-excluded' '10002-10003'"));
    testRules = [rule]; badStatus = true;
    await nmChangeRule(rule, false); assert(!nmMountState.removed.has(nmRuleKey(rule)));
    badStatus = false;
    nmMountState.busy = true;
    const busyCalls = calls.length; await nmChangeRule(rule, false); assert.equal(calls.length, busyCalls);
    nmMountState.busy = false;
    failList = true; await nmRefreshRules();
    assert(nmMountState.panel.message.textContent.includes('操作失败'));
    assert.equal(nmMountState.panel.rows.children.length, 0);
    nmRenderRules(); assert.equal(nmMountState.panel.rows.children.length, 0);
    failList = false; testRules = []; await nmRefreshRules();
    assert.equal(nmMountState.panel.rows.children[0].textContent, '没有挂载规则');
    document.documentElement.lang = 'fr'; assert.equal(nmRuleText('restore'), 'Reload');
    // 后返回的旧查询不得覆盖较新的列表。
    let responses = [];
    exec = () => new Promise(resolve => responses.push(resolve));
    const first = nmRefreshRules(), second = nmRefreshRules();
    responses[1]({errno: 0, stdout: JSON.stringify([other]), stderr: 'nm_path_status=0\\n'}); await second;
    responses[0]({errno: 0, stdout: JSON.stringify([rule]), stderr: 'nm_path_status=0\\n'}); await first;
    assert.equal(nmMountState.active[0].uid, 20000);
})()
`;
vm.runInContext(tests, context).catch(error => { console.error(error); process.exitCode = 1; });
'''

HOST_ARCH = '''#include <stdlib.h>
#include <stdio.h>
#define SYS_EXIT 1
#define SYS_WRITE 2
#define SYS_GETCWD 3
#define SYS_ADD_KEY 4
static long sys1(long n, long a) { exit((int)a); }
static long sys3(long n, long a, long b, long c) { return -1; }
static long sys5(long n, long a, long b, long c, long d, long e);
'''
HOST_MAIN = '''
static long sys5(long n, long a, long b, long c, long d, long e) {
    struct nm_payload *p = (void *)*(unsigned long *)c;
    p->status = 0;
    if (p->cmd == NM_CMD_GET_VERSION) {
        p->buffer[0] = '2'; p->buffer[1] = '2'; p->data_size = 2;
    } else { fwrite(p, 1, sizeof(*p), stdout); }
    return 0;
}
int main(int argc, char **argv) {
    long *sp = calloc(argc + 2, sizeof(long));
    sp[0] = argc;
    for (int i = 0; i < argc; i++) sp[i + 1] = (long)argv[i];
    c_main(sp);
}
'''


class WebuiRulesTests(unittest.TestCase):
    def test_generated_webui(self):
        js = adapt_webui((UPSTREAM / 'module/webroot/index.js').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'index.js').write_text(js)
            (root / 'test.cjs').write_text(NODE_TEST)
            subprocess.run(['node', '--check', str(root / 'index.js')], check=True)
            subprocess.run(['node', str(root / 'test.cjs'), str(root / 'index.js')], check=True)

    def test_generated_cli_payload(self):
        header = (UPSTREAM / 'userspace/src/nm.h').read_text()
        header = HOST_ARCH + header[header.index('/* --- DEFS --- */'):]
        body = adapt_cli((UPSTREAM / 'userspace/src/nm.c').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'nm.h').write_text(header)
            (root / 'nm.c').write_text(body + HOST_MAIN)
            binary = root / 'nm'
            subprocess.run(['cc', '-fno-builtin', '-Wno-return-type', str(root / 'nm.c'), '-o', str(binary)], check=True)
            for flag, expected in [('--whiteout', 4), ('--virtual-dir', 3), ('--opaque', 8), ('', 0)]:
                args = [str(binary), 'rule', 'add', '--uid-range', '10000-10010', '--uid-excluded', '10002-10003']
                if flag:
                    args.append(flag)
                args.append('/target')
                if flag not in ('--whiteout', '--virtual-dir'):
                    args.append('/source')
                output = subprocess.check_output(args)
                self.assertEqual(len(output), 4096)
                self.assertEqual(struct.unpack_from('<I', output, 8)[0], 2)
                self.assertEqual(struct.unpack_from('<IIIIIHH', output, 28), (expected, 10000, 10010, 10002, 10003, 7, 0 if expected in (3, 4) else 7))
                self.assertEqual(output[52:59], b'/target')
            for flags in [('--virtual-dir', '--whiteout'), ('--virtual-dir', '--opaque'), ('--opaque', '--whiteout')]:
                result = subprocess.run([str(binary), 'rule', 'add', *flags, '/target'], capture_output=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b'')
            output = subprocess.check_output([str(binary), 'rule', 'del', '--uid-excluded', '10002-10003', '/target'])
            self.assertEqual(struct.unpack_from('<I', output, 8)[0], 3)
            self.assertEqual(struct.unpack_from('<IIIIH', output, 28), (0, 0, 10002, 10003, 7))


if __name__ == '__main__':
    unittest.main()
