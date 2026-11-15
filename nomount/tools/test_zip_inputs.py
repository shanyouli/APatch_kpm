#!/usr/bin/env python3
"""在无子模块的临时 Git 树中验证 ZIP 冻结输入；不编译、不提交。"""
import configparser
import fnmatch
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from build_zip import collect_zip_inputs, sha

ROOT = Path(__file__).resolve().parents[2]


class ZipInputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        for directory in ('nomount/module', 'nomount/upstream'):
            shutil.copytree(ROOT / directory, self.repo / directory)
        tools = self.repo / 'nomount/tools'
        tools.mkdir()
        for name in ('build_zip.py', 'build_nm.sh'):
            shutil.copy2(ROOT / 'nomount/tools' / name, tools / name)
        self.git('init', '-q')
        self.git('add', '.')
        self.tree = self.git('write-tree').decode().strip()

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.repo)

    def test_inputs_come_from_main_tree_without_nested_git(self):
        self.assertFalse((self.repo / 'nomount/upstream/nomount/.git').exists())
        inputs, contents, sources, origin = collect_zip_inputs(self.repo, self.tree)
        self.assertEqual(origin, 'bf1847f98fed382369c43bfd652cd93774b9b8e3')
        expected = (self.repo / 'nomount/upstream/nomount/userspace/src/nm.c').read_bytes()
        self.assertEqual(sources['nm.c'], expected)
        self.assertEqual(inputs['nomount/upstream/nomount/userspace/src/nm.c'], sha(expected))
        self.assertEqual(contents['sources/UPSTREAM.json'], (self.repo / 'nomount/upstream/SOURCE.json').read_bytes())
        self.assertEqual(contents['webroot/index.js'], (self.repo / 'nomount/upstream/nomount/module/webroot/index.js').read_bytes())
        self.assertNotIn('nomount/upstream/nomount/kernel/src/nomount.c', inputs)
        self.assertFalse(any(row.startswith(b'160000 ') for row in self.git('ls-files', '-s').splitlines()))
        # 指定 Git 对象必须隔离随后发生的工作树变化。
        (self.repo / 'nomount/upstream/nomount/userspace/src/nm.c').write_text('changed')
        self.assertEqual(collect_zip_inputs(self.repo, self.tree)[2]['nm.c'], expected)

    def test_missing_source_is_rejected(self):
        (self.repo / 'nomount/upstream/nomount/userspace/src/nm.h').unlink()
        self.git('add', '-u')
        tree = self.git('write-tree').decode().strip()
        with self.assertRaisesRegex(ValueError, '源码输入不完整'):
            collect_zip_inputs(self.repo, tree)

    def test_invalid_provenance_is_rejected(self):
        path = self.repo / 'nomount/upstream/SOURCE.json'
        provenance = json.loads(path.read_text())
        provenance['revision'] = 'HEAD'
        path.write_text(json.dumps(provenance))
        self.git('add', '.')
        tree = self.git('write-tree').decode().strip()
        with self.assertRaisesRegex(ValueError, '来源记录无效'):
            collect_zip_inputs(self.repo, tree)

    def test_ci_matches_nested_zip_files_and_registration_is_removed(self):
        workflow = (ROOT / '.github/workflows/build-kpm.yml').read_text()
        self.assertEqual(workflow.count('- "nomount/upstream/**"'), 2)
        for path in ('nomount/upstream/nomount/module/webroot/index.js',
                     'nomount/upstream/nomount/module/webroot/locales/zh.json',
                     'nomount/upstream/SOURCE.json'):
            self.assertTrue(fnmatch.fnmatchcase(path, 'nomount/upstream/**'))
        self.assertFalse(fnmatch.fnmatchcase('unrelated/module/index.js', 'nomount/upstream/**'))
        modules = configparser.ConfigParser()
        modules.read(ROOT / '.gitmodules')
        self.assertNotIn('submodule "nomount/upstream/nomount"', modules.sections())
        self.assertIn('submodule "KernelPatch"', modules.sections())
        self.assertIn('submodule "zram_zstd/upstream/zstd"', modules.sections())


if __name__ == '__main__':
    unittest.main()
