# SPDX-License-Identifier: GPL-3.0-or-later
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from wg_program_split.command import capture


class CommandTests(unittest.TestCase):
    def run_script(self, code, **kwargs):
        return capture([sys.executable, '-c', code], **kwargs)

    def test_empty_and_large_bidirectional_input(self):
        self.assertEqual(self.run_script('import sys; print(len(sys.stdin.buffer.read()))', input=b''), '0\n')
        data = b'x' * (2 * 1024 * 1024)
        self.assertEqual(self.run_script(
            'import os,sys; os.write(2,b"e"*200000); '
            'sys.stdout.buffer.write(sys.stdin.buffer.read())', input=data), data.decode())

    def test_exact_output_limit(self):
        self.assertEqual(self.run_script('import os; os.write(1,b"x"*128)', maximum=128), 'x'*128)
        with self.assertRaises(subprocess.SubprocessError):
            self.run_script('import os; os.write(1,b"x"*129)', maximum=128)

    def test_stderr_limit_and_nonzero_exit_redact_content(self):
        for code in ('import os; os.write(2,b"private"*100000)',
                     'import sys; sys.stderr.write("private"); sys.exit(4)'):
            with self.assertRaises(subprocess.SubprocessError) as error:
                self.run_script(code, stderr_maximum=128)
            self.assertNotIn('private', str(error.exception))

    def test_timeout_and_overflow_reap_child(self):
        with tempfile.TemporaryDirectory() as temp:
            pid = Path(temp) / 'pid'
            for ending in ('time.sleep(60)', 'os.write(1,b"x"*1000000); time.sleep(60)'):
                code = f'import os,time; open({str(pid)!r},"w").write(str(os.getpid())); ' + ending
                with self.assertRaises(subprocess.SubprocessError):
                    self.run_script(code, timeout=.2, maximum=128)
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pid.read_text()), 0)

    def test_invalid_utf8_is_rejected(self):
        with self.assertRaises(UnicodeError):
            self.run_script('import os; os.write(1,b"\\xff")')

    def test_early_stdin_close_is_bounded(self):
        self.assertEqual(self.run_script('import os; os.close(0); print("done")', input=b'x'*1000000), 'done\n')

    def test_trusted_environment(self):
        result = self.run_script('import os; print(os.getenv("PATH")); print(os.getenv("LC_ALL"))')
        self.assertEqual(result, '/usr/sbin:/usr/bin:/sbin:/bin\nC\n')


if __name__ == '__main__':
    unittest.main()
