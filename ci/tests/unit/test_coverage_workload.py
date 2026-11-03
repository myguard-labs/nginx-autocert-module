"""Exercise the coverage server workload without rebuilding nginx."""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "ci/tools/coverage.sh"
FUNCTION_MATCH = re.search(
    r"^run_server_workload\(\) \{\n.*?^\}(?=\n\n# ---- 3\.)",
    SCRIPT.read_text(),
    re.MULTILINE | re.DOTALL,
)
assert FUNCTION_MATCH is not None, "coverage server workload function not found"
FUNCTION = FUNCTION_MATCH.group()

# Bind the configured socket with the real kernel limit; only nginx's module
# loading and worker log are simulated. No daemon or network access is needed.
NGINX = """#!/usr/bin/env python3
import os
import pathlib
import re
import socket
import sys

if '-s' in sys.argv:
    sys.exit(0)
config = pathlib.Path(sys.argv[sys.argv.index('-c') + 1]).read_text()
address = re.search(r'listen unix:(.*);', config).group(1)
with socket.socket(socket.AF_UNIX) as listener:
    listener.bind(address)
log = re.search(r'error_log (.*) notice;', config).group(1)
pathlib.Path(log).write_text(
    'autocert: ACME driver armed on worker 0' if os.environ['ARM_WORKER'] == '1' else ''
)
"""


class CoverageWorkloadTest(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(
            tempfile.TemporaryDirectory(prefix="autocert-coverage-test.")
        )
        self.workspace = Path(temp) / ("checkout-" + "x" * 120)
        (self.workspace / ".build").mkdir(parents=True)
        self.build = self.workspace / "nginx-test"
        (self.build / "objs").mkdir(parents=True)
        (self.build / "objs/ngx_http_autocert_module.so").touch()
        binary = self.build / "objs/nginx"
        binary.write_text(NGINX)
        binary.chmod(0o755)

    def run_workload(self, function=FUNCTION, armed=True):
        result = subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail\nworkspace="$1"\nbuild_dir="$2"\n'
                'server_prefix=""\n'
                'trap \'printf "prefix=%s\\n" "$server_prefix"; '
                'rm -rf "$server_prefix"\' EXIT\n'
                + function
                + "\nrun_server_workload\n",
                "coverage-test",
                str(self.workspace),
                str(self.build),
            ],
            env={
                **os.environ,
                "TMPDIR": str(self.workspace),
                "ARM_WORKER": str(int(armed)),
            },
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        match = re.search(r"^prefix=(.+)$", result.stdout, re.MULTILINE)
        self.assertIsNotNone(match, result.stdout + result.stderr)
        prefix = match.group(1)
        self.assertFalse(Path(prefix).exists(), "workload prefix was not cleaned up")
        return result, prefix

    def test_long_checkout_and_tmpdir(self):
        result, first = self.run_workload()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("armed worker 0", result.stdout)
        self.assertLess(len(os.fsencode(first + "/coverage.sock")), 108)
        result, second = self.run_workload()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(first, second)

    def test_original_workspace_allocation_fails(self):
        original = FUNCTION.replace(
            "mktemp -d /tmp/autocert-cov.XXXXXX",
            'mktemp -d "$workspace/.build/coverage-server.XXXXXX"',
        )
        self.assertNotEqual(
            original, FUNCTION, "negative control did not mutate the allocator"
        )
        result, _ = self.run_workload(original)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AF_UNIX path too long", result.stderr)

    def test_missing_module_fails(self):
        (self.build / "objs/ngx_http_autocert_module.so").unlink()
        result, _ = self.run_workload()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("coverage server workload needs", result.stderr)

    def test_unarmed_worker_fails(self):
        result, _ = self.run_workload(armed=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not reach ngx_autocert_driver_init_process", result.stderr)


if __name__ == "__main__":
    unittest.main()
