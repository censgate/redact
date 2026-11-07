"""An unrelated listening server must never authorize harness writes."""
import importlib.util
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('harness', Path(__file__).with_name('test-local.py'))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)

class InstanceChecks(unittest.TestCase):
    def test_failed_child_cannot_borrow_unrelated_listener(self):
        with socket.socket() as unrelated:
            unrelated.bind(('127.0.0.1', 0))
            unrelated.listen()
            child = Mock()
            child.poll.return_value = 1
            with self.assertRaises(RuntimeError):
                harness.ready(child, unrelated.getsockname()[1])

    def test_identity_check_rejects_other_data_directory(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        with tempfile.TemporaryDirectory() as expected:
            response = subprocess.CompletedProcess([], 0, stdout='/unrelated/fixture\n')
            with patch.object(harness.subprocess, 'run', return_value=response) as run:
                with self.assertRaises(RuntimeError):
                    harness.verify_postgres(child, ['psql'], Path(expected))
                self.assertEqual(run.call_args.args[0], ['psql', '-At', '-c', 'SHOW data_directory'])

    def test_identity_check_requires_child_postmaster_pid(self):
        child = Mock(pid=123)
        child.poll.return_value = None
        with tempfile.TemporaryDirectory() as expected:
            Path(expected, 'postmaster.pid').write_text('456\n')
            response = subprocess.CompletedProcess([], 0, stdout=expected+'\n')
            with patch.object(harness.subprocess, 'run', return_value=response):
                with self.assertRaises(RuntimeError):
                    harness.verify_postgres(child, ['psql'], Path(expected))

if __name__ == '__main__':
    unittest.main()
