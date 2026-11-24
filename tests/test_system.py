import json
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ReconnaissanceSystemTests(unittest.TestCase):
    def test_waitress_serves_the_recorded_report(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(PROJECT_ROOT)
        server = subprocess.Popen(
            [sys.executable, "-m", "src.server", "--host", "127.0.0.1", "--port", str(port)],
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 10
            data = None
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    self.fail(f"Waitress exited with status {server.returncode}.")
                try:
                    with urlopen(f"http://127.0.0.1:{port}/api/report", timeout=1) as response:
                        data = json.loads(response.read())
                    break
                except (URLError, TimeoutError, ConnectionError):
                    time.sleep(0.1)
            self.assertIsNotNone(data, "Waitress did not become ready.")
            self.assertEqual(data["scope"]["domain"], "kwachahelper.com")
            self.assertEqual(data["finding_count"], 0)
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
