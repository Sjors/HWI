#! /usr/bin/env python3
"""Unit tests for the Bitcoin Core IPC signer service helpers.

These need no device and no pycapnp; the device integration test lives in
test_core_ipc.py.
"""

import unittest
from pathlib import Path
from unittest.mock import patch

from hwilib import _ipc
from hwilib.common import Chain


class TestDefaultSocketPath(unittest.TestCase):
    def test_linux(self):
        with patch("sys.platform", "linux"), patch.object(Path, "home", return_value=Path("/home/user")):
            self.assertEqual(_ipc.default_socket_path(Chain.MAIN), "/home/user/.bitcoin/node.sock")
            self.assertEqual(_ipc.default_socket_path(Chain.TEST), "/home/user/.bitcoin/testnet3/node.sock")
            self.assertEqual(_ipc.default_socket_path(Chain.REGTEST), "/home/user/.bitcoin/regtest/node.sock")
            self.assertEqual(_ipc.default_socket_path(Chain.SIGNET), "/home/user/.bitcoin/signet/node.sock")
            self.assertEqual(_ipc.default_socket_path(Chain.TESTNET4), "/home/user/.bitcoin/testnet4/node.sock")

    def test_macos(self):
        with patch("sys.platform", "darwin"), patch.object(Path, "home", return_value=Path("/Users/satoshi")):
            self.assertEqual(_ipc.default_socket_path(Chain.MAIN), "/Users/satoshi/Library/Application Support/Bitcoin/node.sock")
            self.assertEqual(_ipc.default_socket_path(Chain.REGTEST), "/Users/satoshi/Library/Application Support/Bitcoin/regtest/node.sock")

    def test_windows(self):
        with patch("sys.platform", "win32"), patch.dict(_ipc.os.environ, {"APPDATA": "C:/Users/satoshi/AppData/Roaming"}):
            self.assertEqual(_ipc.default_socket_path(Chain.MAIN), str(Path("C:/Users/satoshi/AppData/Roaming") / "Bitcoin" / "node.sock"))


if __name__ == "__main__":
    unittest.main()
