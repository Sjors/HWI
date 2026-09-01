#! /usr/bin/env python3
"""Bitcoin Core integration test for the IPC signer service.

Starts a multiprocess bitcoin-node with an IPC socket, runs `hwi ipc` as a
long-lived process registered as the node's external signer, and drives the
device entirely through Bitcoin Core RPCs: enumeratesigners, wallet creation
with external_signer=true (getdescriptors), walletdisplayaddress and send
(signtx). See Bitcoin Core's doc/external-signer.md.
"""

import atexit
import os
import re
import subprocess
import sys
import time
import unittest

from test_device import Bitcoind, DeviceTestCase

from authproxy import AuthServiceProxy, JSONRPCException
from hwilib import _bech32 as bech32

# Address type per descriptor prefix, in HWI getdescriptors output order
DESC_ADDRESS_TYPES = [
    ("sh(wpkh(", "p2sh-segwit"),
    ("pkh(", "legacy"),
    ("wpkh(", "bech32"),
    ("tr(", "bech32m"),
]


class BitcoinNode(Bitcoind):
    """A regtest bitcoin-node with an IPC socket for signer registration."""

    def __init__(self, path):
        super().__init__(path)
        self.ipc_socket_path = os.path.join(self.datadir, "regtest", "node.sock")
        self.extra_args = [f"-ipcbind=unix:{self.ipc_socket_path}"]


class TestCoreSignerIPC(DeviceTestCase):
    def daemon_command(self):
        """How to launch the signer daemon, following the same interface
        convention as DeviceTestCase.do_command, so this test can run
        against an installed or frozen HWI rather than the source tree."""
        if self.interface == "cli":
            return ["hwi"]
        if self.interface == "bindist":
            return [os.path.join("..", "dist", "hwi")]
        return [sys.executable, os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "hwi.py")]

    def setUp(self):
        super().setUp()  # starts the emulator
        daemon_args = self.daemon_command() + ["--emulators", "--debug"]
        daemon_args.extend(self.get_password_args())
        daemon_args.extend(["ipc", "--socket-path", self.bitcoind.ipc_socket_path])
        self.daemon_stdout = open("core-ipc-hwi.stdout", "a")
        self.daemon_stderr = open("core-ipc-hwi.stderr", "a")
        self.daemon = subprocess.Popen(daemon_args, stdout=self.daemon_stdout, stderr=self.daemon_stderr)
        atexit.register(self.stop_daemon)
        self.wait_for_registration()

    def stop_daemon(self):
        if self.daemon.poll() is None:
            self.daemon.kill()
            self.daemon.wait()
        self.daemon_stdout.close()
        self.daemon_stderr.close()

    def tearDown(self):
        self.stop_daemon()
        super().tearDown()  # stops the emulator

    def wait_for_registration(self, timeout=30):
        """Wait until the daemon has registered and reports our device."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.daemon.poll() is not None:
                raise RuntimeError(f"hwi ipc exited with {self.daemon.poll()}, see core-ipc-hwi.stderr")
            try:
                signers = self.rpc.enumeratesigners()["signers"]
                if any(signer["fingerprint"] == self.emulator.fingerprint for signer in signers):
                    return
            except JSONRPCException:
                pass
            time.sleep(0.5)
        raise RuntimeError("hwi ipc did not register with the node in time")

    def get_wallet_rpc(self, wallet):
        # Signing waits for the device, so use a generous timeout to fail
        # instead of hanging if a simulator gets stuck.
        url = self.bitcoind.rpc_url + f"/wallet/{wallet}"
        return AuthServiceProxy(url, timeout=120)

    def device_descriptors(self):
        """The device's receive descriptors for regtest, with the address
        type Bitcoin Core maps each of them to."""
        result = self.do_command(self.dev_args_regtest() + ["getdescriptors"])
        self.assertNotIn("error", result)
        descriptors = []
        for descriptor in result["receive"]:
            for prefix, address_type in DESC_ADDRESS_TYPES:
                if descriptor.startswith(prefix):
                    descriptors.append((descriptor, address_type))
                    break
        return descriptors

    def dev_args_regtest(self):
        # Self-contained variant of self.dev_args: the node runs regtest, so
        # compare against descriptors for the same chain.
        args = ["-t", self.emulator.type, "-d", self.emulator.path, "--chain", "regtest", "--emulators"]
        args.extend(self.get_password_args())
        return args

    def create_signer_wallet(self):
        wallet_name = f"{self.emulator.type}_{self.id()}"
        self.rpc.createwallet(wallet_name=wallet_name, disable_private_keys=True, external_signer=True)
        wrpc = self.get_wallet_rpc(wallet_name)
        self.assertTrue(wrpc.getwalletinfo()["external_signer"])
        return wrpc

    def test_enumerate(self):
        signers = self.rpc.enumeratesigners()["signers"]
        self.assertTrue(any(signer["fingerprint"] == self.emulator.fingerprint for signer in signers))

    def test_create_wallet_and_addresses(self):
        wrpc = self.create_signer_wallet()
        for descriptor, address_type in self.device_descriptors():
            normalized = self.rpc.getdescriptorinfo(descriptor)["descriptor"]
            expected = self.rpc.deriveaddresses(normalized, [0, 0])[0]
            self.assertEqual(wrpc.getnewaddress(address_type=address_type), expected)

    def supports_regtest(self):
        """The legacy Ledger app (and its HWI client) does not handle the
        regtest chain Bitcoin Core reports over IPC: it renders mainnet
        addresses and rejects signing with "Bad argument"."""
        return not getattr(self.emulator, "legacy", False)

    def supports_display_address(self):
        """The original Digital Bitbox has no screen on which to display an
        address."""
        return self.emulator.type != "digitalbitbox"

    def test_display_address(self):
        if not self.supports_regtest():
            raise unittest.SkipTest("device client does not support regtest")
        if not self.supports_display_address():
            raise unittest.SkipTest("device does not have a screen")
        wrpc = self.create_signer_wallet()
        address = wrpc.getnewaddress(address_type="bech32")
        try:
            result = wrpc.walletdisplayaddress(address)
            self.assertEqual(result, {"address": address})
        except JSONRPCException as e:
            # Some devices (e.g. Coldcard) render regtest addresses with the
            # testnet HRP, which Core's echo check rejects. Verify the device
            # still displayed the same witness program.
            match = re.search(r"Signer echoed unexpected address (\S+)", e.error["message"])
            self.assertIsNotNone(match, f"unexpected error: {e}")
            echoed = match.group(1)
            self.assertEqual(bech32.decode("tb", echoed), bech32.decode("bcrt", address))

    def test_send(self):
        if not self.supports_regtest():
            raise unittest.SkipTest("device client does not support regtest")
        wrpc = self.create_signer_wallet()
        supply = self.bitcoind.wrpc
        address_types = [address_type for _, address_type in self.device_descriptors()]

        # Some devices can derive descriptors for address types they cannot
        # sign (the BitBox02 cannot sign legacy inputs). Taproot inputs are
        # spent in their own transaction: the Coldcard
        # Edge simulator rejects PSBTs mixing taproot with other segwit
        # inputs, and when an input remains unsigned the Core wallet
        # re-invokes the signer with a partially finalized PSBT, which
        # strict devices reject. This mirrors the input type combinations
        # the existing HWI signing tests cover.
        groups = []
        non_tap = [
            t for t in address_types
            if t != "bech32m" and (t != "legacy" or self.emulator.supports_legacy)
        ]
        if non_tap:
            groups.append(non_tap)
        if "bech32m" in address_types:
            groups.append(["bech32m"])

        dest = supply.getnewaddress()
        for group in groups:
            addresses = [wrpc.getnewaddress(address_type=address_type) for address_type in group]
            for address in addresses:
                supply.sendtoaddress(address, 1)
            supply.generatetoaddress(1, supply.getnewaddress())
            utxos = [u for u in wrpc.listunspent() if u["address"] in addresses]
            self.assertEqual(len(utxos), len(group))
            inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in utxos]
            res = wrpc.send(outputs={dest: len(group) - 0.5}, inputs=inputs, add_inputs=False, add_to_wallet=False)
            self.assertTrue(res["complete"])
            self.assertEqual(len(wrpc.decoderawtransaction(res["hex"])["vin"]), len(group))
            self.assertTrue(wrpc.testmempoolaccept([res["hex"]])[0]["allowed"])


def core_ipc_test_suite(emulator, bitcoin_node_path, interface):
    node = BitcoinNode.create(bitcoin_node_path)
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestCoreSignerIPC, node, emulator=emulator, interface=interface))
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    node.cleanup()
    atexit.unregister(node.cleanup)
    return result.wasSuccessful()
