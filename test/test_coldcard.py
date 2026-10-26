#! /usr/bin/env python3

import argparse
import atexit
import copy
import glob
import os
import signal
import subprocess
import sys
import time
import unittest

from hwilib._cli import process_commands
from hwilib import _bech32 as bech32
from hwilib import anti_exfil as ae
from hwilib.commands import get_client
from hwilib.common import Chain
from hwilib.key import G, point_mul, point_to_bytes
from hwilib.psbt import PSBT
from hwilib.devices.coldcard import _firmware_version_supports_psbt_v2
from test_device import (
    Bitcoind,
    DeviceEmulator,
    DeviceTestCase,
    TestDeviceConnect,
    TestDisplayAddress,
    TestGetKeypool,
    TestGetDescriptors,
    TestRegisterDescriptor,
    TestSignMessage,
    TestSignTx,
)


class TestColdcardFirmware(unittest.TestCase):
    def test_psbt_v2_support(self):
        versions = {
            "5.1.4": False,
            "5.2.0": True,
            "5.6.0": True,
            "1.0.0Q": True,
            "6.6.0X": True,
            "unknown": False,
        }
        for version, expected in versions.items():
            with self.subTest(version=version):
                self.assertEqual(
                    _firmware_version_supports_psbt_v2(version),
                    expected,
                )


class ColdcardSimulator(DeviceEmulator):
    def __init__(self, simulator, is_edge=False, segregate=False):
        try:
            os.unlink("coldcard-emulator.stdout")
        except FileNotFoundError:
            pass
        self.simulator = simulator
        self.segregate = segregate
        self.coldcard_log = None
        self.coldcard_proc = None
        self.type = "coldcard"
        self.path = "/tmp/ckcc-simulator.sock"
        self.fingerprint = "0f056943"
        self.master_xpub = "tpubDCiHGUNYdRRBPNYm7CqeeLwPWfeb2ZT2rPsk4aEW3eUoJM93jbBa7hPpB1T9YKtigmjpxHrB1522kSsTxGm9V6cqKqrp1EDaYaeJZqcirYB"
        self.password = ""
        self.supports_ms_display = not is_edge
        self.supports_xpub_ms_display = False
        self.supports_unsorted_ms = False
        self.supports_taproot = is_edge
        self.supports_anti_exfil = is_edge
        self.strict_bip48 = False
        self.include_xpubs = False
        self.supports_device_multiple_multisig = True
        self.supports_legacy = True
        self.supports_arbitrary_keypool_paths = True

    def start(self):
        super().start()
        self.coldcard_log = open("coldcard-emulator.stdout", "a")
        # A protected-only run uses the firmware's private socket and never
        # probes other emulators via enumerate(). Full suites keep discovery.
        if self.segregate:
            readme = os.path.join(os.path.dirname(self.simulator), "work", "VirtDisk", "README.md")
            if not os.path.exists(readme):
                with open(readme, "w") as stream:
                    stream.write("Isolated simulator runtime\n")
        # Start the Coldcard simulator
        self.coldcard_proc = subprocess.Popen(
            [
                "python3",
                os.path.basename(self.simulator), "--ms", "--headless"
            ] + (["--segregate"] if self.segregate else []),
            cwd=os.path.dirname(self.simulator),
            stdout=self.coldcard_log,
            preexec_fn=os.setsid
        )
        if self.segregate:
            self.path = f"/tmp/ckcc-simulator-{self.coldcard_proc.pid}.sock"
        # Wait for simulator to be up
        deadline = time.monotonic() + 60
        while True:
            if time.monotonic() > deadline:
                self.stop()
                raise RuntimeError("Coldcard simulator did not become ready")
            # Prevent CI from lingering until timeout:
            if self.coldcard_proc.poll() is not None:
                raise RuntimeError(f"coldcard simulator failed with exit code {self.coldcard_proc.poll()}")

            try:
                if self.segregate:
                    client = get_client("coldcard", self.path, chain=Chain.TEST)
                    try:
                        if client.get_master_fingerprint().hex() == self.fingerprint:
                            break
                    finally:
                        client.close()
                    continue
                enum_res = process_commands(["--emulators", "enumerate"])
                found = False
                for dev in enum_res:
                    if dev["type"] == "coldcard" and "error" not in dev:
                        found = True
                        break
                if found:
                    break
            except Exception:
                pass
            time.sleep(0.5)
        atexit.register(self.stop)

    def stop(self):
        super().stop()
        if self.coldcard_proc.poll() is None:
            os.killpg(os.getpgid(self.coldcard_proc.pid), signal.SIGTERM)
            os.waitpid(os.getpgid(self.coldcard_proc.pid), 0)
        self.coldcard_log.close()
        atexit.unregister(self.stop)

# Coldcard specific management command tests
class TestColdcardManCommands(DeviceTestCase):
    def test_setup(self):
        result = self.do_command(self.dev_args + ['-i', 'setup'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Coldcard does not support software setup')
        self.assertEqual(result['code'], -9)

    def test_wipe(self):
        result = self.do_command(self.dev_args + ['wipe'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Coldcard does not support wiping via software')
        self.assertEqual(result['code'], -9)

    def test_restore(self):
        result = self.do_command(self.dev_args + ['-i', 'restore'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Coldcard does not support restoring via software')
        self.assertEqual(result['code'], -9)

    def test_backup(self):
        result = self.do_command(self.dev_args + ['backup'])
        self.assertTrue(result['success'])
        for filename in glob.glob("backup-*.7z"):
            os.remove(filename)

    def test_pin(self):
        result = self.do_command(self.dev_args + ['promptpin'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Coldcard does not need a PIN sent from the host')
        self.assertEqual(result['code'], -9)

        result = self.do_command(self.dev_args + ['sendpin', '1234'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Coldcard does not need a PIN sent from the host')
        self.assertEqual(result['code'], -9)

class TestColdcardGetXpub(DeviceTestCase):
    def test_getxpub(self):
        result = self.do_command(self.dev_args + ['--expert', 'getxpub', 'm/44h/0h/0h/3'])
        self.assertEqual(result['xpub'], 'tpubDFHiBJDeNvqPWNJbzzxqDVXmJZoNn2GEtoVcFhMjXipQiorGUmps3e5ieDGbRrBPTFTh9TXEKJCwbAGW9uZnfrVPbMxxbFohuFzfT6VThty')
        self.assertTrue(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 4)
        self.assertEqual(result['parent_fingerprint'], 'bc123c3e')
        self.assertEqual(result['child_num'], 3)
        self.assertEqual(result['chaincode'], '806b26507824f73bc331494afe122f428ef30dde80b2c1ce025d2d03aff411e7')
        self.assertEqual(result['pubkey'], '0368000bdff5e0b71421c37b8514de8acd4d98ba9908d183d9da56d02ca4fcfd08')

class TestColdcardEdgeDisplayAddress(DeviceTestCase):
    def test_display_taproot_address(self):
        descriptors = self.do_command(self.dev_args + [
            'getkeypool', '--addr-type', 'tap', '0', '0'
        ])
        expected = self.rpc.deriveaddresses(descriptors[0]['desc'], [0, 0])[0]

        result = self.do_command(self.dev_args + [
            'displayaddress', '--addr-type', 'tap', '--path', 'm/86h/1h/0h/0/0'
        ])
        self.assertNotIn('error', result)
        self.assertIn('address', result)
        displayed_witness = bech32.decode('tb', result['address'])
        expected_witness = bech32.decode('bcrt', expected)
        self.assertEqual(displayed_witness, expected_witness)

class TestColdcardAntiExfil(DeviceTestCase):
    """Opt-in tests requiring a Coldcard Edge firmware built with the draft protocol."""

    def setUp(self):
        super().setUp()
        self.dev_args[self.dev_args.index("-d") + 1] = self.emulator.path
        self.setup_wallets()

    def test_taproot_anti_exfil(self):
        descriptors = self.do_command(self.dev_args + ["getkeypool", "--addr-type", "tap", "0", "5"])
        self.assertIsInstance(descriptors, list, descriptors)
        self.assertTrue(all(result["success"] for result in self.wrpc.importdescriptors(descriptors)))

        for hash_type, version in ((None, 0), (0, 2), (1, 0), (1, 2)):
            with self.subTest(sighash=hash_type, psbt_version=version):
                address = self.wrpc.getnewaddress("", "bech32m")
                txid = self.wpk_rpc.sendtoaddress(address, 1)
                self.wpk_rpc.generatetoaddress(1, self.wpk_rpc.getnewaddress())
                coins = [coin for coin in self.wrpc.listunspent() if coin["txid"] == txid]
                self.assertEqual(len(coins), 1)
                funded = self.wrpc.walletcreatefundedpsbt(
                    [{"txid": txid, "vout": coins[0]["vout"]}],
                    [{self.wpk_rpc.getnewaddress(): 0.5}], 0,
                    {"add_inputs": False}, True,
                )
                request = PSBT()
                request.deserialize(funded["psbt"])
                self.assertEqual(len(request.inputs), 1)
                request.inputs[0].sighash = hash_type
                if version == 2:
                    request.convert_to_v2()
                pubkey = ae.get_utxo(request, 0).scriptPubKey[2:]
                entropy = (5 if hash_type is None else 6).to_bytes(32, "big")
                request.inputs[0].unknown[ae.key(ae.HOST_COMMITMENT, pubkey)] = ae.host_commit(entropy)
                for mapping in [request.unknown] + [item.unknown for item in request.inputs + request.outputs]:
                    mapping[bytes.fromhex("fc017800")] = b"original caller metadata"
                unsigned = request.get_unsigned_tx().serialize_without_witness()

                first_result = self.do_command(self.dev_args + ["signtx", request.serialize()])
                self.assertNotIn("error", first_result, first_result)
                self.assertFalse(first_result["signed"])
                first = PSBT()
                first.deserialize(first_result["psbt"])
                expected = copy.deepcopy(request)
                self.assertFalse(first.inputs[0].tap_key_sig)
                nonce = first.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, pubkey)]
                self.assertEqual(len(nonce), 33)
                expected.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, pubkey)] = nonce
                self.assertEqual(first.serialize(), expected.serialize())
                self.assertEqual(first.get_unsigned_tx().serialize_without_witness(), unsigned)
                # Reconnecting between subprocess calls does not lose the device's commitment.
                retry_result = self.do_command(self.dev_args + ["signtx", request.serialize()])
                self.assertNotIn("error", retry_result, retry_result)
                retry = PSBT()
                retry.deserialize(retry_result["psbt"])
                self.assertEqual(retry.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, pubkey)], nonce)
                first.inputs[0].unknown[ae.key(ae.HOST_ENTROPY, pubkey)] = entropy

                # Bypass HWI preflight here: the firmware itself must reject a wrong
                # opening and a changed round-1 nonce rather than sign anyway.
                for bad_entropy, bad_nonce in ((True, False), (False, True)):
                    bad = copy.deepcopy(first)
                    if bad_entropy:
                        bad.inputs[0].unknown[ae.key(ae.HOST_ENTROPY, pubkey)] = (7).to_bytes(32, "big")
                    if bad_nonce:
                        bad.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, pubkey)] = point_to_bytes(point_mul(G, 7))
                    client = get_client("coldcard", self.emulator.path, chain=Chain.TEST)
                    try:
                        client.device.check_mitm()
                        with self.assertRaises(Exception):
                            client._sign_tx_once(bad)
                    finally:
                        client.close()

                signed_result = self.do_command(self.dev_args + ["signtx", first.serialize()])
                self.assertNotIn("error", signed_result, signed_result)
                signed = PSBT()
                signed.deserialize(signed_result["psbt"])
                expected = copy.deepcopy(first)
                for index, psbt_in in enumerate(signed.inputs):
                    expected.inputs[index].tap_key_sig = psbt_in.tap_key_sig
                self.assertEqual(signed.serialize(), expected.serialize())
                self.assertEqual(signed.get_unsigned_tx().serialize_without_witness(), unsigned)
                signature = signed.inputs[0].tap_key_sig
                self.assertEqual(len(signature), 64 if hash_type in (None, 0) else 65)
                self.assertTrue(ae.host_verify(pubkey, ae.signature_hash(request, 0, hash_type or 0), signature[:64], entropy, nonce))
                finalized = self.wrpc.finalizepsbt(signed.serialize())
                self.assertTrue(finalized["complete"])
                self.assertTrue(self.wrpc.testmempoolaccept([finalized["hex"]])[0]["allowed"])
                sent = self.wrpc.sendrawtransaction(finalized["hex"])
                self.wpk_rpc.generatetoaddress(1, self.wpk_rpc.getnewaddress())
                self.assertGreater(self.wrpc.gettransaction(sent)["confirmations"], 0)


# Ledger specific disabled command tests
def coldcard_test_suite(simulator, bitcoind, interface, is_edge=False, anti_exfil=False):
    dev_emulator = ColdcardSimulator(simulator, is_edge, segregate=anti_exfil)
    if anti_exfil:
        if not is_edge:
            raise ValueError("Coldcard anti-exfil tests require Edge firmware")
        suite = DeviceTestCase.parameterize(TestColdcardAntiExfil, bitcoind, emulator=dev_emulator, interface=interface)
        return unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite).wasSuccessful()

    signtx_cases = [
        (["legacy"], [], False, False),
        (["segwit"], [], False, False),
        (["legacy", "segwit"], [], False, False),
    ]

    # Generic device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestColdcardManCommands, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestColdcardGetXpub, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type="coldcard"))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type="coldcard"))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, bitcoind, emulator=dev_emulator, interface=interface, signtx_cases=signtx_cases))
    suite.addTest(DeviceTestCase.parameterize(
        TestRegisterDescriptor,
        bitcoind,
        emulator=dev_emulator,
        interface=interface,
        returns_registration=False,
        supports_multiple_policies=is_edge,
    ))
    if is_edge:
        suite.addTest(DeviceTestCase.parameterize(TestColdcardEdgeDisplayAddress, bitcoind, emulator=dev_emulator, interface=interface))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Coldcard implementation')
    parser.add_argument('simulator', help='Path to the Coldcard simulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    parser.add_argument('--edge', help='Test Coldcard Edge behavior', action='store_true')
    args = parser.parse_args()

    # Start bitcoind
    bitcoind = Bitcoind.create(args.bitcoind)

    sys.exit(not coldcard_test_suite(args.simulator, bitcoind, args.interface, is_edge=args.edge))
