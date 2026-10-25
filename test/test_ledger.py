#! /usr/bin/env python3

import argparse
import atexit
import copy
import os
import subprocess
import signal
import shlex
import sys
import time
import unittest

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

from hwilib._cli import process_commands
from hwilib import anti_exfil as ae
from hwilib.commands import get_client
from hwilib.common import Chain
from hwilib.key import G, point_mul, point_to_bytes
from hwilib.psbt import PSBT

class LedgerEmulator(DeviceEmulator):
    def __init__(self, path, legacy=False):
        self.emulator_path = path
        self.emulator_proc = None
        self.emulator_stderr = None
        self.emulator_stdout = None
        self.legacy = legacy
        try:
            os.unlink('ledger-emulator.stderr')
        except FileNotFoundError:
            pass
        self.type = "ledger"
        self.path = 'tcp:127.0.0.1:9999'
        self.fingerprint = 'f5acc2fd'
        self.master_xpub = 'tpubDCwYjpDhUdPGP5rS3wgNg13mTrrjBuG8V9VpWbyptX6TRPbNoZVXsoVUSkCjmQ8jJycjuDKBb9eataSymXakTTaGifxR6kmVsfFehH1ZgJT'
        self.password = ""
        self.supports_ms_display = False # Legacy does not multisig address display; tests not updated for new app
        self.supports_xpub_ms_display = False # Legacy does not multisig address display; tests not updated for new app
        self.supports_unsorted_ms = False # Legacy does not support unsorted multisig; tests not updated for new app
        self.supports_taproot = not legacy # Legacy does not support Taproot
        self.supports_anti_exfil = not legacy
        self.strict_bip48 = True
        self.include_xpubs = True
        self.supports_device_multiple_multisig = True
        self.supports_legacy = True
        # Bitcoin app 2.5.0 enforces standard Ledger paths for xpub derivation.
        self.supports_arbitrary_keypool_paths = legacy

    def start(self):
        super().start()
        automation_path = os.path.abspath("data/speculos-automation.json")
        app_path = f"./apps/btc-test{'-legacy' if self.legacy else ''}.elf"
        os.environ["SPECULOS_APPNAME"] = "Bitcoin Test:1.6.6" if self.legacy else "Bitcoin Test:2.5.0"

        self.emulator_stderr = open('ledger-emulator.stderr', 'a')
        # Start the emulator
        self.emulator_proc = subprocess.Popen(
            [
                'python3',
                './' + os.path.basename(self.emulator_path),
                '--display',
                'headless',
                '--automation',
                'file:{}'.format(automation_path),
                '--log-level',
                'automation:DEBUG',
                '--log-level',
                'seproxyhal:DEBUG',
                '--api-port',
                '0',
                '--model', 'nanosp' if self.legacy else 'nanox',
                app_path
            ],
            cwd=os.path.dirname(self.emulator_path),
            stderr=self.emulator_stderr,
            preexec_fn=os.setsid,
        )
        # Wait for simulator to be up
        while True:
            # Prevent CI from lingering until timeout:
            if self.emulator_proc.poll() is not None:
                raise RuntimeError(f"Ledger simulator failed with exit code {self.emulator_proc.poll()}")

            try:
                enum_res = process_commands(["--emulators", "enumerate"])
                found = False
                for dev in enum_res:
                    if dev['type'] == 'ledger' and 'error' not in dev:
                        found = True
                        break
                if found:
                    break
            except Exception as e:
                print(str(e))
                pass
            time.sleep(0.5)
        atexit.register(self.stop)

    def stop(self):
        super().stop()
        if self.emulator_proc.poll() is None:
            os.killpg(os.getpgid(self.emulator_proc.pid), signal.SIGTERM)
            os.waitpid(self.emulator_proc.pid, 0)
        if self.emulator_stderr is not None:
            self.emulator_stderr.close()
        if self.emulator_stdout is not None:
            self.emulator_stdout.close()
        atexit.unregister(self.stop)

class TestLedgerCoreAntiExfil(DeviceTestCase):
    """Actual Core C++ host -> HWI subprocess -> Ledger firmware integration."""

    def test_core_taproot_anti_exfil(self):
        # A separate node makes the host's mandatory anti-exfil setting explicit.
        # Its subprocess uses the same installed HWI environment as this harness.
        hwi_path = os.path.join(os.path.dirname(sys.executable), "hwi")
        signer = shlex.quote(hwi_path) + " --emulators"
        node = Bitcoind.create(self.bitcoind.bitcoind_path, extra_args=["-signerantiexfil", "-signer=" + signer])
        try:
            node.rpc.createwallet(wallet_name="core_anti_exfil", disable_private_keys=True, external_signer=True)
            wallet = node.get_wallet_rpc("core_anti_exfil")
            supply = node.get_wallet_rpc("supply")
            address = wallet.getnewaddress("", "bech32m")
            supply.sendtoaddress(address, 1)
            supply.generatetoaddress(1, supply.getnewaddress())
            destination = supply.getnewaddress()
            request = wallet.walletcreatefundedpsbt([], [{destination: 0.25}], 0, {}, True)["psbt"]
            signed = wallet.walletprocesspsbt(request)
            self.assertTrue(signed["complete"])
            psbt = PSBT()
            psbt.deserialize(signed["psbt"])
            self.assertTrue(all(not any(field.startswith(ae.PREFIX) for field in item.unknown) for item in psbt.inputs))
            finalized = wallet.finalizepsbt(signed["psbt"])
            self.assertTrue(finalized["complete"])
            self.assertTrue(wallet.testmempoolaccept([finalized["hex"]])[0]["allowed"])

            # The ordinary wallet send path also invokes both C++ anti-exfil rounds,
            # then submits to the local mempool and broadcasts.
            sent = wallet.send(outputs={destination: 0.25})
            self.assertTrue(sent["complete"])
            self.assertIn(sent["txid"], node.rpc.getrawmempool())
            supply.generatetoaddress(1, supply.getnewaddress())
            self.assertGreater(wallet.gettransaction(sent["txid"])["confirmations"], 0)
        finally:
            node.cleanup()
            atexit.unregister(node.cleanup)


class TestLedgerAntiExfil(DeviceTestCase):
    """Opt-in tests requiring a Ledger app built with the draft protocol."""

    def setUp(self):
        super().setUp()
        self.setup_wallets()

    def test_taproot_anti_exfil(self):
        descriptors = self.do_command(self.dev_args + ["getkeypool", "--addr-type", "tap", "0", "5"])
        self.assertIsInstance(descriptors, list, descriptors)
        self.assertTrue(all(result["success"] for result in self.wrpc.importdescriptors(descriptors)))

        for hash_type in (None, 1):
            with self.subTest(sighash=hash_type):
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
                pubkey = ae.get_utxo(request, 0).scriptPubKey[2:]
                entropy = (5 if hash_type is None else 6).to_bytes(32, "big")
                request.inputs[0].unknown[ae.key(ae.HOST_COMMITMENT, pubkey)] = ae.host_commit(entropy)
                unsigned = request.get_unsigned_tx().serialize_without_witness()

                first_result = self.do_command(self.dev_args + ["signtx", request.serialize()])
                self.assertNotIn("error", first_result, first_result)
                self.assertFalse(first_result["signed"])
                first = PSBT()
                first.deserialize(first_result["psbt"])
                self.assertFalse(first.inputs[0].tap_key_sig)
                nonce = first.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, pubkey)]
                self.assertEqual(len(nonce), 33)
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
                    client = get_client("ledger", self.emulator.path, chain=Chain.TEST)
                    try:
                        with self.assertRaises(Exception):
                            client.sign_tx(bad)
                    finally:
                        client.close()

                signed_result = self.do_command(self.dev_args + ["signtx", first.serialize()])
                self.assertNotIn("error", signed_result, signed_result)
                signed = PSBT()
                signed.deserialize(signed_result["psbt"])
                self.assertEqual(signed.get_unsigned_tx().serialize_without_witness(), unsigned)
                signature = signed.inputs[0].tap_key_sig
                self.assertEqual(len(signature), 64 if hash_type is None else 65)
                self.assertTrue(ae.host_verify(pubkey, ae.signature_hash(request, 0, hash_type or 0), signature[:64], entropy, nonce))
                finalized = self.wrpc.finalizepsbt(signed.serialize())
                self.assertTrue(finalized["complete"])
                self.assertTrue(self.wrpc.testmempoolaccept([finalized["hex"]])[0]["allowed"])
                sent = self.wrpc.sendrawtransaction(finalized["hex"])
                self.wpk_rpc.generatetoaddress(1, self.wpk_rpc.getnewaddress())
                self.assertGreater(self.wrpc.gettransaction(sent)["confirmations"], 0)


# Ledger specific disabled command tests
class TestLedgerDisabledCommands(DeviceTestCase):
    def test_pin(self):
        result = self.do_command(self.dev_args + ['promptpin'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not need a PIN sent from the host')
        self.assertEqual(result['code'], -9)

        result = self.do_command(self.dev_args + ['sendpin', '1234'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not need a PIN sent from the host')
        self.assertEqual(result['code'], -9)

    def test_setup(self):
        result = self.do_command(self.dev_args + ['-i', 'setup'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not support software setup')
        self.assertEqual(result['code'], -9)

    def test_wipe(self):
        result = self.do_command(self.dev_args + ['wipe'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not support wiping via software')
        self.assertEqual(result['code'], -9)

    def test_restore(self):
        result = self.do_command(self.dev_args + ['-i', 'restore'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not support restoring via software')
        self.assertEqual(result['code'], -9)

    def test_backup(self):
        result = self.do_command(self.dev_args + ['backup'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'The Ledger Nano S and X do not support creating a backup via software')
        self.assertEqual(result['code'], -9)

class TestLedgerGetXpub(DeviceTestCase):
    def test_getxpub(self):
        result = self.do_command(self.dev_args + ['--expert', 'getxpub', 'm/44h/1h/0h/0/3'])
        self.assertEqual(result['xpub'], "tpubDHcN44A4UHqdR5iJduo8FWiWtJNcY7MPUEe1Dmpo4sv1R93k6mrWxAVNmjFAsW4e9gC14yTfkHFzBTQUjnkdijZVLmmiJdueMgLPczBRBSL")
        self.assertTrue(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 5)
        self.assertEqual(result['parent_fingerprint'], "f7ed8b7e")
        self.assertEqual(result['child_num'], 3)
        self.assertEqual(result['chaincode'], "1067f2a53975faf7ac265be505c1c50ef80a0dcbe1f53f50497c5618e8888dbd")
        self.assertEqual(result['pubkey'], "035879ca173a9c1b3f300ec587fb4cc6d54d618e30584e425c1b53b98828708f1d")

def ledger_test_suite(emulator, bitcoind, interface, legacy=False, anti_exfil=False, anti_exfil_core=False):
    dev_emulator = LedgerEmulator(emulator, legacy)

    signtx_cases = [
        (["legacy"], ["legacy"], True, legacy),
        (["segwit"], ["segwit"], True, legacy),
    ]
    if not legacy:
        signtx_cases.extend([
            (["tap"], [], True, legacy),
            (["legacy", "segwit"], ["legacy", "segwit"], True, legacy),
            (["legacy", "segwit", "tap"], ["legacy", "segwit"], True, legacy),
        ])

    if anti_exfil:
        if legacy:
            raise ValueError("Anti-exfil tests require the modern Ledger app")
        suite = DeviceTestCase.parameterize(TestLedgerAntiExfil, bitcoind, emulator=dev_emulator, interface=interface)
        if anti_exfil_core:
            suite.addTest(DeviceTestCase.parameterize(TestLedgerCoreAntiExfil, bitcoind, emulator=dev_emulator, interface=interface))
        return unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite).wasSuccessful()

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestLedgerDisabledCommands, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestLedgerGetXpub, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type=dev_emulator.type))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, bitcoind, emulator=dev_emulator, interface=interface, signtx_cases=signtx_cases))
    if not legacy:
        suite.addTest(DeviceTestCase.parameterize(TestRegisterDescriptor, bitcoind, emulator=dev_emulator, interface=interface, returns_registration=True))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Ledger implementation')
    parser.add_argument('emulator', help='Path to the ledger emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    parser.add_argument("--legacy", action="store_true", help="Use the v1 app and test the legacy API")

    args = parser.parse_args()

    # Start bitcoind
    bitcoind = Bitcoind.create(args.bitcoind)

    sys.exit(not ledger_test_suite(args.emulator, bitcoind, args.interface, args.legacy))
