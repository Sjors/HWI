#! /usr/bin/env python3

import atexit
import os
import subprocess
import time
import threading
import unittest
from unittest import mock
import sys
import argparse

from hwilib.devices.bitbox02 import Bitbox02Client
from hwilib import anti_exfil as ae
from hwilib.commands import get_client, signtx
from hwilib.common import Chain
from hwilib.errors import HWWError, UnavailableActionError
from hwilib.key import G, point_mul, point_to_bytes
from hwilib.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from hwilib.tx import COutPoint, CTransaction, CTxIn, CTxOut

from test_device import (
    DeviceEmulator,
    DeviceTestCase,
    TestDeviceConnect,
    TestDisplayAddress,
    TestGetKeypool,
    TestGetDescriptors,
    TestRegisterDescriptor,
    TestSignTx,
)

# Class for emulator control
class BitBox02Emulator(DeviceEmulator):
    # Maximum time to wait for simulator startup (5 minutes)
    MAX_STARTUP_TIME = 300
    # Maximum time to wait for simulator shutdown
    MAX_SHUTDOWN_TIME = 30

    def __init__(self, simulator):
        self.simulator = simulator
        self.path = "127.0.0.1:15423"
        self.type = "bitbox02"
        self.fingerprint = "4c00739d"
        self.master_xpub = "tpubDDoFYQF4zAhrW8LRtCxePR8bJsAh5SXU6PwPNi2oRfeh67qhmxZawJ4m3V76P8AYSEueKmwvNyiSPAGYtynGfzJNvTHyzj2FJTbp729jmYM"
        self.password = None
        self.supports_ms_display = False
        self.supports_xpub_ms_display = False
        self.supports_unsorted_ms = False
        self.supports_taproot = True
        self.supports_anti_exfil = True
        self.strict_bip48 = False
        self.include_xpubs = True
        self.supports_device_multiple_multisig = True
        self.supports_legacy = False
        self.supports_arbitrary_keypool_paths = True

    def start(self):
        super().start()
        self.log = open('bitbox02-simulator.stderr', 'a')
        # Start the Bitbox02 simulator
        self.simulator_proc = subprocess.Popen(
            [
                './' + os.path.basename(self.simulator)
            ],
            cwd=os.path.dirname(self.simulator),
            stderr=self.log
        )
        time.sleep(1)

        # Prevent CI from lingering until timeout:
        if self.simulator_proc.poll() is not None:
            raise RuntimeError(f"BitBox02 simulator failed with exit code {self.simulator_proc.poll()}")

        # Run restore_device in a thread with timeout to prevent CI from hanging
        setup_error = None

        def do_restore():
            nonlocal setup_error
            try:
                self.setup_client = Bitbox02Client(self.path)
                self.setup_bb02 = self.setup_client.restore_device()
                self.setup_client.close()
            except Exception as e:
                setup_error = e

        restore_thread = threading.Thread(target=do_restore)
        restore_thread.start()
        restore_thread.join(timeout=self.MAX_STARTUP_TIME)

        if restore_thread.is_alive():
            self.simulator_proc.terminate()
            raise RuntimeError("BitBox02 simulator startup timed out after 5 minutes")
        if setup_error:
            raise setup_error

        atexit.register(self.stop)

    def stop(self):
        super().stop()
        self.simulator_proc.terminate()
        try:
            self.simulator_proc.wait(timeout=self.MAX_SHUTDOWN_TIME)
        except subprocess.TimeoutExpired:
            self.simulator_proc.kill()
            self.simulator_proc.wait(timeout=5)
        self.log.close()
        atexit.unregister(self.stop)

class TestBitbox02GetXpub(DeviceTestCase):
    def test_getxpub(self):
        self.dev_args.remove('--chain')
        self.dev_args.remove('test')
        result = self.do_command(self.dev_args + ['--expert', 'getxpub', 'm/84h/0h/0h/3'])
        self.assertEqual(result['xpub'], 'xpub6F8W4c3nJf6vWyEQPW9rofRgKf9LUWrbLc6fh2GUgofxXzuMwNEXw9dUuAeHuNiu2MebTmLX1CY2wxN1pgUuQtsWa9x8QBk7J51nD86vann')
        self.assertFalse(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 4)
        self.assertEqual(result['parent_fingerprint'], 'd934efde')
        self.assertEqual(result['child_num'], 3)
        self.assertEqual(result['chaincode'], '03b0d37df586659fb87145e1d28506e4e2d42777586568d61ecdf6c9e041a0a1')
        self.assertEqual(result['pubkey'], '03290b94a942a317c3846244f1eb6d67214326c8cfc6d940c823ace57ab818dbbd')

class TestBitBox02AntiExfilCapability(DeviceTestCase):
    def test_released_firmware_refuses_anti_exfil(self):
        # A real device capability query, followed by a valid protocol request.
        # No signing RPC may reach firmware that doesn't advertise support.
        client = get_client("bitbox02", self.emulator.path, chain=Chain.TEST)
        try:
            if client.can_sign_anti_exfil():
                self.skipTest("Firmware advertises the draft protocol")
            pubkey = point_mul(G, 3)[0].to_bytes(32, "big")
            transaction = CTransaction()
            transaction.nVersion = 2
            transaction.vin = [CTxIn(COutPoint(1, 0), nSequence=0xfffffffd)]
            transaction.vout = [CTxOut(90000, b"\x51\x20" + pubkey)]
            request = PSBT(transaction)
            request.inputs = [PartiallySignedInput(0)]
            request.outputs = [PartiallySignedOutput(0)]
            request.cache_unsigned_tx_pieces()
            request.inputs[0].witness_utxo = CTxOut(100000, b"\x51\x20" + pubkey)
            request.inputs[0].unknown[ae.key(ae.HOST_COMMITMENT, pubkey)] = ae.host_commit((5).to_bytes(32, "big"))
            with mock.patch.object(client.init(), "btc_sign", side_effect=AssertionError("Signing RPC must not be called")):
                with self.assertRaises(UnavailableActionError):
                    signtx(client, request.serialize())
                with self.assertRaises(UnavailableActionError):
                    client.sign_tx(request)
        finally:
            client.close()


class TestBitBox02AntiExfil(DeviceTestCase):
    """Real native firmware signing; ordinary BitBox02 firmware must fail capability checks."""

    def setUp(self):
        super().setUp()
        self.setup_wallets()

    def test_taproot_anti_exfil(self):
        descriptors = self.do_command(self.dev_args + ["getkeypool", "--addr-type", "tap", "0", "10"])
        self.assertIsInstance(descriptors, list, descriptors)
        self.assertTrue(all(result["success"] for result in self.wrpc.importdescriptors(descriptors)))

        for psbt_version, hash_type in ((0, None), (0, 1), (2, None), (2, 1)):
            with self.subTest(version=psbt_version, sighash=hash_type):
                addresses = [self.wrpc.getnewaddress("", "bech32m") for _ in range(2)]
                txid = self.wpk_rpc.sendmany("", {address: 1 for address in addresses})
                self.wpk_rpc.generatetoaddress(1, self.wpk_rpc.getnewaddress())
                coins = [coin for coin in self.wrpc.listunspent() if coin["txid"] == txid]
                self.assertEqual(len(coins), 2)
                funded = self.wrpc.walletcreatefundedpsbt(
                    [{"txid": txid, "vout": coin["vout"]} for coin in coins],
                    [{self.wpk_rpc.getnewaddress(): 0.5}], 0,
                    {"add_inputs": False}, True,
                )
                request = PSBT()
                request.deserialize(funded["psbt"])
                if psbt_version == 2:
                    request.convert_to_v2()
                self.assertEqual(len(request.inputs), 2)
                pubkeys, entropies = [], []
                for index, psbt_in in enumerate(request.inputs):
                    psbt_in.sighash = hash_type
                    pubkey = ae.get_utxo(request, index).scriptPubKey[2:]
                    entropy = (5 + index + 2 * (hash_type or 0)).to_bytes(32, "big")
                    psbt_in.unknown[ae.key(ae.HOST_COMMITMENT, pubkey)] = ae.host_commit(entropy)
                    pubkeys.append(pubkey)
                    entropies.append(entropy)
                unsigned = request.get_unsigned_tx().serialize_without_witness()

                first_result = self.do_command(self.dev_args + ["signtx", request.serialize()])
                self.assertNotIn("error", first_result, first_result)
                self.assertFalse(first_result["signed"])
                first = PSBT()
                first.deserialize(first_result["psbt"])
                nonces = []
                for index, pubkey in enumerate(pubkeys):
                    self.assertFalse(first.inputs[index].tap_key_sig)
                    nonce = first.inputs[index].unknown[ae.key(ae.SIGNER_NONCE, pubkey)]
                    self.assertEqual(len(nonce), 33)
                    nonces.append(nonce)
                self.assertEqual(first.get_unsigned_tx().serialize_without_witness(), unsigned)
                self.assertEqual(first.version, request.version)
                # Reconnecting cannot change the committed nonce for the same session.
                retry_result = self.do_command(self.dev_args + ["signtx", request.serialize()])
                self.assertNotIn("error", retry_result, retry_result)
                retry = PSBT()
                retry.deserialize(retry_result["psbt"])
                for index, pubkey in enumerate(pubkeys):
                    self.assertEqual(retry.inputs[index].unknown[ae.key(ae.SIGNER_NONCE, pubkey)], nonces[index])
                    first.inputs[index].unknown[ae.key(ae.HOST_ENTROPY, pubkey)] = entropies[index]

                # Intercept a valid transport request after HWI's PSBT preflight.
                # Thus malformed entropy/nonces/rounds are rejected by actual
                # firmware rather than by the host parser.
                for mutation in ("entropy", "nonce", "missing-request", "round", "sighash", "keypath"):
                    client = get_client("bitbox02", self.emulator.path, chain=Chain.TEST)
                    try:
                        sdk = client.init()
                        original_query = sdk._msg_query

                        def corrupt(request, *args, **kwargs):
                            if request.HasField("btc_sign_init") and mutation == "round":
                                request.btc_sign_init.taproot_anti_exfil_round = 1
                            if request.HasField("btc_sign_input") and request.btc_sign_input.HasField("taproot_anti_exfil"):
                                tx_input = request.btc_sign_input
                                if mutation == "entropy":
                                    tx_input.taproot_anti_exfil.host_entropy = (11).to_bytes(32, "big")
                                elif mutation == "nonce":
                                    tx_input.taproot_anti_exfil.signer_nonce = point_to_bytes(point_mul(G, 7))
                                elif mutation == "missing-request":
                                    tx_input.ClearField("taproot_anti_exfil")
                                elif mutation == "sighash":
                                    tx_input.taproot_anti_exfil.sighash = 2
                                elif mutation == "keypath":
                                    tx_input.keypath[-1] += 1
                            return original_query(request, *args, **kwargs)
                        with mock.patch.object(sdk, "_msg_query", side_effect=corrupt):
                            with self.assertRaises(HWWError):
                                client.sign_tx(first)
                    finally:
                        client.close()

                signed_result = self.do_command(self.dev_args + ["signtx", first.serialize()])
                self.assertNotIn("error", signed_result, signed_result)
                signed = PSBT()
                signed.deserialize(signed_result["psbt"])
                self.assertEqual(signed.get_unsigned_tx().serialize_without_witness(), unsigned)
                self.assertEqual(signed.version, request.version)
                for index, pubkey in enumerate(pubkeys):
                    signature = signed.inputs[index].tap_key_sig
                    self.assertEqual(len(signature), 64 if hash_type is None else 65)
                    self.assertTrue(ae.host_verify(pubkey, ae.signature_hash(request, index, hash_type or 0),
                                                   signature[:64], entropies[index], nonces[index]))
                # Core v31 finalizes v0; verify v2 preservation before conversion.
                if psbt_version == 2:
                    signed.convert_to_v0()
                finalized = self.wrpc.finalizepsbt(signed.serialize())
                self.assertTrue(finalized["complete"])
                self.assertTrue(self.wrpc.testmempoolaccept([finalized["hex"]])[0]["allowed"])
                sent = self.wrpc.sendrawtransaction(finalized["hex"])
                self.wpk_rpc.generatetoaddress(1, self.wpk_rpc.getnewaddress())
                self.assertGreater(self.wrpc.gettransaction(sent)["confirmations"], 0)


def bitbox02_test_suite(simulator, bitcoind, interface, anti_exfil=False):
    dev_emulator = BitBox02Emulator(simulator)

    signtx_cases = [
        (["segwit"], [], False, False),
        (["tap"], [], False, False)
    ]

    if anti_exfil:
        suite = DeviceTestCase.parameterize(TestBitBox02AntiExfil, bitcoind, emulator=dev_emulator, interface=interface)
        return unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite).wasSuccessful()

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestBitBox02AntiExfilCapability, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type=dev_emulator.type))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignTx, bitcoind, emulator=dev_emulator, interface=interface, signtx_cases=signtx_cases))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, bitcoind, emulator=dev_emulator, interface=interface))
    # TestSignMessage is removed, since its only testcase is for legacy p2pkh, which is not supported by BitBox02
    # suite.addTest(DeviceTestCase.parameterize(TestSignMessage, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestBitbox02GetXpub, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(
        TestRegisterDescriptor,
        bitcoind,
        emulator=dev_emulator,
        interface=interface,
        returns_registration=False,
        sorted=False,
        supports_multiple_policies=False,
    ))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test BitBox02 implementation')
    parser.add_argument('simulator', help='Path to simulator binary')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')
    args = parser.parse_args()

    sys.exit(not bitbox02_test_suite(args.simulator, args.bitcoind, args.interface))
