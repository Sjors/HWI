#! /usr/bin/env python3

import argparse
import atexit
import copy
import os
import subprocess
import logging
import signal
import sys
import time
import unittest
from unittest import mock

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
from hwilib.devices.jadepy.jade import JadeAPI
from hwilib import anti_exfil as ae
from hwilib.commands import get_client, signtx
from hwilib.common import Chain
from hwilib.key import G, point_mul, point_to_bytes
from hwilib.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from hwilib.tx import COutPoint, CTransaction, CTxIn, CTxOut
from hwilib.errors import HWWError, UnavailableActionError

USE_SIMULATOR = True
JADE_PATH = 'tcp:127.0.0.1:30121' if USE_SIMULATOR else None # None -> should search and find plugged unit
TEST_SEED = bytes.fromhex('b90e532426d0dc20fffe01037048c018e940300038b165c211915c672e07762c')

LOGGING = None  # logging.INFO

# Enable jade logging
if LOGGING:
    logger = logging.getLogger("hwilib.devices.jadepy.jade")
    logger.setLevel(LOGGING)
    device_logger = logging.getLogger("hwilib.devices.jadepy.jade-device")
    device_logger.setLevel(LOGGING)

class JadeEmulator(DeviceEmulator):
    def __init__(self, jade_qemu_emulator_path):
        self.emulator_path = jade_qemu_emulator_path
        self.emulator_proc = None
        self.type = "jade"
        self.path = JADE_PATH
        self.master_xpub = "tpubDCgUYU13ZZ2ES5mTZNfR93i2hGLKyCkGcbJtUJ2U1Lt9qQdNTSG7kQ4r6WK3mY7HVVKxyVpkbK6Hrdo1FLRHFRL4RP68eLmoySecZLLX5tW"
        self.fingerprint = '1273da33'
        self.password = ""
        self.supports_ms_display = False
        self.supports_xpub_ms_display = False
        self.supports_unsorted_ms = False
        self.supports_taproot = True
        self.supports_anti_exfil = True
        self.strict_bip48 = False
        self.include_xpubs = False
        self.supports_device_multiple_multisig = True
        self.supports_legacy = True
        self.supports_arbitrary_keypool_paths = True

    def start(self):
        super().start()
        if USE_SIMULATOR:
            # Start the qemu emulator
            self.emulator_stdout_log = open("jade-emulator.stdout", "a")
            self.emulator_stderr_log = open("jade-emulator.stderr", "a")
            self.emulator_proc = subprocess.Popen(
                [
                    './qemu-system-xtensa',
                    '-nographic',
                    '-machine', 'esp32',
                    '-m', '4M',
                    '-drive', 'file=flash_image.bin,if=mtd,format=raw',
                    '-nic', 'user,model=open_eth,id=lo0,hostfwd=tcp:0.0.0.0:30121-:30121',
                    '-drive', 'file=qemu_efuse.bin,if=none,format=raw,id=efuse',
                    '-global', 'driver=nvram.esp32.efuse,property=drive,value=efuse',
                    '-serial', 'pty',
                    '-L', './pc-bios'
                ],
                cwd=self.emulator_path,
                preexec_fn=os.setsid,
                stdout=self.emulator_stdout_log,
                stderr=self.emulator_stderr_log,
            )
            time.sleep(5)

            # Wait for emulator to be up (max 5 minutes)
            MAX_STARTUP_TIME = 300
            start_time = time.time()
            while True:
                # Prevent CI from lingering until timeout:
                if time.time() - start_time > MAX_STARTUP_TIME:
                    raise RuntimeError("Jade simulator startup timed out after 5 minutes")
                if self.emulator_proc.poll() is not None:
                    raise RuntimeError(f"Jade simulator failed with exit code {self.emulator_proc.poll()}")

                time.sleep(1)
                try:
                    # Try to connect and set the test seed
                    with JadeAPI.create_serial(JADE_PATH, timeout=5) as jade:
                        if jade.set_seed(TEST_SEED):
                            break

                except Exception as e:
                    print(str(e))
        atexit.register(self.stop)

    def stop(self):
        super().stop()
        if USE_SIMULATOR:
            if self.emulator_proc.poll() is None:
                os.killpg(os.getpgid(self.emulator_proc.pid), signal.SIGTERM)
                os.waitpid(self.emulator_proc.pid, 0)
            self.emulator_stdout_log.close()
            self.emulator_stderr_log.close()
        atexit.unregister(self.stop)

# Jade specific disabled command tests
class TestJadeDisabledCommands(DeviceTestCase):
    def test_pin(self):
        result = self.do_command(self.dev_args + ['promptpin'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'Blockstream Jade does not need a PIN sent from the host')
        self.assertEqual(result['code'], -9)

        result = self.do_command(self.dev_args + ['sendpin', '1234'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'Blockstream Jade does not need a PIN sent from the host')
        self.assertEqual(result['code'], -9)

    def test_setup(self):
        result = self.do_command(self.dev_args + ['-i', 'setup'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'Blockstream Jade does not support software setup')
        self.assertEqual(result['code'], -9)

    def test_wipe(self):
        result = self.do_command(self.dev_args + ['wipe'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'Blockstream Jade does not support wiping via software')
        self.assertEqual(result['code'], -9)

    def test_restore(self):
        result = self.do_command(self.dev_args + ['-i', 'restore'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'Blockstream Jade does not support restoring via software')
        self.assertEqual(result['code'], -9)

    def test_backup(self):
        result = self.do_command(self.dev_args + ['backup'])
        self.assertIn('error', result)
        self.assertIn('code', result)
        self.assertEqual(result['error'], 'Blockstream Jade does not support creating a backup via software')
        self.assertEqual(result['code'], -9)

class TestJadeGetXpub(DeviceTestCase):
    def test_getexpertxpub(self):
        self.dev_args.remove("--chain")
        self.dev_args.remove("test")
        result = self.do_command(self.dev_args + ['--expert', 'getxpub', 'm/44h/0h/0h/3'])
        self.assertEqual(result['xpub'], 'xpub6EZPQwwr93eGRt5uAN8fqNpLWtgoWM4Cn96Y7XERhRBaXus5FjuTpgGBWuvuAXp1PhYBfp7h7C7HPyuRvCyyc6wBAK7PC1Z1JVEGBnrZUXi')
        self.assertFalse(result['testnet'])
        self.assertFalse(result['private'])
        self.assertEqual(result['depth'], 4)
        self.assertEqual(result['parent_fingerprint'], '8b878d56')
        self.assertEqual(result['child_num'], 3)
        self.assertEqual(result['chaincode'], '7f6e61a651f74388da6a741be38aaf223e849ab5a677220dee113c34c51028b3')
        self.assertEqual(result['pubkey'], '03f99c7114dd0418434585410e11648ec202817dcba5551d7a5ab1d3f93a2aad2e')

# Because Jade has some restrictions about what multisigs it supports, we run
# explicit multisig-address tests, rather than using the standard/provided ones.
class TestJadeGetMultisigAddresses(DeviceTestCase):
    # NOTE: These ones are present in Jade's own unit tests
    # Jade test case: test_data/multisig_reg_ss_p2sh.json
    def test_getp2sh(self):
        descriptor_param = '--desc=sh(multi(2,[1273da33/44/0h/0h]tpubDDCNstnPhbdd4vwbw5UWK3vRQSF1WXQkvBHpNXpKJAkwFYjwu735EH3GVf53qwbWimzewDUv68MUmRDgYtQ1AU8FRCPkazfuaBp7LaEaohG/3/1/11/12,[e3ebcc79/3h/1h/1]tpubDDExQpZg2tziZ7ACSBCYsY3rYxAZtTRBgWwioRLYqgNBguH6rMHN1D8epTxUQUB5kM5nxkEtr2SNic6PJLPubcGMR6S2fmDZTzL9dHpU7ka/1/3/4/5))'
        result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
        self.assertEqual(result['address'], '2N2K6xGHeEYNaKEHZSBVy33g2GfUdFwJr2A')

    # Jade test case: test_data/multisig_reg_ss_wsh_sorted.json
    def test_get_sorted_p2wsh(self):
        descriptor_param = '--desc=wsh(sortedmulti(2,[1273da33/44/0h/0h]tpubDDCNstnPhbdd4vwbw5UWK3vRQSF1WXQkvBHpNXpKJAkwFYjwu735EH3GVf53qwbWimzewDUv68MUmRDgYtQ1AU8FRCPkazfuaBp7LaEaohG/3/1/0/1,[e3ebcc79/3h/1h/1]tpubDDExQpZg2tziZ7ACSBCYsY3rYxAZtTRBgWwioRLYqgNBguH6rMHN1D8epTxUQUB5kM5nxkEtr2SNic6PJLPubcGMR6S2fmDZTzL9dHpU7ka/1/0/16))'
        result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
        self.assertEqual(result['address'], 'tb1qx474um8lr97sn46wz9v90u6qs49ttrhdze2cfxa5x4tajvl62avshcqval')

    # Jade test case: test_data/multisig_reg_ss_matches_ga_2of3.json
    def test_getp2shwsh(self):
        descriptor_param = '--desc=sh(wsh(multi(2,[b5281696/3]tpubECMbgHMZm4QymrFbuEntaWbSsaaKvJVpoR6rhVwxGUrT9qf6WLfC88piWYVsQDV86PUKx3QsXYiCqugWX1oz8ekucUdFUdupuNCgjf17EYK/13,[e3ebcc79/3h/2h/1]tpubDD8fpYqWy6DEvbqdj9CVWptA3gd3xqarNN6wCAjfDs1sFnd8zfb9SeDzRAXA3S4eeeYvo2sz6mbyS3KaXuDe5PcWy94PqShTpBjiJN198A6/13,[1273da33/1]tpubD8PzcLmm1rVeUpEjmd2kQD6a9DXy6dwVVgE14mrh1zc6L98nmNqmDaApAbEcbrJ1iPBpo2gnEniSpVXHgovU8ecWwfHVP113DK2bWEMPpEs/13)))'
        result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
        self.assertEqual(result['address'], '2NFgE1k4EpyiBTN4SBkGamFU9E1DwLLajLo')

    # NOTE: these ones are used by the sign-tx tests - using them here gets
    # them 'registered' on the Jade hw - This is not mandatory but means in
    # sign-tx we should be using them to auto-validate the change outputs.
    SIGN_TX_MULTI_DESCRIPTOR = 'multi(2,[1273da33/48h/1h/2h/0h]tpubDE5KhdeLh956ERiopzHRskaJ3huWXLUPKiQUSkR3R3nTsr4SQfVVU6DbA9E66BZYwTk87hwE7wn1175WqBzMsbkFErGt3ATJm2xaisCPUmn/0/1,[1273da33/48h/1h/0h/0h]tpubDEAjmvwVDj4aNW8D1KX39VmMW1ZUX8BNgVEyD6tUVshZYCJQvbp9LSqvihiJa4tGZUisf6XpyZHg76dDBxNZLHTf6xYwgbio4Xnj6i21JgN/0/1,[1273da33/48h/1h/1h/0h]tpubDERHGgfviqDnoRSykG1YBBfhFbgNPuTeWvjwJBXM36d5wzFwkQpWFXHC76XW99hMgd1NkR6A3rRHM93Njqdx2X3KoUebekokUPsAvmeC4NE/0/1)'
    SIGN_TX_SORTEDMULTI_DESCRIPTOR = f'sorted{SIGN_TX_MULTI_DESCRIPTOR}'

    def test_get_signing_p2sh(self):
        descriptor_param = f'--desc=sh({self.SIGN_TX_MULTI_DESCRIPTOR})'
        result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
        self.assertEqual(result['address'], '2N4v6yct4NHy7FLex1wgwksLG97dXSTEs9x', result)

        descriptor_param = f'--desc=sh({self.SIGN_TX_SORTEDMULTI_DESCRIPTOR})'
        result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
        self.assertEqual(result['address'], '2MwZVj4Sbjn3ewD87ZoDgWrKFNjav4uPJm9', result)

    def test_get_signing_p2wsh(self):
        descriptor_param = f'--desc=wsh({self.SIGN_TX_MULTI_DESCRIPTOR})'
        result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
        self.assertEqual(result['address'], 'tb1qxjxvxk69yedt49u2djh8mu9lsmw6tf4n2pwuqend5tjlqrumuq2skh7qzc', result)

        descriptor_param = f'--desc=wsh({self.SIGN_TX_SORTEDMULTI_DESCRIPTOR})'
        result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
        self.assertEqual(result['address'], 'tb1qeuh6d9eg28aqy5ckrqxn868saapcr6kg968prm6999gclkr4ewqsv22prt', result)

    def test_get_signing_p2shwsh(self):
        descriptor_param = f'--desc=sh(wsh({self.SIGN_TX_MULTI_DESCRIPTOR}))'
        result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
        self.assertEqual(result['address'], '2N6wdpQsBUvT3nAp8hGaXEFpfvzerqaHFVC', result)

        descriptor_param = f'--desc=sh(wsh({self.SIGN_TX_SORTEDMULTI_DESCRIPTOR}))'
        result = self.do_command(self.dev_args + ['displayaddress', descriptor_param])
        self.assertEqual(result['address'], '2NAXBEePa5ebo1zTDrtQ9C21QDkkamwczfQ', result)

class TestJadeAntiExfilCapability(DeviceTestCase):
    def test_released_firmware_refuses_anti_exfil(self):
        # A real device capability query, followed by a valid protocol request.
        # No signing RPC may reach firmware that doesn't advertise support.
        client = get_client("jade", self.emulator.path, chain=Chain.TEST)
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
            with mock.patch.object(client.jade, "sign_psbt", side_effect=AssertionError("Signing RPC must not be called")):
                with self.assertRaises(UnavailableActionError):
                    signtx(client, request.serialize())
                with self.assertRaises(UnavailableActionError):
                    client.sign_tx(request)
        finally:
            client.close()


class TestJadeAntiExfil(DeviceTestCase):
    """Real QEMU firmware signing; ordinary Jade firmware must fail capability checks."""

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

                # Bypass commands.signtx preflight: these errors must be caught by
                # the actual firmware, before any signature is released.
                for mutation in ("entropy", "nonce", "output-key", "existing-signature", "mixed-round"):
                    bad = copy.deepcopy(first)
                    if mutation == "entropy":
                        bad.inputs[0].unknown[ae.key(ae.HOST_ENTROPY, pubkeys[0])] = (11).to_bytes(32, "big")
                    elif mutation == "nonce":
                        bad.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, pubkeys[0])] = point_to_bytes(point_mul(G, 7))
                    elif mutation == "output-key":
                        value = bad.inputs[0].unknown.pop(ae.key(ae.HOST_COMMITMENT, pubkeys[0]))
                        bad.inputs[0].unknown[ae.key(ae.HOST_COMMITMENT, point_mul(G, 7)[0].to_bytes(32, "big"))] = value
                    elif mutation == "existing-signature":
                        bad.inputs[0].tap_key_sig = bytes(64)
                    else:
                        del bad.inputs[0].unknown[ae.key(ae.HOST_ENTROPY, pubkeys[0])]
                        del bad.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, pubkeys[0])]
                    client = get_client("jade", self.emulator.path, chain=Chain.TEST)
                    try:
                        with self.assertRaises(HWWError):
                            client.sign_tx(bad)
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


class TestJadeSignTx(TestSignTx):
    # disable big psbt as jade simulator can't handle it
    def test_big_tx(self):
        pass

def jade_test_suite(emulator, bitcoind, interface, anti_exfil=False):
    dev_emulator = JadeEmulator(emulator)

    signtx_cases = [
        (["legacy"], ["legacy"], True, True),
        (["segwit"], ["segwit"], True, True),
        (["legacy", "segwit", "tap"], ["legacy", "segwit"], True, True),
        (["tap"], [], False, False),
    ]

    if anti_exfil:
        suite = DeviceTestCase.parameterize(TestJadeAntiExfil, bitcoind, emulator=dev_emulator, interface=interface)
        return unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite).wasSuccessful()

    # Generic Device tests
    suite = unittest.TestSuite()
    suite.addTest(DeviceTestCase.parameterize(TestJadeAntiExfilCapability, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestJadeDisabledCommands, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDeviceConnect, bitcoind, emulator=dev_emulator, interface=interface, detect_type="jade"))
    suite.addTest(DeviceTestCase.parameterize(TestJadeGetXpub, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetDescriptors, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestGetKeypool, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestDisplayAddress, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestJadeGetMultisigAddresses, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestSignMessage, bitcoind, emulator=dev_emulator, interface=interface))
    suite.addTest(DeviceTestCase.parameterize(TestJadeSignTx, bitcoind, emulator=dev_emulator, interface=interface, signtx_cases=signtx_cases))
    suite.addTest(DeviceTestCase.parameterize(TestRegisterDescriptor, bitcoind, emulator=dev_emulator, interface=interface, returns_registration=False))

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
    return result.wasSuccessful()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Test Jade implementation')
    parser.add_argument('emulator', help='Docker image name of the jade emulator')
    parser.add_argument('bitcoind', help='Path to bitcoind binary')
    parser.add_argument('--interface', help='Which interface to send commands over', choices=['library', 'cli', 'bindist'], default='library')

    args = parser.parse_args()

    # Start bitcoind
    bitcoind = Bitcoind.create(args.bitcoind)

    sys.exit(not jade_test_suite(args.emulator, bitcoind, args.interface))
