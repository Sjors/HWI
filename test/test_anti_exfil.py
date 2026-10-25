#! /usr/bin/env python3
# Copyright (c) 2026 The HWI developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import copy
import json
import io
import logging
import threading
import traceback
from pathlib import Path
import unittest
from unittest.mock import patch

from hwilib import anti_exfil as ae
from hwilib.commands import signtx
from hwilib.errors import ActionCanceledError, BadArgumentError, DeviceBusyError, DeviceConnectionError, DeviceFailureError, UnavailableActionError
from hwilib.key import G, n, point_mul, point_to_bytes
from hwilib.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from hwilib.tx import COutPoint, CTransaction, CTxIn, CTxOut
from hwilib.devices.ledger_bitcoin.client import _decode_signpsbt_yielded_value
from hwilib.devices.ledger_bitcoin.client_base import AntiExfilNonce


def signer_nonce(secret, msg, commitment):
    """Independent test-only reference signer. Never use for real keys."""
    point = point_mul(G, secret)
    if point[1] & 1:
        secret = n - secret
    aux = ae.tagged_hash("BIP0340/aux", commitment)
    masked = bytes(a ^ b for a, b in zip(secret.to_bytes(32, "big"), aux))
    nonce = int.from_bytes(ae.tagged_hash("BIP-EXFIL/nonce", masked + point[0].to_bytes(32, "big") + msg), "big") % n
    if nonce == 0:
        raise ValueError("Zero reference nonce")
    return secret, nonce, point[0].to_bytes(32, "big")


def signer_commit(secret, msg, commitment):
    _, nonce, _ = signer_nonce(secret, msg, commitment)
    return point_to_bytes(point_mul(G, nonce))


def sign(secret, msg, entropy):
    secret, nonce, pubkey = signer_nonce(secret, msg, ae.host_commit(entropy))
    nonce = (nonce + int.from_bytes(entropy, "big")) % n
    if nonce == 0:
        raise ValueError("Zero final nonce")
    point = point_mul(G, nonce)
    if point[1] & 1:
        nonce = n - nonce
    r = point[0].to_bytes(32, "big")
    challenge = int.from_bytes(ae.tagged_hash("BIP0340/challenge", r + pubkey + msg), "big") % n
    return r + ((nonce + challenge * secret) % n).to_bytes(32, "big")


class ReferenceClient:
    def __init__(self, secret, mutate=None):
        self.secret = secret
        self.mutate = mutate

    def can_sign_anti_exfil(self):
        return True

    def sign_tx(self, psbt, registrations=None):
        result = copy.deepcopy(psbt)
        for index, request in ae.requests(psbt).items():
            result.inputs[index].unknown[ae.key(ae.SIGNER_NONCE, request.pubkey)] = signer_commit(self.secret, request.message, request.commitment)
            if request.entropy is not None:
                signature = sign(self.secret, request.message, request.entropy)
                result.inputs[index].tap_key_sig = signature + (bytes([request.hash_type]) if request.hash_type else b"")
        if self.mutate:
            self.mutate(result)
        return result


class TestAntiExfil(unittest.TestCase):
    def setUp(self):
        self.secret = 3
        self.pubkey = point_mul(G, self.secret)[0].to_bytes(32, "big")
        self.entropy = (5).to_bytes(32, "big")
        tx = CTransaction()
        tx.nVersion = 2
        tx.vin = [CTxIn(COutPoint(1, 0), nSequence=0xfffffffd)]
        tx.vout = [CTxOut(90000, b"\x51\x20" + self.pubkey)]
        self.psbt = PSBT(tx)
        self.psbt.inputs = [PartiallySignedInput(0)]
        self.psbt.outputs = [PartiallySignedOutput(0)]
        self.psbt.cache_unsigned_tx_pieces()
        self.psbt.inputs[0].witness_utxo = CTxOut(100000, b"\x51\x20" + self.pubkey)
        self.psbt.inputs[0].unknown[ae.key(ae.HOST_COMMITMENT, self.pubkey)] = ae.host_commit(self.entropy)

    def round_one(self):
        response = signtx(ReferenceClient(self.secret), self.psbt.serialize())
        self.assertFalse(response["signed"])
        result = PSBT()
        result.deserialize(response["psbt"])
        return result

    def round_two_request(self):
        result = self.round_one()
        result.inputs[0].unknown[ae.key(ae.HOST_ENTROPY, self.pubkey)] = self.entropy
        return result

    def test_unsupported_client_rejected_before_signing(self):
        class UnsupportedClient(ReferenceClient):
            def can_sign_anti_exfil(self):
                return False

            def sign_tx(self, *args, **kwargs):
                raise AssertionError("Unsupported signer was invoked")

        with self.assertRaises(UnavailableActionError):
            signtx(UnsupportedClient(self.secret), self.psbt.serialize())

    def test_shared_vectors(self):
        vectors = json.loads((Path(__file__).parent / "data/anti_exfil_vectors.json").read_text())
        for vector in vectors:
            with self.subTest(index=vector["index"]):
                secret = int(vector["secret_key"], 16)
                message = bytes.fromhex(vector["message"])
                entropy = bytes.fromhex(vector["host_nonce"])
                commitment = bytes.fromhex(vector["host_commitment"])
                nonce = bytes.fromhex(vector["signer_nonce"])
                signature = bytes.fromhex(vector["signature"])
                self.assertEqual(ae.host_commit(entropy), commitment)
                self.assertEqual(signer_commit(secret, message, commitment), nonce)
                self.assertEqual(sign(secret, message, entropy), signature)
                self.assertTrue(ae.host_verify(bytes.fromhex(vector["public_key"]), message, signature, entropy, nonce))

    def test_interactive_roundtrip(self):
        for version in (0, 2):
            for hash_type in (None, 1):
                with self.subTest(version=version, hash_type=hash_type):
                    request = copy.deepcopy(self.psbt)
                    if version == 2:
                        request.convert_to_v2()
                    request.inputs[0].sighash = hash_type
                    first = ReferenceClient(self.secret).sign_tx(request)
                    ae.check_response(request, first, ae.requests(request))
                    self.assertFalse(first.inputs[0].tap_key_sig)
                    first.inputs[0].unknown[ae.key(ae.HOST_ENTROPY, self.pubkey)] = self.entropy
                    response = signtx(ReferenceClient(self.secret), first.serialize())
                    result = PSBT()
                    result.deserialize(response["psbt"])
                    self.assertEqual(result.get_unsigned_tx().serialize_without_witness(), request.get_unsigned_tx().serialize_without_witness())
                    self.assertTrue(ae.verify_signature(self.pubkey, ae.signature_hash(request, 0, hash_type or 0), result.inputs[0].tap_key_sig[:64]))

    def test_missing_or_early_response(self):
        def remove_nonce(result):
            result.inputs[0].unknown.pop(ae.key(ae.SIGNER_NONCE, self.pubkey))

        def add_signature(result):
            result.inputs[0].tap_key_sig = bytes(64)
        for mutation in (remove_nonce, add_signature):
            with self.assertRaises(DeviceFailureError):
                signtx(ReferenceClient(self.secret, mutation), self.psbt.serialize())

    def test_changed_transaction(self):
        def change_sequence(result):
            result.tx.vin[0].nSequence ^= 1
        with self.assertRaisesRegex(DeviceFailureError, "changed the transaction"):
            signtx(ReferenceClient(self.secret, change_sequence), self.psbt.serialize())

    def test_commitment_and_nonce_mismatch(self):
        request = self.round_two_request()
        bad = copy.deepcopy(request)
        bad.inputs[0].unknown[ae.key(ae.HOST_ENTROPY, self.pubkey)] = (6).to_bytes(32, "big")
        with self.assertRaises(BadArgumentError):
            ae.requests(bad)
        bad = copy.deepcopy(request)
        bad.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, self.pubkey)] = point_to_bytes(point_mul(G, 7))
        with self.assertRaisesRegex(DeviceFailureError, "changed its nonce"):
            signtx(ReferenceClient(self.secret), bad.serialize())

    def test_invalid_signature_or_ignored_entropy(self):
        request = self.round_two_request()

        def corrupt_signature(result):
            signature = bytearray(result.inputs[0].tap_key_sig)
            signature[40] ^= 1
            result.inputs[0].tap_key_sig = bytes(signature)

        def wrong_entropy(result):
            result.inputs[0].tap_key_sig = sign(self.secret, ae.signature_hash(request, 0, 0), (6).to_bytes(32, "big"))
        for mutation in (corrupt_signature, wrong_entropy):
            with self.assertRaisesRegex(DeviceFailureError, "verification failed"):
                signtx(ReferenceClient(self.secret, mutation), request.serialize())

    def test_unprotected_extra_signature(self):
        request = self.round_two_request()

        def add_unprotected(result):
            result.inputs[0].tap_script_sigs[(self.pubkey, bytes(32))] = bytes(64)

        with self.assertRaisesRegex(DeviceFailureError, "unprotected signature"):
            signtx(ReferenceClient(self.secret, add_unprotected), request.serialize())

    def test_malformed_requests(self):
        cases = []
        bad = copy.deepcopy(self.psbt)
        bad.inputs[0].unknown[ae.key(ae.HOST_COMMITMENT, self.pubkey)] = bytes(31)
        cases.append(bad)
        bad = copy.deepcopy(self.psbt)
        bad.inputs[0].sighash = 0x81
        cases.append(bad)
        bad = copy.deepcopy(self.psbt)
        bad.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, self.pubkey)] = b"\x02" + bytes([0xff]) * 32
        cases.append(bad)
        bad = copy.deepcopy(self.psbt)
        bad.inputs[0].unknown[ae.PREFIX + b"\x03" + self.pubkey] = bytes(32)
        cases.append(bad)
        for case in cases:
            with self.assertRaises(BadArgumentError):
                ae.requests(case)
        for entropy in (bytes(32), n.to_bytes(32, "big"), bytes(31)):
            with self.assertRaises(ValueError):
                ae.host_commit(entropy)

    def test_field_location_and_encoding(self):
        field = ae.key(ae.HOST_COMMITMENT, self.pubkey)
        for output_map in (False, True):
            bad = copy.deepcopy(self.psbt)
            mapping = bad.outputs[0].unknown if output_map else bad.unknown
            mapping[field] = ae.host_commit(self.entropy)
            with self.assertRaisesRegex(BadArgumentError, "only allowed in PSBT input"):
                ae.requests(bad)
        for malformed in (b"\xfc\xfd\x02\x00ae\x00" + self.pubkey, b"\xfd\xfc\x00\x02ae\x00" + self.pubkey):
            bad = copy.deepcopy(self.psbt)
            bad.inputs[0].unknown = {malformed: ae.host_commit(self.entropy)}
            with self.assertRaisesRegex(BadArgumentError, "Malformed"):
                ae.requests(bad)

        def outside_input(result):
            result.unknown[field] = ae.host_commit(self.entropy)

        with self.assertRaisesRegex(DeviceFailureError, "outside its input map"):
            signtx(ReferenceClient(self.secret, outside_input), self.psbt.serialize())

    def test_nonce_sign_and_infinity(self):
        nonce = point_to_bytes(point_mul(G, n - 5))
        self.assertFalse(ae.host_verify(self.pubkey, bytes(32), bytes(64), self.entropy, nonce))
        request = self.round_two_request()
        response = ReferenceClient(self.secret).sign_tx(request)
        signature = response.inputs[0].tap_key_sig
        msg = ae.signature_hash(request, 0, 0)
        nonce = request.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, self.pubkey)]
        self.assertTrue(ae.host_verify(self.pubkey, msg, signature, self.entropy, nonce))
        flipped = bytes([nonce[0] ^ 1]) + nonce[1:]
        self.assertFalse(ae.host_verify(self.pubkey, msg, signature, self.entropy, flipped))

    def multiple_input_request(self, version):
        request = copy.deepcopy(self.psbt)
        request.tx.vin.append(CTxIn(COutPoint(2, 0), nSequence=0xfffffffd))
        request.tx.vout[0].nValue = 190000
        request.inputs.append(PartiallySignedInput(0))
        request.cache_unsigned_tx_pieces()
        request.inputs[1].witness_utxo = CTxOut(100000, b"\x51\x20" + self.pubkey)
        entropies = [(5 + index).to_bytes(32, "big") for index in range(2)]
        for index, entropy in enumerate(entropies):
            request.inputs[index].unknown[ae.key(ae.HOST_COMMITMENT, self.pubkey)] = ae.host_commit(entropy)
        if version == 2:
            request.convert_to_v2()
        return request, entropies

    def test_multiple_input_receipts(self):
        for version in (0, 2):
            with self.subTest(version=version):
                request, entropies = self.multiple_input_request(version)
                first_result = signtx(ReferenceClient(self.secret), request.serialize())
                self.assertFalse(first_result["signed"])
                first = PSBT()
                first.deserialize(first_result["psbt"])
                for index, entropy in enumerate(entropies):
                    first.inputs[index].unknown[ae.key(ae.HOST_ENTROPY, self.pubkey)] = entropy
                nonce_field = ae.key(ae.SIGNER_NONCE, self.pubkey)
                self.assertNotEqual(first.inputs[0].unknown[nonce_field], first.inputs[1].unknown[nonce_field])
                response = signtx(ReferenceClient(self.secret), first.serialize())
                self.assertTrue(response["signed"])
                signed = PSBT()
                signed.deserialize(response["psbt"])
                self.assertTrue(all(len(psbt_in.tap_key_sig) == 64 for psbt_in in signed.inputs))

                def wrong_second_nonce(result):
                    result.inputs[1].unknown[nonce_field] = point_to_bytes(point_mul(G, 7))

                def bad_second_signature(result):
                    signature = result.inputs[1].tap_key_sig
                    result.inputs[1].tap_key_sig = signature[:-1] + bytes([signature[-1] ^ 1])

                def swap_nonces(result):
                    result.inputs[0].unknown[nonce_field], result.inputs[1].unknown[nonce_field] = result.inputs[1].unknown[nonce_field], result.inputs[0].unknown[nonce_field]

                def changed_second_utxo(result):
                    result.inputs[1].witness_utxo.nValue -= 1

                for mutation in (wrong_second_nonce, bad_second_signature, swap_nonces, changed_second_utxo):
                    with self.subTest(mutation=mutation.__name__):
                        with self.assertRaises(DeviceFailureError):
                            signtx(ReferenceClient(self.secret, mutation), first.serialize())

    def test_partial_input_targeting(self):
        for version in (0, 2):
            with self.subTest(version=version):
                request, entropies = self.multiple_input_request(version)
                request.inputs[1].unknown.clear()
                first_result = signtx(ReferenceClient(self.secret), request.serialize())
                first = PSBT()
                first.deserialize(first_result["psbt"])
                first.inputs[0].unknown[ae.key(ae.HOST_ENTROPY, self.pubkey)] = entropies[0]
                response = signtx(ReferenceClient(self.secret), first.serialize())
                signed = PSBT()
                signed.deserialize(response["psbt"])
                self.assertTrue(signed.inputs[0].tap_key_sig)
                self.assertFalse(signed.inputs[1].tap_key_sig)

                def extra_signature(result):
                    message = ae.signature_hash(result, 1, 0)
                    result.inputs[1].tap_key_sig = sign(self.secret, message, (7).to_bytes(32, "big"))

                with self.assertRaisesRegex(DeviceFailureError, "unprotected signature"):
                    signtx(ReferenceClient(self.secret, extra_signature), first.serialize())

    def test_private_device_diagnostics(self):
        import cbor2
        from hwilib.devices.jade import jade_exception
        from hwilib.devices.jadepy.jade import JadeInterface, device_logger
        from hwilib.devices.jadepy.jade_error import JadeError

        request = self.round_two_request()
        nonce = request.inputs[0].unknown[ae.key(ae.SIGNER_NONCE, self.pubkey)].hex()
        payload = "PRIVATE_TRANSCRIPT " + nonce + " " + self.entropy.hex()

        class ErrorClient(ReferenceClient):
            @jade_exception
            def sign_tx(self, psbt, registrations=None):
                # Use the real SDK decoder's default-level device log path.
                wire = cbor2.dumps({"log": ("E " + payload).encode()})
                wire += cbor2.dumps({"id": "1", "result": None})
                JadeInterface.read_cbor_message(io.BytesIO(wire))
                raise JadeError(JadeError.INTERNAL_ERROR, payload, None)

        output = io.StringIO()
        handler = logging.StreamHandler(output)
        old_handlers, old_level, old_propagate = device_logger.handlers[:], device_logger.level, device_logger.propagate
        old_filters = device_logger.filters[:]
        device_logger.handlers = [handler]
        device_logger.setLevel(logging.WARNING)
        device_logger.propagate = False
        try:
            with self.assertRaises(DeviceFailureError) as raised:
                signtx(ErrorClient(self.secret), request.serialize())
            trace = io.StringIO()
            traceback.print_exception(type(raised.exception), raised.exception, raised.exception.__traceback__, file=trace)
            for private in ("PRIVATE_TRANSCRIPT", nonce, self.entropy.hex()):
                self.assertNotIn(private, str(raised.exception))
                self.assertNotIn(private, trace.getvalue())
                self.assertNotIn(private, output.getvalue())
            self.assertTrue(raised.exception.__suppress_context__)
            self.assertEqual(device_logger.filters, old_filters)
            self.assertFalse(handler.filters)
            device_logger.warning("logging restored")
            self.assertIn("logging restored", output.getvalue())
        finally:
            device_logger.handlers, device_logger.propagate = old_handlers, old_propagate
            device_logger.setLevel(old_level)

    def test_private_logging_context(self):
        logger = logging.getLogger("hwi.test.anti_exfil.logging")
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        old_handlers, old_level, old_propagate = logger.handlers[:], logger.level, logger.propagate
        logger.handlers, logger.propagate = [handler], False
        logger.setLevel(logging.WARNING)
        try:
            for fail in (False, True):
                with self.subTest(failure=fail):
                    failed = False
                    try:
                        with ae.private_operation():
                            logger.error("PRIVATE_TRANSCRIPT")
                            worker = threading.Thread(target=logger.warning, args=("unrelated application log",))
                            worker.start()
                            worker.join()
                            # Nested signing scopes must not unmute the outer one.
                            with ae.private_operation():
                                logger.error("PRIVATE_TRANSCRIPT")
                            logger.error("PRIVATE_TRANSCRIPT")
                            if fail:
                                raise RuntimeError("PRIVATE_TRANSCRIPT")
                    except DeviceFailureError as error:
                        failed = True
                        self.assertTrue(fail)
                        self.assertNotIn("PRIVATE_TRANSCRIPT", str(error))
                    self.assertEqual(failed, fail)
                    logger.warning("logging restored")
                    self.assertNotIn("PRIVATE_TRANSCRIPT", output.getvalue())
                    self.assertIn("unrelated application log", output.getvalue())
                    self.assertIn("logging restored", output.getvalue())
                    self.assertFalse(logger.filters)
                    self.assertFalse(handler.filters)
        finally:
            logger.handlers, logger.propagate = old_handlers, old_propagate
            logger.setLevel(old_level)

    def test_private_last_resort_logging(self):
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        name = "hwi.test.anti_exfil.last_resort"
        while name in logging.Logger.manager.loggerDict:
            name += ".new"
        with patch.object(logging, "lastResort", handler):
            with ae.private_operation():
                # A newly imported SDK logger has no logger-level filter yet.
                logger = logging.getLogger(name)
                logger.propagate = False
                logger.error("PRIVATE_TRANSCRIPT")
            logger.error("logging restored")
            self.assertNotIn("PRIVATE_TRANSCRIPT", output.getvalue())
            self.assertIn("logging restored", output.getvalue())
            self.assertFalse(handler.filters)
            logger.propagate = True

    def test_private_error_categories(self):
        for category in (ActionCanceledError, UnavailableActionError, DeviceConnectionError, DeviceBusyError, BadArgumentError):
            class ErrorClient(ReferenceClient):
                def sign_tx(self, psbt, registrations=None):
                    raise category("PRIVATE_TRANSCRIPT")

            with self.subTest(category=category.__name__):
                with self.assertRaises(category) as raised:
                    signtx(ErrorClient(self.secret), self.psbt.serialize())
                self.assertNotIn("PRIVATE_TRANSCRIPT", str(raised.exception))
                self.assertEqual(raised.exception.get_code(), category("").get_code())

    def test_ordinary_device_diagnostics(self):
        class ErrorClient(ReferenceClient):
            def sign_tx(self, psbt, registrations=None):
                raise RuntimeError("ordinary SDK diagnostic")

        ordinary = copy.deepcopy(self.psbt)
        ordinary.inputs[0].unknown.clear()
        with self.assertRaisesRegex(RuntimeError, "ordinary SDK diagnostic"):
            signtx(ErrorClient(self.secret), ordinary.serialize())

    def test_ledger_nonce_yield(self):
        nonce = signer_commit(self.secret, bytes(32), ae.host_commit(self.entropy))
        encoded = b"\xfe\xfd\xff\xff\xff\x03" + nonce + self.pubkey
        index, receipt = _decode_signpsbt_yielded_value(encoded)
        self.assertEqual(index, 3)
        self.assertIsInstance(receipt, AntiExfilNonce)
        self.assertEqual(receipt.nonce, nonce)
        self.assertEqual(receipt.pubkey, self.pubkey)
        with self.assertRaises(Exception):
            _decode_signpsbt_yielded_value(encoded[:-1])


if __name__ == "__main__":
    unittest.main()
