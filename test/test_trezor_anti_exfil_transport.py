"""Unit tests for Trezor's nonce receipt wire transport."""
from io import BytesIO
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import test_anti_exfil as fixtures
from hwilib import anti_exfil as ae
from hwilib.common import Chain
from hwilib.devices.trezor import TrezorClient
from hwilib.errors import BadArgumentError, DeviceFailureError
from hwilib.key import KeyOriginInfo
from hwilib._base58 import get_xpub_fingerprint
from hwilib.devices.trezorlib import btc, messages, protobuf


class Client:
    def __init__(self, receipt):
        self.receipt = receipt

    def open(self):
        pass

    def close(self):
        pass

    def call(self, request):
        return messages.TxRequest(request_type=messages.RequestType.TXFINISHED,
                                  serialized=self.receipt)


class TestTrezorAntiExfilTransport(unittest.TestCase):
    def setUp(self):
        self.input = messages.TxInputType(
            prev_hash=bytes(32), prev_index=0,
            script_type=messages.InputScriptType.SPENDTAPROOT,
            anti_exfil_host_commitment=bytes([1]) * 32,
        )
        self.nonce = bytes([3]) + bytes([2]) * 32

    def test_ordinary_input_has_no_anti_exfil_fields(self):
        ordinary = messages.TxInputType(prev_hash=bytes(32), prev_index=0)
        encoded = BytesIO()
        protobuf.dump_message(encoded, ordinary)
        decoded = protobuf.load_message(BytesIO(encoded.getvalue()), messages.TxInputType)
        for name in ("anti_exfil_host_commitment", "anti_exfil_signer_nonce",
                     "anti_exfil_host_entropy", "anti_exfil_sighash"):
            self.assertIsNone(getattr(ordinary, name))
            self.assertIsNone(getattr(decoded, name))

    def test_wire_roundtrip(self):
        self.input.anti_exfil_signer_nonce = self.nonce
        self.input.anti_exfil_host_entropy = bytes([4]) * 32
        self.input.anti_exfil_sighash = 1
        encoded = BytesIO()
        protobuf.dump_message(encoded, self.input)
        decoded = protobuf.load_message(BytesIO(encoded.getvalue()), messages.TxInputType)
        for name in ("anti_exfil_host_commitment", "anti_exfil_signer_nonce",
                     "anti_exfil_host_entropy", "anti_exfil_sighash"):
            self.assertEqual(getattr(decoded, name), getattr(self.input, name))

    def test_receipt_is_not_signature(self):
        nonces = {}
        client = Client(messages.TxRequestSerializedType(signature_index=0,
                        anti_exfil_nonce=self.nonce))
        signatures, transaction = btc.sign_tx(client, "Bitcoin", [self.input], [],
                                              anti_exfil_nonces=nonces, serialize=False)
        self.assertEqual(signatures, [None])
        self.assertEqual(transaction, b"")
        self.assertEqual(nonces, {0: self.nonce})

    def test_direct_driver_checks_signature_proof(self):
        fixture = fixtures.TestAntiExfil()
        fixture.setUp()
        psbt = fixture.round_two_request()
        xpub = "tpubDCknDegFqAdP4V2AhHhs635DPe8N1aTjfKE9m2UFbdej8zmeNbtqDzK59SxnsYSRSx5uS3AujbwgANUiAk4oHmDNUKoGGkWWUY6c48WgjEx"
        psbt.inputs[0].tap_internal_key = fixture.pubkey
        psbt.inputs[0].tap_bip32_paths[fixture.pubkey] = ([], KeyOriginInfo(
            get_xpub_fingerprint(xpub), [0x80000056, 0x80000001, 0x80000000, 0, 0]))
        request = ae.requests(psbt)[0]
        client = TrezorClient.__new__(TrezorClient)
        client.chain = Chain.TEST
        client.coin_name = "Testnet"
        client.client = object()
        # A malicious firmware can return a valid signature whose nonce ignores
        # the originally recorded host transcript. The direct library API must
        # reject this too, without relying on commands.signtx's outer verifier.
        signature = fixtures.sign(fixture.secret, request.message, (7).to_bytes(32, "big"))
        self.assertTrue(ae.verify_signature(fixture.pubkey, request.message, signature))
        with patch.object(client, "_check_unlocked"), patch.object(client, "can_sign_anti_exfil", return_value=True):
            with patch.object(btc, "get_public_node", return_value=SimpleNamespace(xpub=xpub)):
                with patch.object(btc, "sign_tx", return_value=([signature], b"")):
                    with self.assertRaises(DeviceFailureError):
                        client.sign_tx(psbt)
        self.assertFalse(psbt.inputs[0].tap_key_sig)
        # Unowned protected targets must be rejected before the ordinary
        # external-input fallback can ask the device for an unrelated signature.
        psbt.inputs[0].tap_bip32_paths.clear()
        with patch.object(client, "_check_unlocked"), patch.object(client, "can_sign_anti_exfil", return_value=True):
            with patch.object(client, "_supports_external", return_value=True):
                with patch.object(btc, "get_public_node", return_value=SimpleNamespace(xpub=xpub)):
                    with patch.object(btc, "sign_tx", return_value=([signature], b"")) as signer:
                        with self.assertRaises(BadArgumentError):
                            client.sign_tx(psbt)
                        signer.assert_not_called()

    def test_invalid_receipts(self):
        for receipt in (
            messages.TxRequestSerializedType(signature_index=1, anti_exfil_nonce=self.nonce),
            messages.TxRequestSerializedType(signature_index=0, anti_exfil_nonce=bytes(32)),
            messages.TxRequestSerializedType(signature_index=0, signature=bytes(64)),
            messages.TxRequestSerializedType(signature_index=0, signature=bytes(64), anti_exfil_nonce=self.nonce),
            messages.TxRequestSerializedType(),
        ):
            with self.subTest(receipt=receipt):
                with self.assertRaises(Exception):
                    btc.sign_tx(Client(receipt), "Bitcoin", [self.input], [],
                                anti_exfil_nonces={}, serialize=False)


if __name__ == "__main__":
    unittest.main()
