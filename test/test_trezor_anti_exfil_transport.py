"""Unit tests for Trezor's nonce receipt wire transport."""
from io import BytesIO
import unittest
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
