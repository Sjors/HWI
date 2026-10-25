# Copyright (c) 2026 The HWI developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Host verification for the draft interactive BIP340 anti-exfil protocol.

Only single-signer Taproot key-path signatures with DEFAULT or ALL are supported.
The proprietary PSBT keys are experimental pending allocation by the BIP process.
All curve operations here process public data; signing belongs on the device.
"""

from dataclasses import dataclass
from contextlib import contextmanager
from contextvars import ContextVar
from io import BytesIO
import hashlib
import logging
import struct
from typing import Dict, Iterator, List, Optional, Set, Union

from ._serialize import deser_compact_size, ser_string
from .errors import ActionCanceledError, BadArgumentError, DeviceBusyError, DeviceConnectionError, DeviceFailureError, HWWError, UnavailableActionError
from .key import G, Point, n, p, point_add, point_mul
from .psbt import PSBT
from .tx import CTxOut


PREFIX = b"\xfc\x02ae"
HOST_COMMITMENT = 0
SIGNER_NONCE = 1
HOST_ENTROPY = 2
HOST_TAG = "BIP-EXFIL/host"


_PRIVATE_LOGGING: ContextVar[bool] = ContextVar("hwi_anti_exfil_private_logging", default=False)


class _PrivateOperationFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Context-local state preserves records from unrelated threads/tasks.
        # QueueHandlers are filtered before private records enter their queues.
        return not _PRIVATE_LOGGING.get()


def _private_error(error: Exception) -> HWWError:
    if isinstance(error, ActionCanceledError):
        return ActionCanceledError("Anti-exfil signing canceled")
    if isinstance(error, UnavailableActionError):
        return UnavailableActionError("Anti-exfil signing is unavailable")
    if isinstance(error, DeviceConnectionError):
        return DeviceConnectionError("Anti-exfil device connection failed")
    if isinstance(error, DeviceBusyError):
        return DeviceBusyError("Anti-exfil device is busy")
    if isinstance(error, BadArgumentError):
        return BadArgumentError("Anti-exfil signer rejected the request")
    return DeviceFailureError("Anti-exfil device operation failed")


@contextmanager
def private_operation(enabled: bool = True) -> Iterator[None]:
    """Keep device diagnostics private in this protected signing context.

    SDK errors and transport/device logs can contain the complete transcript.
    Filter the currently configured loggers/handlers, including lastResort,
    without changing logging levels or muting unrelated application threads.
    Library callers can include client construction and close in this scope.
    """
    if not enabled:
        yield
        return
    token = _PRIVATE_LOGGING.set(True)
    private_filter = _PrivateOperationFilter()
    loggers = [logging.getLogger()] + [
        logger for logger in list(logging.Logger.manager.loggerDict.values())
        if isinstance(logger, logging.Logger)
    ]
    targets: List[Union[logging.Logger, logging.Handler]] = list(loggers)
    for logger in loggers:
        targets.extend(logger.handlers)
    if logging.lastResort is not None:
        targets.append(logging.lastResort)
    installed: List[Union[logging.Logger, logging.Handler]] = []
    seen: Set[int] = set()
    try:
        for target in targets:
            if id(target) in seen:
                continue
            seen.add(id(target))
            target.addFilter(private_filter)
            installed.append(target)
        yield
    except Exception as error:
        # Suppress chained SDK errors too: --debug prints exception tracebacks.
        raise _private_error(error) from None
    finally:
        for target in installed:
            target.removeFilter(private_filter)
        _PRIVATE_LOGGING.reset(token)


def has_fields(psbt: PSBT) -> bool:
    """Recognize explicit protection before opening a CLI device connection."""
    mappings = [psbt.unknown] + [item.unknown for item in psbt.inputs] + [item.unknown for item in psbt.outputs]
    return any(is_field(field) for mapping in mappings for field in mapping)


def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def is_field(encoded_key: bytes) -> bool:
    """Recognize the ae namespace even when its CompactSize encoding is invalid."""
    stream = BytesIO(encoded_key)
    try:
        return deser_compact_size(stream) == 0xfc and deser_compact_size(stream) == 2 and stream.read(2) == b"ae"
    except struct.error:
        return False


def key(subtype: int, pubkey: bytes) -> bytes:
    if subtype not in (HOST_COMMITMENT, SIGNER_NONCE, HOST_ENTROPY) or len(pubkey) != 32:
        raise ValueError("Invalid anti-exfil key")
    return PREFIX + bytes([subtype]) + pubkey


def host_commit(entropy: bytes) -> bytes:
    if len(entropy) != 32 or not 0 < int.from_bytes(entropy, "big") < n:
        raise ValueError("Anti-exfil entropy must be a nonzero scalar")
    return tagged_hash(HOST_TAG, entropy)


def parse_point(encoded: bytes) -> Point:
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("Invalid compressed anti-exfil nonce")
    x = int.from_bytes(encoded[1:], "big")
    if x >= p:
        raise ValueError("Anti-exfil nonce coordinate out of range")
    y = pow((x ** 3 + 7) % p, (p + 1) // 4, p)
    if y * y % p != (x ** 3 + 7) % p:
        raise ValueError("Anti-exfil nonce is not on the curve")
    if y & 1 != encoded[0] & 1:
        y = p - y
    return (x, y)


def verify_signature(pubkey: bytes, msg: bytes, signature: bytes) -> bool:
    if len(pubkey) != 32 or len(msg) != 32 or len(signature) != 64:
        return False
    try:
        point = parse_point(b"\x02" + pubkey)
    except ValueError:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r >= p or s >= n:
        return False
    challenge = int.from_bytes(tagged_hash("BIP0340/challenge", signature[:32] + pubkey + msg), "big") % n
    nonce = point_add(point_mul(G, s), point_mul(point, n - challenge))
    return nonce is not None and nonce[1] & 1 == 0 and nonce[0] == r


def host_verify(pubkey: bytes, msg: bytes, signature: bytes, entropy: bytes, signer_nonce: bytes) -> bool:
    """Verify both the ordinary signature and the committed nonce relation."""
    try:
        host_commit(entropy)
        expected_nonce = point_add(parse_point(signer_nonce), point_mul(G, int.from_bytes(entropy, "big")))
    except ValueError:
        return False
    return (
        expected_nonce is not None
        and len(signature) == 64
        and signature[:32] == expected_nonce[0].to_bytes(32, "big")
        and verify_signature(pubkey, msg, signature)
    )


def get_utxo(psbt: PSBT, index: int) -> CTxOut:
    psbt_in = psbt.inputs[index]
    if psbt_in.non_witness_utxo is not None:
        previous = psbt_in.non_witness_utxo
        previous.rehash()
        if previous.hash != psbt_in.prev_txid or psbt_in.prev_out is None or psbt_in.prev_out >= len(previous.vout):
            raise BadArgumentError("Anti-exfil input has an incorrect previous transaction")
        utxo = previous.vout[psbt_in.prev_out]
        if psbt_in.witness_utxo is not None and psbt_in.witness_utxo.serialize() != utxo.serialize():
            raise BadArgumentError("Anti-exfil input UTXOs disagree")
        return utxo
    if psbt_in.witness_utxo is None:
        raise BadArgumentError("Anti-exfil requires UTXO data for every input")
    return psbt_in.witness_utxo


def signature_hash(psbt: PSBT, index: int, hash_type: int) -> bytes:
    """BIP341 key-path signature message, without annex or ANYONECANPAY."""
    if hash_type not in (0, 1):
        raise BadArgumentError("Anti-exfil only supports DEFAULT and ALL")
    tx = psbt.get_unsigned_tx()
    utxos = [get_utxo(psbt, i) for i in range(len(tx.vin))]

    def sha(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()
    msg = bytes([0, hash_type]) + struct.pack("<iI", tx.nVersion, tx.nLockTime)
    msg += sha(b"".join(txin.prevout.serialize() for txin in tx.vin))
    msg += sha(b"".join(struct.pack("<q", utxo.nValue) for utxo in utxos))
    msg += sha(b"".join(ser_string(utxo.scriptPubKey) for utxo in utxos))
    msg += sha(b"".join(struct.pack("<I", txin.nSequence) for txin in tx.vin))
    msg += sha(b"".join(txout.serialize() for txout in tx.vout))
    msg += b"\x00" + struct.pack("<I", index)  # key path, no annex
    return tagged_hash("TapSighash", msg)


@dataclass(frozen=True)
class Request:
    pubkey: bytes
    commitment: bytes
    signer_nonce: Optional[bytes]
    entropy: Optional[bytes]
    hash_type: int
    message: bytes


def requests(psbt: PSBT) -> Dict[int, Request]:
    """Parse and validate explicit anti-exfil requests before device access."""
    if any(is_field(field) for mapping in [psbt.unknown] + [output.unknown for output in psbt.outputs] for field in mapping):
        raise BadArgumentError("Anti-exfil fields are only allowed in PSBT input maps")
    result = {}
    round_number = None
    for index, psbt_in in enumerate(psbt.inputs):
        fields = {}
        pubkey = None
        for encoded_key, value in psbt_in.unknown.items():
            if not is_field(encoded_key):
                continue
            if not encoded_key.startswith(PREFIX) or len(encoded_key) != 37 or encoded_key[4] not in (0, 1, 2):
                raise BadArgumentError("Malformed anti-exfil PSBT field")
            if pubkey is not None and pubkey != encoded_key[5:]:
                raise BadArgumentError("Only one anti-exfil signing key per input is supported")
            pubkey = encoded_key[5:]
            fields[encoded_key[4]] = value
        if not fields:
            continue
        if HOST_COMMITMENT not in fields or len(fields[HOST_COMMITMENT]) != 32:
            raise BadArgumentError("Anti-exfil host commitment is missing or invalid")
        if psbt_in.tap_key_sig or psbt_in.tap_script_sigs or psbt_in.final_script_sig or not psbt_in.final_script_witness.is_null():
            raise BadArgumentError("Anti-exfil input already contains signatures or finalized data")
        assert pubkey is not None
        utxo = get_utxo(psbt, index)
        if utxo.scriptPubKey != b"\x51\x20" + pubkey:
            raise BadArgumentError("Anti-exfil key must be the Taproot output key")
        try:
            parse_point(b"\x02" + pubkey)
        except ValueError as error:
            raise BadArgumentError(str(error))
        signer_nonce = fields.get(SIGNER_NONCE)
        entropy = fields.get(HOST_ENTROPY)
        if entropy is None and signer_nonce is not None:
            raise BadArgumentError("Anti-exfil nonce requires the host reveal")
        current_round = 2 if entropy is not None else 1
        if round_number is not None and current_round != round_number:
            raise BadArgumentError("Anti-exfil rounds cannot be mixed in one request")
        round_number = current_round
        try:
            if signer_nonce is not None:
                parse_point(signer_nonce)
            if entropy is not None and (signer_nonce is None or host_commit(entropy) != fields[HOST_COMMITMENT]):
                raise ValueError("Anti-exfil entropy does not open the host commitment")
        except ValueError as error:
            raise BadArgumentError(str(error))
        hash_type = psbt_in.sighash if psbt_in.sighash is not None else 0
        result[index] = Request(pubkey, fields[HOST_COMMITMENT], signer_nonce, entropy, hash_type, signature_hash(psbt, index, hash_type))
    return result


def check_response(original: PSBT, response: PSBT, expected: Dict[int, Request]) -> None:
    """Fail closed on unsupported firmware or a changed anti-exfil transcript."""
    if not expected:
        return
    if any(is_field(field) for mapping in [response.unknown] + [output.unknown for output in response.outputs] for field in mapping):
        raise DeviceFailureError("Anti-exfil signer returned a field outside its input map")
    if original.version != response.version or original.get_unsigned_tx().serialize_without_witness() != response.get_unsigned_tx().serialize_without_witness():
        raise DeviceFailureError("Anti-exfil signer changed the transaction")
    first_round = next(iter(expected.values())).entropy is None
    if first_round and any(
        after.tap_key_sig != before.tap_key_sig
        or after.tap_script_sigs != before.tap_script_sigs
        or after.partial_sigs != before.partial_sigs
        or after.final_script_sig != before.final_script_sig
        or after.final_script_witness.serialize() != before.final_script_witness.serialize()
        for before, after in zip(original.inputs, response.inputs)
    ):
        raise DeviceFailureError("Anti-exfil commitment round returned signatures")
    for index, (before, after) in enumerate(zip(original.inputs, response.inputs)):
        for encoded_key in after.unknown:
            if not is_field(encoded_key):
                continue
            target = expected.get(index)
            if target is None or not encoded_key.startswith(PREFIX) or len(encoded_key) != 37 or encoded_key[4] not in (0, 1, 2) or encoded_key[5:] != target.pubkey:
                raise DeviceFailureError("Anti-exfil signer returned an unexpected transcript field")
        try:
            if get_utxo(original, index).serialize() != get_utxo(response, index).serialize():
                raise DeviceFailureError("Anti-exfil signer changed input UTXO data")
        except BadArgumentError as error:
            raise DeviceFailureError(str(error))
        if after.sighash != before.sighash:
            raise DeviceFailureError("Anti-exfil signer changed the declared sighash type")
        if (
            after.partial_sigs != before.partial_sigs
            or after.tap_script_sigs != before.tap_script_sigs
            or after.final_script_sig != before.final_script_sig
            or after.final_script_witness.serialize() != before.final_script_witness.serialize()
            or (index not in expected and after.tap_key_sig != before.tap_key_sig)
        ):
            raise DeviceFailureError("Anti-exfil signer returned an unprotected signature")
    for index, request in expected.items():
        after = response.inputs[index]
        if after.unknown.get(key(HOST_COMMITMENT, request.pubkey)) != request.commitment:
            raise DeviceFailureError("Anti-exfil signer changed the host commitment")
        nonce = after.unknown.get(key(SIGNER_NONCE, request.pubkey))
        try:
            if nonce is None:
                raise ValueError("Anti-exfil nonce missing; device may not support anti-exfil")
            parse_point(nonce)
        except ValueError as error:
            raise DeviceFailureError(str(error))
        if request.signer_nonce is not None and nonce != request.signer_nonce:
            raise DeviceFailureError("Anti-exfil signer changed its nonce commitment")
        if first_round:
            if key(HOST_ENTROPY, request.pubkey) in after.unknown:
                raise DeviceFailureError("Anti-exfil commitment round returned host entropy")
            continue
        if after.unknown.get(key(HOST_ENTROPY, request.pubkey)) != request.entropy:
            raise DeviceFailureError("Anti-exfil signer changed host entropy")
        signature = after.tap_key_sig
        expected_length = 64 if request.hash_type == 0 else 65
        if len(signature) != expected_length or (expected_length == 65 and signature[-1] != request.hash_type):
            raise DeviceFailureError("Anti-exfil signer returned an unexpected sighash type")
        assert request.entropy is not None
        if not host_verify(request.pubkey, request.message, signature[:64], request.entropy, nonce):
            raise DeviceFailureError("Anti-exfil signature or nonce verification failed")
