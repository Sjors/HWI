Interactive Taproot anti-exfil
=============================

This experimental interface implements the draft single-signer BIP340 anti-exfil
protocol. It requires matching device firmware. It supports Taproot key-path
inputs with ``SIGHASH_DEFAULT`` or ``SIGHASH_ALL``; it does not extend MuSig2,
FROST, or script-path signing.

The host runs ``signtx`` twice. Each requested PSBT input carries proprietary
keys encoded as ``fc 02 61 65 <subtype> <output-key>``. The identifier is ``ae``;
the output key is the 32-byte x-only Taproot output key, rather than its internal
key. Subtype 0 holds a 32-byte host commitment, subtype 1 a compressed 33-byte
device nonce, and subtype 2 the host's 32-byte entropy scalar. These experimental
keys are subject to change during specification review.

In the first call the input contains only the host commitment. The device returns
its original nonce and no signature. The host checks and retains that response,
adds its entropy, and makes the second call. HWI verifies that the signature uses
the committed device nonce plus the host contribution and verifies the BIP340
signature against the original transaction. A missing proof, early signature,
changed transaction, or unsupported device fails instead of returning an
unprotected result. The presence of these fields is an explicit protection
request; there is no fallback to ordinary signing.

Generate host entropy with a cryptographically secure random generator and
reject zero or values at or above the secp256k1 group order. Never send the entropy
before receiving the device nonce. Keep the transcript private and retain the
same entropy and device commitment on retries. Do not automatically retry an
aborted exchange with fresh entropy. An ordinary ``signtx`` request without these
fields retains its existing behavior.

The first firmware integration uses the Ledger Bitcoin app with its draft
anti-exfil extension. Its round-1 nonce is transported with yield tag
``0xfffffffd``, followed by the input index, compressed nonce, and x-only key.
Stock firmware is not claimed to support this extension.

To exercise matching firmware in Speculos, run from ``test/``::

    python run_tests.py --ledger-anti-exfil --interface=library \
      --ledger-path=/absolute/path/to/speculos.py \
      --bitcoind=/absolute/path/to/bitcoind

The opt-in test covers DEFAULT and ALL, deterministic commitment retries,
firmware rejection of mismatched openings, host verification, mempool acceptance,
broadcast, and confirmation. The normal non-device test suite includes shared
cryptographic vectors and rejection tests for malformed or malicious responses.

To include the full Bitcoin Core host -> HWI subprocess -> Ledger path, add
``--ledger-anti-exfil-core`` and point ``--bitcoind`` at the matching Core build
with ``-signerantiexfil`` support. The test starts an independent node with that
setting enabled, creates an external-signer wallet, exercises
``walletprocesspsbt`` and ``send``, checks transcript removal, and confirms the
broadcast transaction.

Trezor One and T firmware with the provisional ``BitcoinAntiExfil`` capability
uses the same PSBT transcript. The bridge carries it in optional Bitcoin input
fields and returns commitment receipts separately from signatures. The bridge
rejects protection requests before signing when firmware lacks that capability.

Run either matching emulator's interactive suite using ``--anti-exfil`` with
``--trezor-1`` or ``--trezor-t`` and its corresponding path option. Run the
ordinary device suite separately without ``--anti-exfil``; it checks ordinary
signing as well as rejection on devices without the capability.
