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

Successful protected replies from ``hwilib.commands.signtx`` and the CLI are
private host-local protocol messages. These boundaries validate the raw device
response, then copy only validated nonce receipts or verified target signatures
into the original host request. Original caller metadata and the anti-exfil
transcript are retained; unrelated metadata added, changed or removed by the
device is not forwarded. This handles device-controlled bytes from native PSBT
transports such as Jade and Coldcard; it assumes the application and HWI are
trusted parts of the same host.

The trusted host must retain its original state and verify the device
contributions. A calling application may delegate these checks to the checked
``commands.signtx``/CLI boundary. Core additionally performs its own verification;
Core and HWI remain trusted components of the same host. Before exporting a
completed PSBT, the host must strip the anti-exfil fields and copy verified
signatures into its pristine PSBT. Low-level
``HardwareWalletClient.sign_tx`` and SDK calls expose transport results; direct
callers must perform ``anti_exfil.requests`` / ``anti_exfil.check_response`` and
the same original-PSBT reconstruction themselves.

Generate host entropy with a cryptographically secure random generator and
reject zero or values at or above the secp256k1 group order. Never send the entropy
before receiving the device nonce. Keep the transcript private and retain the
same entropy and device commitment on retries. Do not automatically retry an
aborted exchange with fresh entropy. An ordinary ``signtx`` request without these
fields retains its existing behavior.

Protected signing suppresses SDK/device logs only in the active signing context
and returns fixed device-error messages. Cancellation, unavailable-action and
connection categories remain distinguishable. Logs from unrelated application
threads keep their normal behavior. This also protects debug tracebacks from
chained SDK errors containing the nonce transcript.

Library callers that construct and close clients themselves can include that
whole lifetime in ``hwilib.anti_exfil.private_operation()``. The ``signtx``
command guards its device call; a surrounding scope also covers reconnect and
close diagnostics from a previous signing round. The CLI automatically covers
client initialization, signing and close when it recognizes an explicit
anti-exfil PSBT. Device errors use controlled messages throughout that lifetime,
including when ``--debug`` is enabled. A cleanup failure returns an error without
also returning the signing transcript.

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

The same ``--anti-exfil`` option selects the Jade or Coldcard Edge interactive
suite with ``--jade`` or ``--coldcard-edge`` and its corresponding path option.
Jade uses its native PSBT command and advertises ``JADE_TAPROOT_ANTI_EXFIL``.
Coldcard Edge carries the fields through its existing PSBT upload protocol and
requires the matching native ``libngu`` extension. Ordinary Coldcard firmware,
BitBox01, KeepKey, and the legacy Ledger app reject protection requests before
signing. Full device suites include this unsupported-device check.

BitBox02's matching firmware and bundled SDK use an explicit invocation-wide
round and dedicated per-input Taproot fields in the streaming transaction API.
The driver and raw SDK require the advertised capability and do not reuse the
ECDSA anti-klepto channel for Schnorr. ``--bitbox02 --anti-exfil`` selects its
interactive suite. Released firmware is tested to reject the request before
starting a signing exchange.
