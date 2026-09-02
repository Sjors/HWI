"""
Bitcoin Core IPC signer service
*******************************

Serve HWI as a Bitcoin Core external signer over Cap'n Proto IPC.

Bitcoin Core's ``bitcoin-node`` binary can listen on a unix socket with
``-ipcbind=unix``. This module connects to that socket and registers HWI as
the node's external signer backend, replacing the ``-signer=<cmd>`` model of
spawning ``hwi`` for every operation. See Bitcoin Core's
``doc/external-signer.md`` and the schemas in ``hwilib/ipc/schema``.

Each signer call resolves the device by fingerprint with a fresh client,
matching the behavior of one CLI invocation per operation. Expected failures
(device missing, user cancel) are reported in-band via the ``error``/
``result`` fields; an uncaught exception here reaches the node as a
transport error and makes it drop the registration.
"""

import argparse
import asyncio
import base64
import logging
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Optional

# Optional dependency: everything except serving works without it, so e.g.
# default_socket_path() stays importable in environments without the extra.
try:
    import capnp  # type: ignore
except ImportError:
    capnp = None

from . import commands
from .common import Chain
from .errors import DEVICE_CONN_ERROR, UnavailableActionError, handle_errors
from .hwwclient import HardwareWalletClient

SCHEMA_DIR = Path(__file__).parent / "ipc" / "schema"


def default_socket_path(chain: Chain) -> str:
    """The default path of Bitcoin Core's -ipcbind=unix socket for this
    platform and chain: <datadir>/<chain subdirectory>/node.sock."""
    if sys.platform == "win32":
        datadir = Path(os.environ["APPDATA"]) / "Bitcoin"
    elif sys.platform == "darwin":
        datadir = Path.home() / "Library" / "Application Support" / "Bitcoin"
    else:
        datadir = Path.home() / ".bitcoin"
    subdir = {
        Chain.MAIN: None,
        Chain.TEST: "testnet3",
        Chain.REGTEST: "regtest",
        Chain.SIGNET: "signet",
        Chain.TESTNET4: "testnet4",
    }[chain]
    if subdir is not None:
        datadir = datadir / subdir
    return str(datadir / "node.sock")


def load_schemas() -> Any:
    imports = [str(SCHEMA_DIR)]
    signer = capnp.load(str(SCHEMA_DIR / "signer.capnp"), imports=imports)
    init = capnp.load(str(SCHEMA_DIR / "init.capnp"), imports=imports)
    return init, signer


def make_signer_server(signer_schema: Any, password: str, allow_emulators: bool) -> Any:

    class SignerServer(signer_schema.ExternalSignerService.Server):  # type: ignore

        def _with_client(self, fingerprint: str, chain_str: str, func: Callable[[HardwareWalletClient], Dict[str, Any]]) -> Dict[str, Any]:
            """Resolve the device by fingerprint, run func with a fresh
            client, and close it. Mirrors one CLI invocation."""
            result: Dict[str, Any] = {}
            with handle_errors(result=result):
                chain = Chain.argparse(chain_str)
                if not isinstance(chain, Chain):
                    raise Exception(f"Invalid chain: {chain_str}")
                client = commands.find_device(password=password, fingerprint=fingerprint, chain=chain, allow_emulators=allow_emulators)
                if client is None:
                    return {"error": "Could not find device with specified fingerprint", "code": DEVICE_CONN_ERROR}
                try:
                    result = func(client)
                finally:
                    with handle_errors(result={}):
                        client.close()
            return result

        async def enumerate(self, chain, _context, **kwargs):
            chain_enum = Chain.argparse(chain)
            if not isinstance(chain_enum, Chain):
                raise Exception(f"Invalid chain: {chain}")
            devices = commands.enumerate(password=password, chain=chain_enum, allow_emulators=allow_emulators)
            # The typed API carries no per-device error entries: skip
            # devices which failed to report a fingerprint.
            _context.results.result = [
                {"fingerprint": d["fingerprint"], "name": d.get("model", "")}
                for d in devices if d.get("fingerprint")
            ]

        async def getDescriptors(self, fingerprint, chain, account, _context, **kwargs):
            res = self._with_client(fingerprint, chain, lambda client: commands.getdescriptors(client, account))
            r = _context.results
            if "error" in res:
                r.error = res["error"]
                r.result = False
            else:
                r.receive = res["receive"]
                r.internal = res["internal"]
                r.result = True

        async def displayAddress(self, fingerprint, chain, descriptor, _context, **kwargs):
            res = self._with_client(fingerprint, chain, lambda client: commands.displayaddress(client, desc=descriptor))
            r = _context.results
            if "error" in res:
                r.error = res["error"]
                r.result = False
            else:
                r.address = res["address"]
                r.result = True

        async def signTransaction(self, fingerprint, chain, psbt, _context, **kwargs):
            psbt_b64 = base64.b64encode(bytes(psbt)).decode("ascii")
            res = self._with_client(fingerprint, chain, lambda client: commands.signtx(client, psbt_b64))
            r = _context.results
            if "error" in res:
                r.error = res["error"]
                r.result = False
            else:
                r.signedPsbt = base64.b64decode(res["psbt"])
                r.result = True

    return SignerServer


async def serve(socket_path: str, password: str, allow_emulators: bool, on_registered: Optional[Callable[[], None]] = None) -> None:
    init_schema, signer_schema = load_schemas()
    connection = await capnp.AsyncIoStream.create_unix_connection(socket_path)
    client = capnp.TwoPartyClient(connection)
    init = client.bootstrap().cast_as(init_schema.Init)
    server_class = make_signer_server(signer_schema, password, allow_emulators)
    await init.registerExternalSigner(server_class())
    logging.info(f"Registered as external signer with the node at {socket_path}")
    if on_registered is not None:
        on_registered()
    # Serve signer calls until the node disconnects.
    await client.on_disconnect()
    logging.info("Node disconnected, exiting")


def run_signer_service(socket_path: str, password: str, allow_emulators: bool, on_registered: Optional[Callable[[], None]] = None) -> None:
    """Connect to the node, register as its external signer and serve until
    the node disconnects. Blocks the calling thread."""
    if capnp is None:
        raise UnavailableActionError("IPC support requires the pycapnp package. Install it with: pip install hwi[ipc]")
    asyncio.run(capnp.run(serve(socket_path, password, allow_emulators, on_registered)))


def ipc_signer_handler(args: argparse.Namespace) -> None:
    socket_path = args.socket_path or default_socket_path(args.chain)
    run_signer_service(socket_path, args.password, args.allow_emulators)
