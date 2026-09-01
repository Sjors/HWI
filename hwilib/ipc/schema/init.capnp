# Stripped copy of Bitcoin Core's src/ipc/capnp/init.capnp with only the
# method HWI calls. See README.md in this directory.

@0xf2c5cfa319406aa6;

using Signer = import "signer.capnp";

interface Init {
    # Methods @0-@4 exist only to keep registerExternalSigner at its real
    # ordinal; their signatures are stubbed out and they must never be called.
    construct @0 () -> ();
    makeEcho @1 () -> ();
    makeMiningOld2 @2 () -> ();
    makeMining @3 () -> ();
    makeRpc @4 () -> ();

    registerExternalSigner @5 (signer :Signer.ExternalSignerService) -> ();
}
