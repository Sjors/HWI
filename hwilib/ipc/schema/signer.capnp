# Stripped copy of Bitcoin Core's src/ipc/capnp/signer.capnp, without the
# C++ proxy generation annotations. See README.md in this directory.

@0x9d361755b28835a4;

struct SignerInfo {
    fingerprint @0 :Text;
    name @1 :Text;
}

interface ExternalSignerService {
    enumerate @0 (chain :Text) -> (result :List(SignerInfo));
    getDescriptors @1 (fingerprint :Text, chain :Text, account :Int32) -> (receive :List(Text), internal :List(Text), error :Text, result :Bool);
    displayAddress @2 (fingerprint :Text, chain :Text, descriptor :Text) -> (address :Text, error :Text, result :Bool);
    signTransaction @3 (fingerprint :Text, chain :Text, psbt :Data) -> (signedPsbt :Data, error :Text, result :Bool);
}
