# Bitcoin Core IPC schemas

These are stripped copies of Bitcoin Core's Cap'n Proto schemas
(`src/ipc/capnp/init.capnp` and `src/ipc/capnp/signer.capnp`), with the C++
proxy generation annotations (`$Proxy.*`, `$Cxx.*`) removed and, for
`init.capnp`, all methods HWI does not call reduced to stubs.

This works because Cap'n Proto derives an interface's type ID from the file ID
and the declaration's name, and dispatches calls on the interface ID, method
ordinal and positional parameter layout. As long as these files keep the same
file IDs, the same top-level declaration names, and the same ordinals and
field layouts for the methods actually used, they interoperate with the
schemas compiled into `bitcoin-node`.

When updating: keep the `@0x...` file IDs identical to Bitcoin Core's, never
renumber fields or methods, and never call the stub methods. If this scheme
ever causes trouble, the fallback is to vendor Bitcoin Core's schema files
verbatim (plus libmultiprocess's `mp/proxy.capnp`, which they import).
