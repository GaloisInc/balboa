---
title: "Balboa Injections"
...

In order for Balboa to operate it must be injected into a target process. On Mac, it is injected via `DYLD_INSERT_LIBRARIES` and on Linux it's injected via `LD_PRELOAD`. See [[Balboa Injection Framework]] for more info.

Injections in Balboa are instantiated via Rust crates with the `cdylib` `crate-type`. See `balboa/injections/nginx` for an example.

These injections configure how connections will be rewritten in Balboa. On the server-side, Balboa is configured to intercept connections accepted on a given socket via:

```rust
fn listen_on_addr(&self, remote: SocketAddr) -> bool;
fn rewriters_for_tcp_server(&self, remote: SocketAddr) -> Option<(
    Box<dyn IncomingRewriter + Send>,
    Box<dyn OutgoingRewriter + Send>,
)>;
```

`listen_on_addr` configured whether Balboa will care about a particular socket that `bind` was called on. `rewriters_for_tcp_server` is invoked when a socket is accepted. It can optionally return functions to operate on the TCP data sent to/from the kernel. (That is, if TLS is being used, the data seen by these functions will be encrypted.)

On the client side, similar functionality exists:

```rust
fn rewriters_for_tcp_client(
    &self,
    remote: SocketAddr,
) -> Option<(
    Box<dyn IncomingRewriter + Send>,
    Box<dyn OutgoingRewriter + Send>,
)>;
```

This function allows the injection to specify how TCP data should be rewritten on outgoing connections.

In order to process TLS-encrypted data, the [Balboa Injection Framework](./Balboa%20Injection%20Framework.md) is invoked.