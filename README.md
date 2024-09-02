---
title: Proxy Authenticator
---

A Proxy Authenticator is a way to verify / authenticate the signature / intent of a transaction to be executed by the [Proxy](../proxy/README.md) is indeed from the controlling `Entity` of said [Proxy](../proxy/README.md).

The `Entity` can choose the authentication method, typically to be Webauthn / Passkeys.
However, more authenticators can be added in the future.

Authentcators are shared between all Proxies and their addresses are stored in D-Chain's [Abstract Account](../../../modules/abstractaccount) module.

### Interactions with other contracts / modules:

- `Proxy` - does a wasm call for the logic
- `Abstract Account` Module - stores the authenticator addresses so that `Proxy` can use them on authentication in `before_tx`.

### Traits

All authenticators must implement the `authenticator_trait` defined in `dchain-interfaces` package.
