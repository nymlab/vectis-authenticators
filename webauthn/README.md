---
title: Webauthn
---

Webauthn is a standard for secure public key authentication on the web.
It is a browser API that allows users to register and authenticate with a website using a security key, biometrics, or a mobile device.
Webauthn is supported by most modern browsers and is considered more secure than traditional password-based authentication.

This authenticator expects the D-Chain transaction to be proposed as the `challenge`,
which will be signed with [-7 on the COSE registry](https://www.iana.org/assignments/cose/cose.xhtml#algorithms), ECDSA with SHA-256.

Important to note that webauthn credentials (private keys) are scoped to the `relying party`,
the domain.
This means that whilst such domain cannot access the private key to sign on behalf of the `Entity` (non-custodial), they can however block the `Entity` from signing transactions.
