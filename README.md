[![Build Status](https://travis-ci.org/fluencelabs/crypto.svg?branch=master)](https://travis-ci.org/fluencelabs/crypto)
[![Gitter](https://badges.gitter.im/fluencelabs/crypto.svg)](https://gitter.im/fluencelabs/crypto?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# Сrypto

Cryptography for Scala and Scala.js, FP-flavoured.

APIs are mostly based on [codec](https://github.com/fluencelabs/codec) approach with partial bijections, using `CryptoError` case class for errors.

## Submodules

### crypto-core

Provides APIs and data types for various cryptographical operations, but without implementations.

This library should be added as dependency to both implementations of crypto algorithms and on the user side, if particular app doesn't require a particular algorithm.

### crypto-hashsign

Cross-platform hashing and signing algos.

Use a `fluence.crypto.hash.CryptoHashers` to access a hashing algorithm. Currently `Sha1` and `Sha256` are provided.

`fluence.crypto.ecdsa.Ecdsa.signAlgo` is an instance of `SignAlgo` with `ecdsa_secp256k1_sha256` under the hood.

### crypto-cipher

Encryption and decryption algorithms, coded as arrows and bijections. Currently contains `AES` ciphering.

### crypto-keystore

Provides a JSON format for serializing a keypair, using `codec-circe` for JSON processing.

For Scala on JVM, storing on the disc is implemented with use of `cats-effect`. 

### crypto-jwt

Simplified JWT implementation, meaning a JSON-serialized header and claim with signature checking.

`codec-circe` is used for JSON encoding/decoding, and `codec-bits` for binary data manipulations.

## Installation

```scala
// Bintray repo is used so far. Migration to Maven Central is planned
resolvers += Resolver.bintrayRepo("fluencelabs", "releases")

val cryptoV = "0.0.1"

libraryDependencies ++= Seq(
  "one.fluence" %%% "crypto-core" % cryptoV, // basic types and APIs
  "one.fluence" %%% "crypto-hashsign" % cryptoV, // hashers and signatures
  "one.fluence" %%% "crypto-cipher" % cryptoV, // encoding and decoding
  "one.fluence" %%% "crypto-keystore" % cryptoV, // serialize and store a keypair
  "one.fluence" %%% "crypto-jwt" % cryptoV // simple JWT implementation
)
```

## License

Fluence is free software; you can redistribute it and/or modify it under the terms of the GNU Affero General Public License v3 (AGPLv3) as published by the Free Software Foundation.

Fluence includes some [external modules](https://github.com/fluencelabs/crypto/blob/master/build.sbt) that carry their own licensing.