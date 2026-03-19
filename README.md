# bls12-381

[![Build & Test](https://github.com/Anvo-Network/bls12-381/actions/workflows/build.yaml/badge.svg)](https://github.com/Anvo-Network/bls12-381/actions/workflows/build.yaml)

A high-performance C++20 implementation of BLS (Boneh-Lynn-Shacham) signatures on the BLS12-381 elliptic curve. Provides G1/G2 group operations, optimal pairings, aggregate signatures, and EIP-compliant key derivation with zero external dependencies.

## Features

- **Optimized field arithmetic** -- x86_64 assembly fast path with pure C++ fallback for other architectures (ARM64, WASM, etc.)
- **G1/G2 point arithmetic and pairing** -- addition, scalar multiplication, optimal Ate pairing
- **BLS signatures** -- sign, verify, aggregate signatures, aggregate verification
- **Proof of Possession (PoP)** -- prove, verify, fast aggregate verify
- **[EIP-2537](https://eips.ethereum.org/EIPS/eip-2537)** -- BLS12-381 precompile operations
- **[EIP-2333](https://eips.ethereum.org/EIPS/eip-2333)** -- BLS key derivation (HKDF-based, hierarchical deterministic)
- **Zero dependencies** -- self-contained SHA-256, HKDF, and field arithmetic
- **WASM compatible** -- builds for WebAssembly targets

## Requirements

- C++20 compiler (GCC 10+, Clang 12+, Apple Clang 13+)
- CMake 3.12+
- x86_64 assembler (optional -- C++ fallback used on other architectures)

## Building

```bash
cmake -B build
cmake --build build -j
```

### Running tests

```bash
cd build && ctest --output-on-failure
```

### Running benchmarks

```bash
./build/bench/eth_bench    # Ethereum compatibility benchmarks
./build/bench/chia_bench   # Chia network benchmarks
```

## Usage

### Key generation

```cpp
#include <bls12-381/bls12-381.hpp>

using namespace bls12_381;

// Initialize the library (detects CPU features for assembly fast path)
init();

// Generate a secret key from a 32+ byte seed
std::vector<uint8_t> seed(32);
// ... fill seed with cryptographically secure random bytes ...
auto sk = secret_key(seed);

// Derive the public key (G1 point)
auto pk = public_key(sk);
```

### Signing and verification

```cpp
// Sign a message
std::vector<uint8_t> message = {0x01, 0x02, 0x03};
g2 signature = sign(sk, message);

// Verify the signature
bool valid = verify(pk, message, signature);
```

### Aggregate signatures

```cpp
// Multiple signers
auto [sk1, sk2, sk3] = std::tuple{secret_key(seed1), secret_key(seed2), secret_key(seed3)};
auto [pk1, pk2, pk3] = std::tuple{public_key(sk1), public_key(sk2), public_key(sk3)};

// Each signs a different message
g2 sig1 = sign(sk1, msg1);
g2 sig2 = sign(sk2, msg2);
g2 sig3 = sign(sk3, msg3);

// Aggregate signatures
g2 agg_sig = aggregate_signatures(std::array{sig1, sig2, sig3});

// Verify aggregate
bool valid = aggregate_verify(
    std::array{pk1, pk2, pk3},
    std::array{msg1, msg2, msg3},
    agg_sig,
    true  // check for duplicate messages
);
```

### Proof of Possession

```cpp
// Prove possession of a secret key
g2 proof = pop_prove(sk);

// Verify proof
bool valid = pop_verify(pk, proof);

// Fast aggregate verify with PoP scheme
g2 agg_sig = aggregate_signatures(std::array{sig1, sig2});
bool valid = pop_fast_aggregate_verify(
    std::array{pk1, pk2},
    message,
    agg_sig
);
```

### Hierarchical key derivation (EIP-2333)

```cpp
// Derive child keys
auto child_sk = derive_child_sk(parent_sk, /*index=*/0);
auto child_sk_unhardened = derive_child_sk_unhardened(parent_sk, /*index=*/0);

// Derive child public keys without the secret key (unhardened only)
auto child_pk = derive_child_g1_unhardened(parent_pk, /*index=*/0);
```

### Serialization

```cpp
// Compressed (48 bytes for G1, 96 bytes for G2)
auto bytes = pk.toCompressedBytesBE();
auto recovered = g1::fromCompressedBytesBE(bytes);

// Affine (96 bytes for G1, 192 bytes for G2)
auto bytes = pk.toAffineBytesLE();
auto recovered = g1::fromAffineBytesLE(bytes);

// Secret key (32 bytes)
auto sk_bytes = sk_to_bytes(sk);
auto sk_recovered = sk_from_bytes(sk_bytes);
```

### Pairing

```cpp
// Direct pairing computation
fp12 result = pairing::calculate(pairs);

// Miller's algorithm with final exponentiation
std::vector<std::tuple<g1, g2>> pairs;
pairing::add_pair(pairs, g1_point, g2_point);
fp12 result = pairing::calculate(pairs);
```

## API Reference

### Types

| Type | Description |
|---|---|
| `std::array<uint64_t, 4>` | Secret key (256-bit scalar) |
| `g1` | G1 group element (48 bytes compressed) |
| `g2` | G2 group element (96 bytes compressed) |
| `fp` | Base field element (Fq, 384-bit) |
| `fp2`, `fp6`, `fp12` | Extension field elements |

### Key management

| Function | Description |
|---|---|
| `secret_key(seed)` | Generate secret key from 32+ byte seed via HKDF |
| `public_key(sk)` | Derive G1 public key from secret key |
| `sk_to_bytes(sk)` / `sk_from_bytes(bytes)` | Serialize/deserialize secret keys |
| `derive_child_sk(sk, index)` | Hardened child key derivation (EIP-2333) |
| `derive_child_sk_unhardened(sk, index)` | Unhardened child key derivation |

### Signing and verification

| Function | Description |
|---|---|
| `sign(sk, message)` | Sign a message (returns G2 signature) |
| `verify(pubkey, message, signature)` | Verify a signature |
| `aggregate_signatures(sigs)` | Aggregate multiple G2 signatures |
| `aggregate_public_keys(pks)` | Aggregate multiple G1 public keys |
| `aggregate_verify(pks, msgs, sig, checkDuplicates)` | Verify an aggregate signature |

### Proof of Possession

| Function | Description |
|---|---|
| `pop_prove(sk)` | Generate proof of possession |
| `pop_verify(pubkey, proof)` | Verify proof of possession |
| `pop_fast_aggregate_verify(pks, msg, sig)` | Fast aggregate PoP verification |

### Low-level operations

| Function | Description |
|---|---|
| `g1::fromCompressedBytesBE(bytes)` | Deserialize compressed G1 point |
| `g2::fromCompressedBytesBE(bytes)` | Deserialize compressed G2 point |
| `pairing::calculate(pairs)` | Compute optimal Ate pairing |
| `init(cpu_features)` | Initialize library (detect CPU features) |

## Curve parameters

- **Curve:** BLS12-381 (Barreto-Lynn-Scott)
- **Field prime (q):** 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
- **Subgroup order (r):** 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
- **Embedding degree:** 12
- **Security level:** ~128 bits

## Architecture

```
bls12-381/
  include/bls12-381/
    bls12-381.hpp          Aggregate header
    signatures.hpp         BLS signature API
    g.hpp                  G1/G2 group elements
    fp.hpp                 Field element operations
    scalar.hpp             Scalar/bignum utilities
    pairing.hpp            Pairing operations
    arithmetic.hpp         Low-level arithmetic dispatch
  src/
    signatures.cpp         Signing, verification, HKDF, key derivation
    g.cpp                  G1/G2 point arithmetic, serialization
    fp.cpp                 Field element implementation (Fp, Fp2, Fp6, Fp12)
    scalar.cpp             Bignum operations
    pairing.cpp            Optimal Ate pairing
    arithmetic.cpp         C++ fallback arithmetic
    arithmetic.s           x86_64 assembly (Montgomery multiplication, field ops)
    sha256.cpp/hpp         Self-contained SHA-256
  test/
    unittests.cpp          Comprehensive test suite
  bench/
    eth_bench.cpp          Ethereum compatibility benchmarks
    chia_bench.cpp         Chia network benchmarks
```

## CI

Tested across multiple compilers and configurations:
- macOS (Apple Clang)
- GCC 10, 11, 12, 13 (Debian/Ubuntu containers)
- Clang (Arch Linux) with LTO, libc++, UBSAN, and ASAN variants

## Benchmarks

Performance comparisons against Ethereum's Go BLS12-381 and Chia Network's C++ library are available by running the benchmark executables. See `bench/` for details.

## License

[MIT](./LICENSE)

Portions of this software incorporate code adapted from projects licensed under
the Apache License 2.0. See [LICENSE](./LICENSE) for full details.

Copyright (c) 2026 Stratovera LLC and its contributors.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
