This crate provides a straightforward implementation of the [ElGamal cryptosystem](https://en.wikipedia.org/wiki/ElGamal_encryption) over the [ristretto255 elliptic curve group](https://ristretto.group/) using the [curve25519-dalek](https://docs.rs/curve25519_dalek/) crate. **This crate is not intended for general developers**, but rather for cryptographers implementing protocols that use ElGamal.

### Should I use ElGamal?
The main reason to use the ElGamal cryptosystem is when one needs the *homomorphic property*: given messages `m1` and `m2`, the sum of their encryptions is an encryption of `m1 + m2`. Here, addition is defined in the elliptic curve group; you may be more used to ElGamal over a finite field, in which the homomorphism is multiplicative.

In other cases, ElGamal is **generally not suitable**. This is because it is not secure against chosen-ciphertext attacks (a direct consequence of the homomorphic property).

**Warning:** while the author of this crate is educated in cryptography, they make no guarantees as to the security of the implementation. Use at your own risk.

### Acknowledgements
The author thanks [Henry de Valence](https://hdevalence.ca/) for his feedback and suggestions.

## Use
To import `rust-elgamal`, add the following dependency to your `Cargo.toml` file:
```toml
rust-elgamal = "0.2"
```
Because this crate is in a pre-release state (major version 0), minor versions may introduce breaking changes. Thus, you should not use `rust_elgamal = "0"`.

## Example
```rust
use rand::rngs::StdRng;
use rand::SeedableRng;
use rust_elgamal::{DecryptionKey, Scalar, GENERATOR_TABLE};

const N: usize = 100;

let mut rng = StdRng::from_entropy();
let dec_key = DecryptionKey::new(&mut rng);
let enc_key = dec_key.encryption_key();

let message = &Scalar::from(5u32) * GENERATOR_TABLE;
let encrypted = enc_key.encrypt(message, &mut rng);
let decrypted = dec_key.decrypt(encrypted);
assert_eq!(message, decrypted);
```

## Features
* `enable-serde`: Turn on [serde](https://docs.rs/serde/) support.