### 0.5.0 (2024-09-17)
* change the forked `curve25519-dalek` dependency back to the original repo.
* remove features `std`, `simd_backend` and `nightly`. Please check `curve25519-dalek` [README.md](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek#simd-backend) for adding SIMD support.
* enable feature `zeroize` in `curve25519-dalek` dependency.

### 0.4.0 (2021-01-29)
* replace `curve25519-dalek` dependency with a fork
* bump `curve25519-dalek` to version 4, removing the need for the `util` module (as `curve25519-dalek` now uses `rand-core` 0.6)

### 0.3.2 (2021-01-14)
* remove superfluous `zkp` dependency. I considered adding ZKP support to this crate but decided it was outside the scope.
* expose `random_point` in `util`

### 0.3.0 (2021-01-14)
* relocated `random_scalar` to a `util` module
* introduced a function `inner()` to convert a `Ciphertext` to `(RistrettoPoint, RistrettoPoint)`, and implemented a corresponding `From<(RistrettoPoint, RistrettoPoint)>` trait
* added documentation for tests

### 0.2.0 (2021-01-13)
Initial release.
