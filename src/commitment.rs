// Implementation of Elgamal Commitment Scheme.
// Copyright 2024 Alvin Hon
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    fmt::{Debug, Formatter},
    ops::{Add, Mul, Neg, Sub},
};

use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};

use crate::{Ciphertext, DecryptionKey, EncryptionKey, Open, GENERATOR_TABLE};

/// Elgamal Commitment Scheme uses exactly the same as encrption logic where the bindling factor
/// and the message are kept secret and then later revealed to verify the commitment.
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Commitment(pub(crate) RistrettoPoint, pub(crate) Ciphertext);

pub type CommitMessage = Scalar;

impl Commitment {
    /// Get the encryption key from the commitment.
    pub fn encryption_key(&self) -> EncryptionKey {
        EncryptionKey(self.0)
    }

    /// Commit to a message using the Elgamal Commitment Scheme.
    ///
    /// `M` is commonly refered as message in the crate but here `m` is the message before multiply
    /// by G, group generator. i.e. M = mG.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::{rngs::StdRng, SeedableRng};
    /// use rust_elgamal::{Commitment, Scalar};
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let m = Scalar::from(7u32);
    /// let (open, commitment) = Commitment::commit(m, &mut rng);
    /// assert!(commitment.verify(&open));
    /// ```
    pub fn commit<R: RngCore + CryptoRng>(m: CommitMessage, rng: &mut R) -> (Open, Commitment) {
        // commitment = (rG, mG + rY), where open = (r, m)

        let decrypt_key = DecryptionKey::new(rng); // secret will not be used anymore
        let y = decrypt_key.encryption_key();
        let r = Scalar::random(rng);

        Commitment::commit_with(m, r, y)
    }

    /// Commit to a message using the Elgamal Commitment Scheme with a given encryption key.
    ///
    /// `M` is commonly refered as message in the crate but here `m` is the message before multiply
    /// by G, group generator. i.e. M = mG.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::{rngs::StdRng, SeedableRng};
    /// use rust_elgamal::{DecryptionKey, Commitment, Scalar};
    ///
    /// let mut rng = StdRng::from_entropy();
    ///
    /// let decrypt_key = DecryptionKey::new(&mut rng);
    /// let y = decrypt_key.encryption_key();
    /// let m = Scalar::from(7u32);
    /// let r = Scalar::from(8u32);
    /// let (open, commitment) = Commitment::commit_with(m, r, y);
    /// assert!(commitment.verify(&open));
    /// ```
    pub fn commit_with(m: CommitMessage, r: Scalar, y: &EncryptionKey) -> (Open, Commitment) {
        // commitment = (rG, mG + rY), where open = (r, m)

        let ciphertext = y.encrypt_with(&m * GENERATOR_TABLE, r);
        let commitment = Commitment(y.0, ciphertext);
        let open = Open(r, m);
        (open, commitment)
    }

    /// Rerandomise the commitment and open.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::{rngs::StdRng, SeedableRng};
    /// use rust_elgamal::{DecryptionKey, Commitment, Scalar};
    ///
    /// let mut rng = StdRng::from_entropy();
    ///
    /// let decrypt_key = DecryptionKey::new(&mut rng);
    /// let y = decrypt_key.encryption_key();
    /// let m = Scalar::from(7u32);
    /// let r = Scalar::from(8u32);
    /// let (open, mut commitment) = Commitment::commit_with(m, r, y);
    ///
    /// let new_open = commitment.rerandomise(open, &mut rng);
    /// assert!(commitment.verify(&new_open));
    /// ```
    #[must_use = "the Open input is not mutated, the function returns the new rerandomised Commitment and Open"]
    pub fn rerandomise<R: RngCore + CryptoRng>(&mut self, open: Open, rng: &mut R) -> Open {
        self.rerandomise_with(open, Scalar::random(rng), Scalar::random(rng))
    }

    /// Rerandomise the commitment and open with a new pair of randomness.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::{rngs::StdRng, SeedableRng};
    /// use rust_elgamal::{DecryptionKey, Commitment, Scalar};
    ///
    /// let mut rng = StdRng::from_entropy();
    ///
    /// let decrypt_key = DecryptionKey::new(&mut rng);
    /// let y = decrypt_key.encryption_key();
    /// let m = Scalar::from(7u32);
    /// let r = Scalar::from(8u32);
    /// let (open, mut commitment) = Commitment::commit_with(m, r, y);
    ///
    /// let new_r1 = Scalar::from(9u32);
    /// let new_r2 = Scalar::from(10u32);
    /// let new_open = commitment.rerandomise_with(open, new_r1, new_r2);
    /// assert!(commitment.verify(&new_open));
    /// ```
    #[must_use = "the Open input is not mutated, the function returns the new rerandomised Commitment and Open"]
    pub fn rerandomise_with(&mut self, open: Open, r1: Scalar, r2: Scalar) -> Open {
        let Commitment(y, Ciphertext(r_g, m_g_r_y)) = self;
        *r_g += &r1 * GENERATOR_TABLE;
        *m_g_r_y += *y * r1 + &r2 * GENERATOR_TABLE;
        Open(open.0 + r1, open.1 + r2)
    }

    /// Verify the commitment.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rand::{rngs::StdRng, SeedableRng};
    /// use rust_elgamal::{Commitment, Scalar};
    ///
    /// let mut rng = StdRng::from_entropy();
    /// let m = Scalar::from(8u32);
    /// let (open, commitment) = Commitment::commit(m, &mut rng);
    /// assert!(commitment.verify(&open));
    ///
    /// let m2 = Scalar::from(9u32);
    /// let (open2, commitment2) = Commitment::commit(m, &mut rng);
    /// assert!(!commitment2.verify(&open)); // wrong pair of open and commitment
    /// assert!(!commitment.verify(&open2)); // wrong pair of open and commitment
    /// ```
    pub fn verify(&self, open: &Open) -> bool {
        let Commitment(_, ct) = self;
        let Open(r, m) = open;

        let ct2 = self.encryption_key().encrypt_with(m * GENERATOR_TABLE, *r);

        ct == &ct2
    }
}

impl Debug for Commitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Commitment({:?}, {:?})", self.0.compress(), self.1)
    }
}

// Arithmetic traits for homomorphisms
// Note: the first element (encryption key) of the commitment is not going to change.

impl Add for Commitment {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Commitment(self.0, self.1 + rhs.1)
    }
}

impl Add for &Commitment {
    type Output = Commitment;

    fn add(self, rhs: Self) -> Self::Output {
        Commitment(self.0, &self.1 + &rhs.1)
    }
}

impl Add<&Commitment> for Commitment {
    type Output = Commitment;

    fn add(self, rhs: &Commitment) -> Self::Output {
        Commitment(self.0, self.1 + &rhs.1)
    }
}

impl Add<Commitment> for &Commitment {
    type Output = Commitment;

    fn add(self, rhs: Commitment) -> Self::Output {
        Commitment(self.0, &self.1 + rhs.1)
    }
}

impl Sub for Commitment {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Commitment(self.0, self.1 - rhs.1)
    }
}

impl Sub for &Commitment {
    type Output = Commitment;

    fn sub(self, rhs: Self) -> Self::Output {
        Commitment(self.0, &self.1 - &rhs.1)
    }
}

impl Sub<&Commitment> for Commitment {
    type Output = Commitment;

    fn sub(self, rhs: &Commitment) -> Self::Output {
        Commitment(self.0, self.1 - &rhs.1)
    }
}

impl Sub<Commitment> for &Commitment {
    type Output = Commitment;

    fn sub(self, rhs: Commitment) -> Self::Output {
        Commitment(self.0, &self.1 - rhs.1)
    }
}

impl Neg for Commitment {
    type Output = Commitment;

    fn neg(self) -> Self::Output {
        Commitment(self.0, -self.1)
    }
}

impl Neg for &Commitment {
    type Output = Commitment;

    fn neg(self) -> Self::Output {
        Commitment(self.0, -self.1)
    }
}

impl Mul<Scalar> for Commitment {
    type Output = Commitment;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Commitment(self.0, self.1 * rhs)
    }
}

impl Mul<Scalar> for &Commitment {
    type Output = Commitment;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Commitment(self.0, self.1 * rhs)
    }
}

impl Mul<&Scalar> for Commitment {
    type Output = Commitment;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        Commitment(self.0, self.1 * rhs)
    }
}

impl Mul<&Scalar> for &Commitment {
    type Output = Commitment;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        Commitment(self.0, self.1 * rhs)
    }
}

#[cfg(feature = "enable-serde")]
#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{Commitment, Scalar};

    // Test that serialising and deserialising a commitment.
    #[test]
    fn serde_commitment() {
        const N: usize = 100;

        let mut rng = StdRng::from_entropy();

        for _ in 0..N {
            let m = Scalar::random(&mut rng);
            let (_, commitment) = Commitment::commit(m, &mut rng);
            let encoded = bincode::serialize(&commitment).unwrap();

            assert_eq!(encoded.len(), 96); // 32 bytes for RistrettoPoint and 64 bytes for Ciphertext

            let decoded = bincode::deserialize(&encoded).unwrap();
            assert_eq!(commitment, decoded);
        }
    }
}
