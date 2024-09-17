// Open definitions for Elgamal Commitment Scheme.
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

use curve25519_dalek::Scalar;
use std::{
    fmt::{Debug, Formatter},
    ops::{Add, Mul, Neg, Sub},
};

/// Open is the pair of the blinding factor and the message used in the commitment.
#[derive(Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Open(pub(crate) Scalar, pub(crate) Scalar);

impl Debug for Open {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Open({:?}, {:?})", self.0, self.1)
    }
}

impl Add for Open {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Open(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl Add for &Open {
    type Output = Open;

    fn add(self, rhs: Self) -> Self::Output {
        Open(&self.0 + &rhs.0, &self.1 + &rhs.1)
    }
}

impl Add<&Open> for Open {
    type Output = Open;

    fn add(self, rhs: &Open) -> Self::Output {
        Open(self.0 + &rhs.0, self.1 + &rhs.1)
    }
}

impl Add<Open> for &Open {
    type Output = Open;

    fn add(self, rhs: Open) -> Self::Output {
        Open(&self.0 + rhs.0, &self.1 + rhs.1)
    }
}

impl Sub for Open {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Open(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl Sub for &Open {
    type Output = Open;

    fn sub(self, rhs: Self) -> Self::Output {
        Open(&self.0 - &rhs.0, &self.1 - &rhs.1)
    }
}

impl Sub<&Open> for Open {
    type Output = Open;

    fn sub(self, rhs: &Open) -> Self::Output {
        Open(self.0 - &rhs.0, self.1 - &rhs.1)
    }
}

impl Sub<Open> for &Open {
    type Output = Open;

    fn sub(self, rhs: Open) -> Self::Output {
        Open(&self.0 - rhs.0, &self.1 - rhs.1)
    }
}

impl Neg for Open {
    type Output = Open;

    fn neg(self) -> Self::Output {
        Open(-self.0, -self.1)
    }
}

impl Neg for &Open {
    type Output = Open;

    fn neg(self) -> Self::Output {
        Open(-self.0, -self.1)
    }
}

impl Mul<Scalar> for Open {
    type Output = Open;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Open(self.0 * rhs, self.1 * rhs)
    }
}

impl Mul<Scalar> for &Open {
    type Output = Open;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Open(self.0 * rhs, self.1 * rhs)
    }
}

impl Mul<&Scalar> for Open {
    type Output = Open;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        Open(self.0 * rhs, self.1 * rhs)
    }
}

impl Mul<&Scalar> for &Open {
    type Output = Open;

    fn mul(self, rhs: &Scalar) -> Self::Output {
        Open(self.0 * rhs, self.1 * rhs)
    }
}
