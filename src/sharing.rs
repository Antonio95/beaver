
use std::fmt::{self, Display};

use rand_chacha::ChaCha20Rng;

use crate::circuit::*;
use crate::utilities;
use crate::utilities::safe_gen_mod;
use crate::utilities::subtract_without_overflow;

pub struct UnauthSharing(u32);

pub struct AuthSharing (
    UnauthSharing,
    UnauthSharing,
    UnauthSharing,
);

pub trait Sharing: Sized + Display + Send {
    // the key is only used if the implementing type corresponds to an authenticated sharing
    fn share(v: u32, k1: u32, k2: u32, rng: &mut ChaCha20Rng, q: u32) -> (Self, Self);
    fn beaver_share(k1: u32, k2: u32, q: u32, rng: &mut ChaCha20Rng) -> (BeaverSharing<Self>, BeaverSharing<Self>);
    fn add(s1: &Self, s2: &Self, q: u32) -> Self;
    // addc adds the given constant - regardless of which party calls it
    fn addc(s: &Self, c: u32, k1: u32, k2: u32, q: u32, party: Party) -> Self;
    // componentwise multiplication, not protocol for multiplication of gates
    fn mulc(s: &Self, c: u32, q: u32) -> Self;
    fn complement(&self, q: u32) -> Self;
    fn subtract(s1: &Self, s2: &Self, q: u32) -> Self {
        Self::add(s1, &s2.complement(q), q)
    }
    fn authenticate(&self, key: u32, q: u32, party: Party) -> bool;
    fn opened(&self, to: Party) -> Self;
    fn value(&self) -> u32;
    //used only to simulate corrupt parties
    fn tweaked(&self) -> Self;
}

impl Sharing for UnauthSharing {
    fn share(v: u32, _k1: u32, _k2: u32, rng: &mut ChaCha20Rng, q: u32) -> (Self, Self) {
        let r = utilities::safe_gen_mod(rng, q);
        (Self(r), Self(subtract_without_overflow(v, r, q)))
    }
    fn beaver_share(_k1: u32, _k2: u32, q: u32, rng: &mut ChaCha20Rng) -> (BeaverSharing<Self>, BeaverSharing<Self>) {
        let a = safe_gen_mod(rng, q);
        let b = safe_gen_mod(rng, q);
        let (a1, a2) = Self::share(a, 0, 0, rng, q); // key not used in unauth sharings
        let (b1, b2) = Self::share(b, 0, 0, rng, q);
        let (c1, c2) = Self::share(utilities::mul_without_overflow(a, b, q), 0, 0, rng, q);

        (BeaverSharing(a1, b1, c1), BeaverSharing(a2, b2, c2))
    }
    fn add(&Self(v1): &Self, &Self(v2): &Self, q: u32) -> Self {
        Self(utilities::add_without_overflow(v1, v2, q))
    }
    fn addc(&Self(v): &Self, c: u32, _k1: u32, _k2: u32, q: u32, party: Party) -> Self {
        match party {
            Party::P1 => Self(utilities::add_without_overflow(v, c, q)),
            Party::P2 => Self(v),
        }
    }
    fn mulc(&Self(v): &Self, c: u32, q: u32) -> Self {
        Self(utilities::mul_without_overflow(v, c, q) as u32)
    }
    fn complement(&self, q: u32) -> Self {
        Self(subtract_without_overflow(0, self.0, q))
    }
    fn authenticate(&self, _key: u32, _q: u32, _party: Party) -> bool {
        true
    }
    fn opened(&self, _to: Party) -> Self {
        UnauthSharing(self.0)
    }
    fn value(&self) -> u32 {
        self.0
    }
    fn tweaked(&self) -> Self {
        Self(self.0 + 1)
    }
}

impl fmt::Display for UnauthSharing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({})", self.0)
    }
}

impl Sharing for AuthSharing{
    fn share(v: u32, k1: u32, k2: u32, rng: &mut ChaCha20Rng, q: u32) -> (Self, Self) {
        
        let (x1, x2) = UnauthSharing::share(v, 0, 0, rng, q);
        let (x11, x12) = UnauthSharing::share(utilities::mul_without_overflow(v, k1, q), 0, 0, rng, q);
        let (x21, x22) = UnauthSharing::share(utilities::mul_without_overflow(v, k2, q), 0, 0, rng, q);

        (Self(x1, x11, x21), Self(x2, x12, x22))
    }
    fn beaver_share(k1: u32, k2: u32, q: u32, rng: &mut ChaCha20Rng) -> (BeaverSharing<Self>, BeaverSharing<Self>) {
        let a = utilities::safe_gen_mod(rng, q);
        let b = utilities::safe_gen_mod(rng, q);

        let (a1, a2) = Self::share(a, k1, k2, rng, q);
        let (b1, b2) = Self::share(b, k1, k2, rng, q);
        let (c1, c2) = Self::share(utilities::mul_without_overflow(a, b, q), k1, k2, rng, q);

        (BeaverSharing(a1, b1, c1), BeaverSharing(a2, b2, c2))
    }
    fn add(Self(s_1, x1_1, x2_1): &Self, Self(s_2, x1_2, x2_2): &Self, q: u32) -> Self {
        Self(
            UnauthSharing::add(s_1, s_2, q),
            UnauthSharing::add(x1_1, x1_2, q),
            UnauthSharing::add(x2_1, x2_2, q),
        )
    }
    fn addc(s: &Self, c: u32, k1: u32, k2: u32, q: u32, party: Party) -> Self {
        Self::add(s, &Self(
            UnauthSharing(if party == Party::P1 {c} else {0}),
            UnauthSharing(utilities::mul_without_overflow(k1, c, q)),
            UnauthSharing(utilities::mul_without_overflow(k2, c, q)),
        ), q)
    }
    fn mulc(s: &Self, c: u32, q: u32) -> Self {
        Self(
            UnauthSharing::mulc(&s.0, c, q),
            UnauthSharing::mulc(&s.1, c, q),
            UnauthSharing::mulc(&s.2, c, q),
        )
    }
    fn complement(&self, q: u32) -> Self {
        Self(self.0.complement(q), self.1.complement(q), self.2.complement(q))
    }
    fn authenticate(&self, key: u32, q: u32, party: Party) -> bool {
        match party {
            // avoid subtraction to prevent overflow of unsigned
            Party::P1 => self.1.0 % q == utilities::mul_without_overflow(self.0.0, key, q),
            Party::P2 => self.2.0 % q == utilities::mul_without_overflow(self.0.0, key, q),
        }  
    }
    fn opened(&self, to: Party) -> Self {
        let AuthSharing(UnauthSharing(x), UnauthSharing(x1), UnauthSharing(x2)) = self;
        match to {
            Party::P1 => Self(UnauthSharing(*x), UnauthSharing(*x1), UnauthSharing(0)),
            Party::P2 => Self(UnauthSharing(*x), UnauthSharing(0), UnauthSharing(*x2)),
        }
    }
    fn value(&self) -> u32 {
        self.0.0
    }
    fn tweaked(&self) -> Self {
        Self(
            self.0.tweaked(),
            UnauthSharing(self.1.0),
            UnauthSharing(self.1.0),
        )
    }
}

impl fmt::Display for AuthSharing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {}, {})", self.0.0, self.1.0, self.2.0)
    }
}

// despite its name, this type does *not* implement the Sharing trait:
// the Sharing functionality is not required for Beaver triple sharings 
pub struct BeaverSharing<T: Sharing> (pub T, pub T, pub T);

impl<T: Sharing> fmt::Display for BeaverSharing<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {}, {}]", self.0, self.1, self.2)
    }
}
