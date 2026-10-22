// Bitcoin secp256k1 bindings
// Written in 2015 by
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # ECDH
//! Support for shared secret computations
//!

use std::ops;

use super::Secp256k1;
use crate::key::{SecretKey, PublicKey};
use crate::ffi;
use crate::Error;

/// A tag used for recovering the public key from a compact signature
pub struct SharedSecret(ffi::SharedSecret);

impl SharedSecret {
    /// Creates a new shared secret from a pubkey and secret key
    /// Note, point is expected to be a valid public key. It is caller responsibility to construct it correctly
    #[inline]
    pub fn new(secp: &Secp256k1, point: &PublicKey, scalar: &SecretKey) -> Result<SharedSecret, Error> {
        if !point.is_valid(secp) {
            return Err(Error::InvalidPublicKey)
        }

        let mut ss = ffi::SharedSecret::blank();
        let res = unsafe {
            ffi::secp256k1_ecdh(secp.ctx, ss.as_mut_ptr(), point.as_ptr(), scalar.as_ptr())
        };

        if res == 1 {
            Ok(SharedSecret(ss))
        }
        else {
            Err(Error::GenericError)
        }
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::SharedSecret {
        &self.0 as *const _
    }
}

/// Creates a new shared secret from a FFI shared secret
impl From<ffi::SharedSecret> for SharedSecret {
    #[inline]
    fn from(ss: ffi::SharedSecret) -> SharedSecret {
        SharedSecret(ss)
    }
}


impl ops::Index<usize> for SharedSecret {
    type Output = u8;

    #[inline]
    fn index(&self, index: usize) -> &u8 {
        &self.0.as_bytes()[index]
    }
}

impl ops::Index<ops::Range<usize>> for SharedSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::Range<usize>) -> &[u8] {
        &self.0.as_bytes()[index]
    }
}

impl ops::Index<ops::RangeFrom<usize>> for SharedSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, index: ops::RangeFrom<usize>) -> &[u8] {
        &self.0.as_bytes()[index.start..]
    }
}

impl ops::Index<ops::RangeFull> for SharedSecret {
    type Output = [u8];

    #[inline]
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        &self.0.as_bytes()[..]
    }
}

impl ::core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SharedSecret(len={}, ****)", self.0.as_bytes().len())
    }
}

// constant-time equality implementation,
impl ::core::cmp::PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        let a = self.0.as_bytes();
        let b = other.0.as_bytes();

        let mut diff: u8 = 0;
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }
}

impl ::core::cmp::Eq for SharedSecret {}

impl Clone for SharedSecret {
    fn clone(&self) -> Self {
        SharedSecret(ffi::SharedSecret::from_bytes(*self.0.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::SysRng;
    use super::SharedSecret;
    use super::super::Secp256k1;

    #[test]
    fn ecdh() {
        let s = Secp256k1::with_caps(crate::ContextFlag::SignOnly).unwrap();
        let (sk1, pk1) = s.generate_keypair(&mut SysRng).unwrap();
        let (sk2, pk2) = s.generate_keypair(&mut SysRng).unwrap();

        let sec1 = SharedSecret::new(&s, &pk1, &sk2).unwrap();
        let sec2 = SharedSecret::new(&s, &pk2, &sk1).unwrap();
        let sec_odd = SharedSecret::new(&s, &pk1, &sk1).unwrap();
        assert!(sec1 == sec2);
        assert!(sec_odd != sec2);
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use rand::rngs::SysRng;
    use test::{Bencher, black_box};

    use super::SharedSecret;
    use super::super::Secp256k1;

    #[bench]
    pub fn bench_ecdh(bh: &mut Bencher) {
        let s = Secp256k1::with_caps(::ContextFlag::SignOnly).unwrap();
        let (sk, pk) = s.generate_keypair(&mut SysRng).unwrap();

        let s = Secp256k1::new().unwrap();
        bh.iter( || {
            let res = SharedSecret::new(&s, &pk, &sk);
            black_box(res);
        });
    }
}
