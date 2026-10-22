// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
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

//! # Public and secret keys

use std::marker;
use arrayvec::ArrayVec;
use rand::TryCryptoRng;
use serde::{Serialize, Deserialize, Serializer, Deserializer};

use super::{Secp256k1, ContextFlag};
use super::Error::{
    self, GenericError, IncapableContext, InvalidPublicKey, InvalidSecretKey, ZeroSecretKey,
};
use crate::constants;
use crate::ffi;
use libc::{c_char, c_void};
use std::ptr;
use zeroize::Zeroize;
use crate::constants::GENERATOR_PUB_J_RAW;

/// Secret 256-bit key used as `x` in an ECDSA signature
//#[derive(Zeroize)]
//#[zeroize(drop)]
// Note, Zeroize on drop implemented manually. Zeroize crate didn't implement macros for
// derive. Since derive(Zeroize) doesn;t work, we can do the same manually.
pub struct SecretKey(pub [u8; constants::SECRET_KEY_SIZE]);
impl_array_newtype!(SecretKey, u8, constants::SECRET_KEY_SIZE, no_serde_no_comp);

// If Zeroize will fix issue with the latest rust compiler, we can switch back
// to derive
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ::core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SecretKey(len={}, ****)", self.0.len())
    }
}

/// The number 0 encoded as a secret key
pub const ZERO_KEY: SecretKey = SecretKey([0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 0]);

/// The number 1 encoded as a secret key
pub const ONE_KEY: SecretKey = SecretKey([0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 1]);

/// A Secp256k1 public key, used for verification of signatures
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub(crate) ffi::PublicKey);


fn random_32_bytes<R: TryCryptoRng>(rng: &mut R) -> Result<[u8; 32], Error> {
    let mut ret = [0u8; 32];
    rng.try_fill_bytes(&mut ret)
        .map_err(|_| Error::SysRngFailure)?;
    Ok(ret)
}

impl SecretKey {
    /// Creates a new random secret key
    #[inline]
    pub fn new<R: TryCryptoRng>(secp: &Secp256k1, rng: &mut R) -> Result<SecretKey, Error> {
        let mut data = random_32_bytes(rng)?;
        let secret = loop {
            if let Ok(secret) = SecretKey::from_slice(secp, &data) {
                break secret;
            }
            data = random_32_bytes(rng)?;
        };
        Ok(secret)
    }

    /// Converts a `SECRET_KEY_SIZE`-byte slice to a secret key
    #[inline]
    pub fn from_slice(secp: &Secp256k1, data: &[u8])
                        -> Result<SecretKey, Error> {
        match data.len() {
            constants::SECRET_KEY_SIZE => {
                unsafe {
                    if ffi::secp256k1_ec_seckey_verify(secp.ctx, data.as_ptr()) != 1 {
                        let mut nonzero = 0u8;
                        for byte in data {
                            nonzero |= *byte;
                        }
                        if nonzero == 0 {
                            return Err(ZeroSecretKey);
                        }
                        return Err(InvalidSecretKey);
                    }
                }
                let mut ret = [0; constants::SECRET_KEY_SIZE];
                ret[..].copy_from_slice(data);
                Ok(SecretKey(ret))
            }
            _ => Err(InvalidSecretKey)
        }
    }

    #[inline]
    /// Adds one secret key to another, modulo the curve order
    /// Note, in case of failure, this SecretKey data can be invalid.
    pub fn add_assign(&mut self, secp: &Secp256k1, other: &SecretKey)
                     -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_ec_privkey_tweak_add(secp.ctx, self.as_mut_ptr(), other.as_ptr()) != 1 {
                Err(InvalidSecretKey)
            } else {
                Ok(())
            }
        }
    }

    #[inline]
    /// Multiplies one secret key by another, modulo the curve order
    /// Note, in case of failure, this SecretKey data can be invalid.
    pub fn mul_assign(&mut self, secp: &Secp256k1, other: &SecretKey)
                     -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_ec_privkey_tweak_mul(secp.ctx, self.as_mut_ptr(), other.as_ptr()) != 1 {
                Err(InvalidSecretKey)
            } else {
                Ok(())
            }
        }
    }

    #[inline]
    /// Inverts the secret key.
    /// Note, in case of failure, this SecretKey data can be invalid.
    pub fn inv_assign(&mut self, secp: &Secp256k1)
                     -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_ec_privkey_tweak_inv(secp.ctx, self.as_mut_ptr()) != 1 {
                Err(InvalidSecretKey)
            } else {
                Ok(())
            }
        }
    }

    #[inline]
    /// Negates the secret key
    /// Note, in case of failure, this SecretKey data can be invalid.
    pub fn neg_assign(&mut self, secp: &Secp256k1)
                     -> Result<(), Error> {
        unsafe {
            if ffi::secp256k1_ec_privkey_tweak_neg(secp.ctx, self.as_mut_ptr()) != 1 {
                Err(InvalidSecretKey)
            } else {
                Ok(())
            }
        }
    }
}

// constant-time equality implementation,
impl ::core::cmp::PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        let a = &self.0;
        let b = &other.0;

        let mut diff: u8 = 0;
        for i in 0..a.len() {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }
}

impl ::core::cmp::Eq for SecretKey {}


// Note, SecretKey deserialized as a row data. It is caller responsibility to encrypt it and never store it as it is.
// Sinse normally all the wallet data is stored into ensrypted storage - that shouldn't be a problem
impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(d: D) -> Result<SecretKey, D::Error>
    where D: Deserializer<'de>
    {
        use serde::de;
        struct Visitor {
            marker: marker::PhantomData<PublicKey>,
        }
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SecretKey;

            #[inline]
            fn visit_seq<A>(self, mut a: A) -> Result<SecretKey, A::Error>
            where A: de::SeqAccess<'de>
            {
                let mut ret: [u8; constants::SECRET_KEY_SIZE] = [0u8; constants::SECRET_KEY_SIZE];

                for i in 0..constants::SECRET_KEY_SIZE {
                    ret[i] = match a.next_element()? {
                        Some(c) => c,
                        None => return Err(::serde::de::Error::invalid_length(i, &self)),
                    };
                }

                let one_after_last: Option<u8> = a.next_element()?;
                if one_after_last.is_some() {
                    return Err(::serde::de::Error::invalid_length(constants::SECRET_KEY_SIZE + 1, &self));
                }

                let s = Secp256k1::without_caps()
                    .map_err( |e| ::serde::de::Error::custom(format!("Secp256k1 creation error, {}", e)) )?;
                let ret = SecretKey::from_slice(&s, &ret)
                    .map_err( |e| ::serde::de::Error::custom(format!("Secret key data is invalid, {}", e)) )?;

                Ok(ret)
            }

            fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "a sequence of {} bytes representing a valid secret key",
                       constants::SECRET_KEY_SIZE)
            }
        }

        // Begin actual function
        d.deserialize_seq(Visitor { marker: ::std::marker::PhantomData })
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        (&self.0[..]).serialize(s)
    }
}



unsafe extern "C" fn illegal_cb(_message: *const c_char, data: *mut c_void) {
    let hit = &mut *(data as *mut bool);
    *hit = true;
}
impl PublicKey {
    /// Creates a new zeroed public key buffer for internal FFI use.
    #[inline]
    pub(crate) fn blank() -> PublicKey {
        PublicKey(ffi::PublicKey::blank())
    }

    /// Public Key for J Generator
    pub fn pub_j_raw() -> PublicKey {
        PublicKey(ffi::PublicKey(GENERATOR_PUB_J_RAW))
    }

    /// Creates a new public key as the sum of the provided keys
    pub fn from_combination(secp: &Secp256k1, in_keys: Vec<&PublicKey>)
                         -> Result<PublicKey, Error> {
        if secp.caps == ContextFlag::SignOnly || secp.caps == ContextFlag::None {
            return Err(IncapableContext);
        }

        if in_keys.is_empty() {
            return Err(Error::InvalidParameters);
        }

        let mut in_vec:Vec<*const ffi::PublicKey> = Vec::with_capacity(in_keys.len());
        for pk in in_keys {
            if !pk.is_valid(secp) {
                return Err(Error::InvalidPublicKey);
            }
            in_vec.push(pk.as_ptr());
        }

        let mut retkey = PublicKey::blank();
        unsafe {
            if ffi::secp256k1_ec_pubkey_combine(secp.ctx, &mut retkey.0 as *mut _,
                                                  in_vec.as_ptr(), in_vec.len() as libc::size_t) == 1 {
                Ok(retkey)
            } else {
                Err(InvalidPublicKey)
            }
        }
    }

    /// Determines whether a pubkey is valid
    pub fn is_valid(&self, secp: &Secp256k1) -> bool {
        // The only invalid pubkey the API should be able to create is
        // the zero one.
        if !self.0[..].iter().any(|&x| x != 0) {
            return false;
        }

        let mut illegal = false;
        let mut ser = [0u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];
        let mut ser_len = constants::UNCOMPRESSED_PUBLIC_KEY_SIZE as libc::size_t;

        let ok = unsafe {
            // Note, there is no way to get the current set callback and restore it back
            // It is expected that callback is short lived and normallu is not set
            ffi::secp256k1_context_set_illegal_callback(
                secp.ctx,
                Some(illegal_cb),
                &mut illegal as *mut _ as *mut c_void,
            );

            let ret = ffi::secp256k1_ec_pubkey_serialize(
                secp.ctx,
                ser.as_mut_ptr(),
                &mut ser_len,
                self.as_ptr(),
                ffi::SECP256K1_SER_UNCOMPRESSED,
            );

            // It is the only user of secp library, We know that before callback was None as well.
            // Also, there is no way to get prev handler
            ffi::secp256k1_context_set_illegal_callback(secp.ctx, None, ptr::null_mut());

            ret == 1
                && !illegal
                && ser_len == constants::UNCOMPRESSED_PUBLIC_KEY_SIZE as libc::size_t
        };

        ok && PublicKey::from_slice(&secp, &ser).is_ok()
    }

    /// Get ffi::PublicKey copy
    #[inline]
    pub fn as_ffi(&self) -> ffi::PublicKey {
        self.0
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::PublicKey {
        &self.0 as *const _
    }

    /// Obtains a mutable raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::PublicKey {
        &mut self.0 as *mut _
    }

    /// Creates a new public key from a Secp256k1 public key
    #[inline]
    pub fn from_secp256k1_pubkey(secp: &Secp256k1, pk: ffi::PublicKey) -> Result<PublicKey, Error> {
        let pk = PublicKey(pk);
        if !pk.is_valid(secp) {
            Err(Error::InvalidPublicKey)
        }
        else {
            Ok(pk)
        }
    }

    /// Creates a new public key from a secret key.
    #[inline]
    pub fn from_secret_key(secp: &Secp256k1,
                           sk: &SecretKey)
                           -> Result<PublicKey, Error> {
        if secp.caps == ContextFlag::VerifyOnly || secp.caps == ContextFlag::None {
            return Err(IncapableContext);
        }
        let mut pk = ffi::PublicKey::blank();
        let res = unsafe {
            // We can assume the return value because it's not possible to construct
            // an invalid `SecretKey` without transmute trickery or something
            ffi::secp256k1_ec_pubkey_create(secp.ctx, &mut pk, sk.as_ptr())
        };
        if res==1 {
            Ok(PublicKey(pk))
        }
        else {
            Err(InvalidSecretKey)
        }
    }

    /// Creates a public key directly from a slice
    #[inline]
    pub fn from_slice(secp: &Secp256k1, data: &[u8])
                      -> Result<PublicKey, Error> {
        // Enforce canonical SEC1 encodings here so all callers consistently
        // reject hybrid 65-byte public keys (0x06/0x07), not just serde paths.
        match data.len() {
            constants::COMPRESSED_PUBLIC_KEY_SIZE => {
                if data.first() != Some(&2) && data.first() != Some(&3) {
                    return Err(InvalidPublicKey);
                }
            }
            constants::UNCOMPRESSED_PUBLIC_KEY_SIZE => {
                if data.first() != Some(&4) {
                    return Err(InvalidPublicKey);
                }
            }
            _ => return Err(InvalidPublicKey),
        }

        let mut pk = ffi::PublicKey::blank();
        unsafe {
            if ffi::secp256k1_ec_pubkey_parse(secp.ctx, &mut pk, data.as_ptr(),
                                              data.len() as ::libc::size_t) == 1 {
                Ok(PublicKey(pk))
            } else {
                Err(InvalidPublicKey)
            }
        }
    }

    #[inline]
    /// Serialize the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    pub fn serialize_vec(&self, secp: &Secp256k1, compressed: bool) ->
                                        Result<ArrayVec<u8, {constants::PUBLIC_KEY_SIZE}>, Error>
    {
        // Note, not calling is_valid because serialize is a part of validation. No reasons to
        // serialize it twice
        if !self.0[..].iter().any(|&x| x != 0) {
            return Err(InvalidPublicKey)
        }

        let mut illegal = false;
        let mut ret : ArrayVec<u8, {constants::PUBLIC_KEY_SIZE}> = ArrayVec::new();
        let mut ret_len = constants::PUBLIC_KEY_SIZE as ::libc::size_t;
        let compressed = if compressed { ffi::SECP256K1_SER_COMPRESSED } else { ffi::SECP256K1_SER_UNCOMPRESSED };

        let ok = unsafe {
            // Note, there is no way to get the current set callback and restore it back
            // It is expected that callback is short lived and normallu is not set
            ffi::secp256k1_context_set_illegal_callback(
                secp.ctx,
                Some(illegal_cb),
                &mut illegal as *mut _ as *mut c_void,
            );

            let ret = ffi::secp256k1_ec_pubkey_serialize(secp.ctx, ret.as_mut_ptr(),
                                               &mut ret_len, self.as_ptr(),
                                               compressed);

            ffi::secp256k1_context_set_illegal_callback(secp.ctx, None, ptr::null_mut());

            ret == 1 && !illegal
        };

        if ok && ret_len<=constants::PUBLIC_KEY_SIZE {
            unsafe {
                ret.set_len(ret_len);
            }
            Ok(ret)
        }
        else {
            Err(InvalidPublicKey)
        }
    }

    #[inline]
    /// Adds the pk corresponding to `other` to the pk `self` in place
    /// Note, in case of error, this PublicKey data can be corrupted
    /// Note, `other` is passed to `secp256k1_ec_pubkey_tweak_add`, whose implementation is
    /// not constant time in the tweak value. This method should only be used with public tweak
    /// values; passing a secret key or other secret-derived scalar may leak it through timing or
    /// microarchitectural side channels.
    pub fn add_exp_assign(&mut self, secp: &Secp256k1, other: &SecretKey)
                         -> Result<(), Error> {
        if secp.caps == ContextFlag::SignOnly || secp.caps == ContextFlag::None {
            return Err(IncapableContext);
        }
        if !self.is_valid(secp) {
            return Err(InvalidPublicKey)
        }

        let res = unsafe {
            ffi::secp256k1_ec_pubkey_tweak_add(secp.ctx, &mut self.0 as *mut _,
                                                  other.as_ptr())
        };

        if res == 1 {
            Ok(())
        } else {
            Err(GenericError)
        }
    }

    #[inline]
    /// Muliplies the pk `self` in place by the scalar `other`
    /// Note, in case of error, this PublicKey data can be corrupted
    /// Note, some data might leaks through the timing channel, multiplication primitive is not constant time
    pub fn mul_assign(&mut self, secp: &Secp256k1, other: &SecretKey)
                         -> Result<(), Error> {
        if secp.caps == ContextFlag::SignOnly || secp.caps == ContextFlag::None {
            return Err(IncapableContext);
        }
        if !self.is_valid(secp) {
            return Err(InvalidPublicKey)
        }

        unsafe {
            if ffi::secp256k1_ec_pubkey_tweak_mul(secp.ctx, &mut self.0 as *mut _,
                                                  other.as_ptr()) == 1 {
                Ok(())
            } else {
                Err(GenericError)
            }
        }
    }
}


impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(d: D) -> Result<PublicKey, D::Error>
        where D: Deserializer<'de>
    {
        use serde::de;
        struct Visitor {
            marker: marker::PhantomData<PublicKey>,
        }
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = PublicKey;

            #[inline]
            fn visit_seq<A>(self, mut a: A) -> Result<PublicKey, A::Error>
                where A: de::SeqAccess<'de>
            {
                debug_assert!(constants::UNCOMPRESSED_PUBLIC_KEY_SIZE >= constants::COMPRESSED_PUBLIC_KEY_SIZE);

                let s = Secp256k1::with_caps(ContextFlag::None).unwrap();
                let mut ret: [u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE] = [0u8; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE];

                let mut read_len = 0;
                while read_len < constants::UNCOMPRESSED_PUBLIC_KEY_SIZE {
                    let read_ch = match a.next_element()? {
                        Some(c) => c,
                        None => break
                    };
                    ret[read_len] = read_ch;
                    read_len += 1;
                }
                let one_after_last: Option<u8> = a.next_element()?;
                if one_after_last.is_some() {
                    return Err(de::Error::invalid_length(read_len + 1, &self));
                }

                match read_len {
                    constants::UNCOMPRESSED_PUBLIC_KEY_SIZE | constants::COMPRESSED_PUBLIC_KEY_SIZE
                    => PublicKey::from_slice(&s, &ret[..read_len]).map_err(
                        |e| match e {
                            InvalidPublicKey => de::Error::invalid_value(de::Unexpected::Seq, &self),
                            _ => de::Error::custom(&e.to_string()),
                        }
                    ),
                    _ => Err(de::Error::invalid_length(read_len, &self)),
                }
            }

            fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "a sequence of {} or {} bytes representing a valid compressed or uncompressed public key",
                       constants::COMPRESSED_PUBLIC_KEY_SIZE, constants::UNCOMPRESSED_PUBLIC_KEY_SIZE)
            }
        }

        // Begin actual function
        d.deserialize_seq(Visitor { marker: ::std::marker::PhantomData })
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let secp = Secp256k1::with_caps(ContextFlag::None).unwrap();
        (&self.serialize_vec(&secp, true)
            .map_err(|e| serde::ser::Error::custom(e.to_string()))?[..])
        .serialize(s)
    }
}

#[cfg(test)]
mod test {
    use crate::ffi;
    use std::convert::Infallible;
    use super::super::{Secp256k1, ContextFlag};
    use super::super::Error::{
        IncapableContext, InvalidPublicKey, InvalidSecretKey, ZeroSecretKey,
    };
    use super::{PublicKey, SecretKey};
    use super::super::constants;

    use rand::{TryCryptoRng, TryRng};
    use rand::rngs::SysRng;

    use std::slice::from_raw_parts;
    use rand::rand_core::utils;
    use crate::key::ONE_KEY;

    // This tests cleaning of SecretKey (e.g. secret key) on Drop.
    // To make this test fail, just remove `Zeroize` derive from `SecretKey` definition.
    #[test]
    fn skey_clear_on_drop() {
        let s = Secp256k1::new().unwrap();

        // Create buffer for blinding factor filled with non-zero bytes.
        let sk_bytes = ONE_KEY;
        let ptr = {
            // Fill blinding factor with some "sensitive" data.
            let sk = SecretKey::from_slice(&s, &sk_bytes[..]).unwrap();
            sk.0.as_ptr()

            // -- after this line SecretKey should be zeroed.
        };

        // Unsafely get data from where SecretKey was in memory. Should be all zeros.
        let sk_bytes = unsafe { from_raw_parts(ptr, constants::SECRET_KEY_SIZE) };

        // There should be all zeroes.
        let mut all_zeros = true;
        for b in sk_bytes {
            if *b != 0x00 {
                all_zeros = false;
            }
        }

        assert!(all_zeros)
    }

    #[test]
    fn skey_from_slice() {
        let s = Secp256k1::new().unwrap();
        let sk = SecretKey::from_slice(&s, &[1; 31]);
        assert!(sk == Err(InvalidSecretKey));

        let sk = SecretKey::from_slice(&s, &[1; 32]);
        assert!(sk.is_ok());
    }

    #[test]
    fn pubkey_from_slice() {
        let s = Secp256k1::new().unwrap();
        assert_eq!(PublicKey::from_slice(&s, &[]), Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&s, &[1, 2, 3]), Err(InvalidPublicKey));

        let uncompressed_bytes = [4, 54, 57, 149, 239, 162, 148, 175, 246, 254, 239, 75, 154, 152, 10, 82, 234, 224, 85, 220, 40, 100, 57, 121, 30, 162, 94, 156, 135, 67, 74, 49, 179, 57, 236, 53, 162, 124, 149, 144, 168, 77, 74, 30, 72, 211, 229, 110, 111, 55, 96, 193, 86, 227, 183, 152, 195, 155, 51, 247, 123, 113, 60, 228, 188];
        let uncompressed = PublicKey::from_slice(&s, &uncompressed_bytes);
        assert!(uncompressed.is_ok());

        let compressed = PublicKey::from_slice(&s, &[3, 23, 183, 225, 206, 31, 159, 148, 195, 42, 67, 115, 146, 41, 248, 140, 11, 3, 51, 41, 111, 180, 110, 143, 114, 134, 88, 73, 198, 174, 52, 184, 78]);
        assert!(compressed.is_ok());

        let mut hybrid = uncompressed_bytes;
        hybrid[0] = 6;
        assert_eq!(PublicKey::from_slice(&s, &hybrid), Err(InvalidPublicKey));
    }

    #[test]
    fn test_pubkey_is_valid() {
        let secp = Secp256k1::new().unwrap();
        let (_, valid_pk) = secp.generate_keypair(&mut SysRng).unwrap();
        let zero_pk = PublicKey::blank();
        let invalid_nonzero_pk = PublicKey(ffi::PublicKey([1u8; 64]));

        assert!(valid_pk.is_valid(&secp));
        assert!(!zero_pk.is_valid(&secp));
        assert!(!invalid_nonzero_pk.is_valid(&secp));
    }

    #[test]
    fn keypair_slice_round_trip() {
        let s = Secp256k1::new().unwrap();

        let (sk1, pk1) = s.generate_keypair(&mut SysRng).unwrap();
        assert!(SecretKey::from_slice(&s, &sk1[..]) == Ok(sk1));
        assert_eq!(PublicKey::from_slice(&s, &pk1.serialize_vec(&s, true).unwrap()[..]), Ok(pk1));
        assert_eq!(PublicKey::from_slice(&s, &pk1.serialize_vec(&s, false).unwrap()[..]), Ok(pk1));
    }

    #[test]
    fn invalid_secret_key() {
        let s = Secp256k1::new().unwrap();
        // Zero
        assert!(SecretKey::from_slice(&s, &[0; 32]) == Err(ZeroSecretKey));
        // -1
        assert!(SecretKey::from_slice(&s, &[0xff; 32]) == Err(InvalidSecretKey));
        // Top of range
        assert!(SecretKey::from_slice(&s,
                                      &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40]).is_ok());
        // One past top of range
        assert!(SecretKey::from_slice(&s,
                                      &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                                        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
                                        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41]).is_err());
    }

    #[test]
    fn test_pubkey_from_slice_bad_context() {
        let s = Secp256k1::without_caps().unwrap();
        let sk = SecretKey::new(&s, &mut SysRng).unwrap();
        assert_eq!(PublicKey::from_secret_key(&s, &sk), Err(IncapableContext));

        let s = Secp256k1::with_caps(ContextFlag::VerifyOnly).unwrap();
        assert_eq!(PublicKey::from_secret_key(&s, &sk), Err(IncapableContext));

        let s = Secp256k1::with_caps(ContextFlag::SignOnly).unwrap();
        assert!(PublicKey::from_secret_key(&s, &sk).is_ok());

        let s = Secp256k1::with_caps(ContextFlag::Full).unwrap();
        assert!(PublicKey::from_secret_key(&s, &sk).is_ok());
    }

    #[test]
    fn test_add_exp_bad_context() {
        let s = Secp256k1::with_caps(ContextFlag::Full).unwrap();
        let (sk, mut pk) = s.generate_keypair(&mut SysRng).unwrap();

        assert!(pk.add_exp_assign(&s, &sk).is_ok());

        let s = Secp256k1::with_caps(ContextFlag::VerifyOnly).unwrap();
        assert!(pk.add_exp_assign(&s, &sk).is_ok());

        let s = Secp256k1::with_caps(ContextFlag::SignOnly).unwrap();
        assert_eq!(pk.add_exp_assign(&s, &sk), Err(IncapableContext));

        let s = Secp256k1::with_caps(ContextFlag::None).unwrap();
        assert_eq!(pk.add_exp_assign(&s, &sk), Err(IncapableContext));
    }

    #[test]
    fn test_bad_serde_deserialize() {
        use serde::Deserialize;
        use crate::json;

        // Invalid length
        let zero31 = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        let mut json = json::de::Deserializer::from_str(zero31);
        assert!(<PublicKey as Deserialize>::deserialize(&mut json).is_err());
        let mut json = json::de::Deserializer::from_str(zero31);
        assert!(<SecretKey as Deserialize>::deserialize(&mut json).is_err());

        let zero32 = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        let mut json = json::de::Deserializer::from_str(zero32);
        assert!(<PublicKey as Deserialize>::deserialize(&mut json).is_err());
        let mut json = json::de::Deserializer::from_str(zero32);
        assert!(<SecretKey as Deserialize>::deserialize(&mut json).is_err()); // Secret key is invalid - no deserializtion

        let valid_secret = "[81,117,240,23,227,126,224,217,105,225,51,45,188,252,144,133,60,209,162,187,183,73,108,79,118,191,49,23,4,33,203,185]";
        let mut json = json::de::Deserializer::from_str(valid_secret);
        assert!(<SecretKey as Deserialize>::deserialize(&mut json).is_ok());

        let zero33 = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        let mut json = json::de::Deserializer::from_str(zero33);
        assert!(<PublicKey as Deserialize>::deserialize(&mut json).is_err());
        let mut json = json::de::Deserializer::from_str(zero33);
        assert!(<SecretKey as Deserialize>::deserialize(&mut json).is_err());

        let secp = Secp256k1::without_caps().unwrap();
        let valid_secret = SecretKey::new(&secp, &mut SysRng).unwrap();
        let vec: Vec<u8> = serde_json::to_vec(&valid_secret).unwrap();
        let restored: SecretKey = serde_json::from_slice(&vec).unwrap();
        assert_eq!( valid_secret.0, restored.0 );

        let trailing66 = "[4,149,16,196,140,38,92,239,179,65,59,224,230,183,91,238,240,46,186,252,
                        175,102,52,249,98,178,123,72,50,171,196,254,236,1,189,143,242,227,16,87,
                        247,183,162,68,237,140,92,205,151,129,166,58,111,96,123,64,180,147,51,12,
                        209,89,236,213,206,17]";
        let mut json = json::de::Deserializer::from_str(trailing66);
        assert!(<PublicKey as Deserialize>::deserialize(&mut json).is_err());

        // The first 65 bytes of trailing66 are valid
        let valid65 = "[4,149,16,196,140,38,92,239,179,65,59,224,230,183,91,238,240,46,186,252,
                        175,102,52,249,98,178,123,72,50,171,196,254,236,1,189,143,242,227,16,87,
                        247,183,162,68,237,140,92,205,151,129,166,58,111,96,123,64,180,147,51,12,
                        209,89,236,213,206]";
        let mut json = json::de::Deserializer::from_str(valid65);
        assert!(<PublicKey as Deserialize>::deserialize(&mut json).is_ok());

        let hybrid65 = "[6,149,16,196,140,38,92,239,179,65,59,224,230,183,91,238,240,46,186,252,
                        175,102,52,249,98,178,123,72,50,171,196,254,236,1,189,143,242,227,16,87,
                        247,183,162,68,237,140,92,205,151,129,166,58,111,96,123,64,180,147,51,12,
                        209,89,236,213,206]";
        let mut json = json::de::Deserializer::from_str(hybrid65);
        assert!(<PublicKey as Deserialize>::deserialize(&mut json).is_err());

        // All zeroes pk is invalid
        let zero65 = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        let mut json = json::de::Deserializer::from_str(zero65);
        assert!(<PublicKey as Deserialize>::deserialize(&mut json).is_err());
        let mut json = json::de::Deserializer::from_str(zero65);
        assert!(<SecretKey as Deserialize>::deserialize(&mut json).is_err());

        // Syntax error
        let string = "\"my key\"";
        let mut json = json::de::Deserializer::from_str(string);
        assert!(<PublicKey as Deserialize>::deserialize(&mut json).is_err());
        let mut json = json::de::Deserializer::from_str(string);
        assert!(<SecretKey as Deserialize>::deserialize(&mut json).is_err());
    }


    #[test]
    fn test_serialize_serde() {
        let s = Secp256k1::new().unwrap();
        for _ in 0..500 {
            let (sk, pk) = s.generate_keypair(&mut SysRng).unwrap();
            round_trip_serde!(sk);
            round_trip_serde!(pk);
        }
    }

    #[test]
    fn test_out_of_range() {

        struct BadRng(u8);
        impl TryRng for BadRng {
            type Error = Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Infallible> { unimplemented!() }
            fn try_next_u64(&mut self) -> Result<u64, Infallible> { unimplemented!() }
            // This will set a secret key to a little over the
            // group order, then decrement with repeated calls
            // until it returns a valid key
            fn try_fill_bytes(&mut self, data: &mut [u8]) -> Result<(), Infallible> {
                let group_order: [u8; 32] = [
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
                    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
                    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41];
                assert_eq!(data.len(), 32);
                data.copy_from_slice(&group_order[..]);
                data[31] = self.0;
                self.0 -= 1;
                Ok(())
            }
        }

        impl TryCryptoRng for BadRng {}

        let s = Secp256k1::new().unwrap();
        s.generate_keypair(&mut BadRng(0xff)).unwrap();
    }

    #[test]
    fn test_pubkey_from_bad_slice() {
        let s = Secp256k1::new().unwrap();
        // Bad sizes
        assert_eq!(PublicKey::from_slice(&s, &[0; constants::COMPRESSED_PUBLIC_KEY_SIZE - 1]),
                   Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&s, &[0; constants::COMPRESSED_PUBLIC_KEY_SIZE + 1]),
                   Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&s, &[0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE - 1]),
                   Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&s, &[0; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE + 1]),
                   Err(InvalidPublicKey));

        // Bad parse
        assert_eq!(PublicKey::from_slice(&s, &[0xff; constants::UNCOMPRESSED_PUBLIC_KEY_SIZE]),
                   Err(InvalidPublicKey));
        assert_eq!(PublicKey::from_slice(&s, &[0x55; constants::COMPRESSED_PUBLIC_KEY_SIZE]),
                   Err(InvalidPublicKey));
    }

    #[test]
    fn test_debug_output() {
        struct DumbRng(u32);
        impl TryRng for DumbRng {
            type Error = Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Infallible> {
                self.0 = self.0.wrapping_add(1);
                Ok(self.0)
            }
            fn try_next_u64(&mut self) -> Result<u64, Infallible> {
                self.0 = self.0.wrapping_add(1);
                Ok(self.0 as u64)
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
                utils::fill_bytes_via_next_word( dest, || self.try_next_u64() )
            }
        }

        impl TryCryptoRng for DumbRng {}

        let s = Secp256k1::new().unwrap();
        let (sk, _) = s.generate_keypair(&mut DumbRng(0)).unwrap();

        assert_eq!(&format!("{:?}", sk.0),
                   "[1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]");
    }

    #[test]
    fn test_pubkey_serialize() {
        struct DumbRng(u32);
        impl TryRng for DumbRng {
            type Error = Infallible;

            fn try_next_u32(&mut self) -> Result<u32, Infallible> {
                self.0 = self.0.wrapping_add(1);
                Ok(self.0)
            }
            fn try_next_u64(&mut self) -> Result<u64, Infallible> {
                self.try_next_u32().map(|v| v as u64)
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
                utils::fill_bytes_via_next_word( dest, || self.try_next_u64() )
            }
        }

        impl TryCryptoRng for DumbRng {}

        let s = Secp256k1::new().unwrap();
        let (_, pk1) = s.generate_keypair(&mut DumbRng(0)).unwrap();
        assert_eq!(&pk1.serialize_vec(&s, false).unwrap()[..],
                   &[4, 124, 121, 49, 14, 253, 63, 197, 50, 39, 194, 107, 17, 193, 219, 108, 154, 126, 9, 181, 248, 2, 12, 149, 233, 198, 71, 149, 134, 250, 184, 154, 229, 185, 28, 165, 110, 27, 3, 162, 126, 238, 167, 157, 242, 221, 76, 251, 237, 34, 231, 72, 39, 245, 3, 191, 64, 111, 170, 117, 103, 82, 28, 102, 163][..]);
        assert_eq!(&pk1.serialize_vec(&s, true).unwrap()[..],
                   &[3, 124, 121, 49, 14, 253, 63, 197, 50, 39, 194, 107, 17, 193, 219, 108, 154, 126, 9, 181, 248, 2, 12, 149, 233, 198, 71, 149, 134, 250, 184, 154, 229][..]);
    }

    #[test]
    fn test_addition() {
        let s = Secp256k1::new().unwrap();

        let (mut sk1, mut pk1) = s.generate_keypair(&mut SysRng).unwrap();
        let (mut sk2, mut pk2) = s.generate_keypair(&mut SysRng).unwrap();

        assert_eq!(PublicKey::from_secret_key(&s, &sk1).unwrap(), pk1);
        assert!(sk1.add_assign(&s, &sk2).is_ok());
        assert!(pk1.add_exp_assign(&s, &sk2).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk1).unwrap(), pk1);

        assert_eq!(PublicKey::from_secret_key(&s, &sk2).unwrap(), pk2);
        assert!(sk2.add_assign(&s, &sk1).is_ok());
        assert!(pk2.add_exp_assign(&s, &sk1).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk2).unwrap(), pk2);
    }

    #[test]
    fn test_multiplication() {
        let s = Secp256k1::new().unwrap();

        let (mut sk1, mut pk1) = s.generate_keypair(&mut SysRng).unwrap();
        let (mut sk2, mut pk2) = s.generate_keypair(&mut SysRng).unwrap();

        assert_eq!(PublicKey::from_secret_key(&s, &sk1).unwrap(), pk1);
        assert!(sk1.mul_assign(&s, &sk2).is_ok());
        assert!(pk1.mul_assign(&s, &sk2).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk1).unwrap(), pk1);

        assert_eq!(PublicKey::from_secret_key(&s, &sk2).unwrap(), pk2);
        assert!(sk2.mul_assign(&s, &sk1).is_ok());
        assert!(pk2.mul_assign(&s, &sk1).is_ok());
        assert_eq!(PublicKey::from_secret_key(&s, &sk2).unwrap(), pk2);
    }

    #[test]
    fn test_pk_combination() {
        let s = Secp256k1::new().unwrap();

        let (sk1, mut pk1) = s.generate_keypair(&mut SysRng).unwrap();
        let (sk2, mut pk2) = s.generate_keypair(&mut SysRng).unwrap();

        let combined_pk = PublicKey::from_combination(&s, vec![&pk1,&pk2]).unwrap();

        let _ = pk2.add_exp_assign(&s, &sk1);
        let _ = pk1.add_exp_assign(&s, &sk2);
        assert_eq!(combined_pk, pk2);
        assert_eq!(combined_pk, pk1);
    }

    #[test]
    fn test_inverse() {
        let s = Secp256k1::new().unwrap();

        let one = SecretKey::from_slice(&s, &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]).unwrap();

        let mut one_inv: SecretKey = one.clone();
        one_inv.inv_assign(&s).unwrap();
        assert!(one_inv == one);

        let (sk1, _) = s.generate_keypair(&mut SysRng).unwrap();
        let mut sk2: SecretKey = sk1.clone();
        sk2.inv_assign(&s).unwrap();
        sk2.inv_assign(&s).unwrap();
        assert!(sk2 == sk1);

        let (sk1, _) = s.generate_keypair(&mut SysRng).unwrap();
        let mut sk2: SecretKey = sk1.clone();
        sk2.inv_assign(&s).unwrap();
        sk2.mul_assign(&s, &sk1).unwrap();
        assert!(sk2 == one);
    }

    #[test]
    fn test_negate() {
        let s = Secp256k1::new().unwrap();

        let (sk1, _) = s.generate_keypair(&mut SysRng).unwrap();
        let mut sk2: SecretKey = sk1.clone();
        sk2.neg_assign(&s).unwrap();
        assert!(sk2.add_assign(&s, &sk1).is_err());

        let (sk1, _) = s.generate_keypair(&mut SysRng).unwrap();
        let mut sk2: SecretKey = sk1.clone();
        sk2.neg_assign(&s).unwrap();
        sk2.neg_assign(&s).unwrap();
        assert!(sk2 == sk1);

        let (mut sk1, _) = s.generate_keypair(&mut SysRng).unwrap();
        let mut sk2: SecretKey = sk1.clone();
        sk1.neg_assign(&s).unwrap();
        let sk1_clone = sk1.clone();
        sk1.add_assign(&s, &sk1_clone).unwrap();
        let sk2_clone = sk2.clone();
        sk2.add_assign(&s, &sk2_clone).unwrap();
        sk2.neg_assign(&s).unwrap();
        assert!(sk2 == sk1);

        let one = SecretKey::from_slice(&s, &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]).unwrap();

        let (mut sk1, _) = s.generate_keypair(&mut SysRng).unwrap();
        let mut sk2: SecretKey = one.clone();
        sk2.neg_assign(&s).unwrap();
        sk2.mul_assign(&s, &sk1).unwrap();
        sk1.neg_assign(&s).unwrap();
        assert!(sk2 == sk1);

        let (mut sk1, _) = s.generate_keypair(&mut SysRng).unwrap();
        let mut sk2: SecretKey = sk1.clone();
        sk1.neg_assign(&s).unwrap();
        sk1.inv_assign(&s).unwrap();
        sk2.inv_assign(&s).unwrap();
        sk2.neg_assign(&s).unwrap();
        assert!(sk2 == sk1);
    }

    #[test]
    fn pubkey_hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::collections::HashSet;

        fn hash<T: Hash>(t: &T) -> u64 {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        }

        let s = Secp256k1::new().unwrap();
        let mut set = HashSet::new();
        const COUNT : usize = 1024;
        let count = (0..COUNT).map(|_| {
            let (_, pk) = s.generate_keypair(&mut SysRng).unwrap();
            let hash = hash(&pk);
            assert!(!set.contains(&hash));
            set.insert(hash);
        }).count();
        assert_eq!(count, COUNT);
    }
}
