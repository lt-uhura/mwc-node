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

//! # Secp256k1
//! Rust bindings for Pieter Wuille's secp256k1 library, which is used for
//! fast and accurate manipulation of ECDSA signatures on the secp256k1
//! curve. Such signatures are used extensively by the Bitcoin network
//! and its derivatives.
//!

#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![crate_name = "secp256k1zkp"]

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(all(test, feature = "unstable"))] extern crate test;

extern crate serde_json as json;

use libc::size_t;
use std::{fmt, ops, ptr};
use std::ptr::NonNull;
use rand::rngs::SysRng;
use rand::TryCryptoRng;
use zeroize::Zeroize;

#[macro_use]
mod macros;
pub mod constants;
pub mod ecdh;
pub mod ffi;
pub mod key;
pub mod pedersen;
pub mod aggsig;

pub use key::SecretKey;
pub use key::PublicKey;

// Reexport crates, so mwc can reuse them
pub use arrayvec;
pub use rand;
pub use libc;
pub use serde;
pub use serde_json;
pub use zeroize;

/// A tag used for recovering the public key from a compact signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RecoveryId(i32);

/// An ECDSA signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct EcdsaSignature(ffi::Signature);

/// An aggsig / Schnorr signature in aggsig's 64-byte format
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AggSigSignature(ffi::Signature);

const SECP256K1_FIELD_PRIME: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
];

fn b32_is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn b32_is_less_than(bytes: &[u8], upper_bound: &[u8; 32]) -> bool {
    if bytes.len() != 32 {
        return false;
    }
    for (byte, upper) in bytes.iter().zip(upper_bound.iter()) {
        if byte < upper {
            return true;
        }
        if byte > upper {
            return false;
        }
    }
    false
}

fn aggsig_rx_bytes_are_valid(bytes: &[u8]) -> bool {
    bytes.len() == 32 && !b32_is_zero(bytes) && b32_is_less_than(bytes, &SECP256K1_FIELD_PRIME)
}

fn aggsig_rx_lifts_to_point(secp: &Secp256k1, bytes: &[u8]) -> bool {
    if !aggsig_rx_bytes_are_valid(bytes) {
        return false;
    }

    let mut compressed = [0u8; constants::COMPRESSED_PUBLIC_KEY_SIZE];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(bytes);
    PublicKey::from_slice(secp, &compressed).is_ok()
}

/// An AggSig partial signature
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AggSigPartialSignature(ffi::AggSigPartialSignature);

impl std::convert::AsRef<[u8]> for AggSigPartialSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_ref()
    }
}

/// An ECDSA signature with a recovery ID for pubkey recovery
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct RecoverableSignature(ffi::RecoverableSignature);

impl RecoveryId {
    #[inline]
    /// Allows library users to create valid recovery IDs from i32.
    pub fn from_i32(id: i32) -> Result<RecoveryId, Error> {
        match id {
            0 | 1 | 2 | 3 => Ok(RecoveryId(id)),
            _ => Err(Error::InvalidRecoveryId)
        }
    }

    #[inline]
    /// Allows library users to convert recovery IDs to i32.
    pub fn to_i32(&self) -> i32 {
        self.0
    }
}

macro_rules! impl_signature_wrapper {
    ($name:ident) => {
        impl $name {
            /// Create a new (zeroed) signature usable for the FFI interface
            pub fn new() -> $name {
                $name(ffi::Signature::new())
            }

            /// Obtains a raw pointer suitable for use with FFI functions
            #[inline]
            pub fn as_ptr(&self) -> *const ffi::Signature {
                &self.0 as *const _
            }

            /// Obtains a raw mutable pointer suitable for use with FFI functions
            #[inline]
            pub fn as_mut_ptr(&mut self) -> *mut ffi::Signature {
                &mut self.0 as *mut _
            }
        }

        impl ops::Index<usize> for $name {
            type Output = u8;

            #[inline]
            fn index(&self, index: usize) -> &u8 {
                &self.0[index]
            }
        }

        impl ops::Index<ops::Range<usize>> for $name {
            type Output = [u8];

            #[inline]
            fn index(&self, index: ops::Range<usize>) -> &[u8] {
                &self.0[index]
            }
        }

        impl ops::Index<ops::RangeFrom<usize>> for $name {
            type Output = [u8];

            #[inline]
            fn index(&self, index: ops::RangeFrom<usize>) -> &[u8] {
                &self.0[index.start..]
            }
        }

        impl ops::Index<ops::RangeFull> for $name {
            type Output = [u8];

            #[inline]
            fn index(&self, _: ops::RangeFull) -> &[u8] {
                &self.0[..]
            }
        }
    };
}

// Note: EcdsaSignature storing data in internal format, not in not a canonical DER or 64-byte compact encoding
//     Use raw data access for logs and debug.
impl_signature_wrapper!(EcdsaSignature);
impl_signature_wrapper!(AggSigSignature);

// Note: This API exposing signature internals. We understand that it is not a good way to expose signature,
//    but there is a legacy code that already using that, we can't switch to compact style for signature data.
impl std::convert::AsRef<[u8]> for AggSigSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0.as_ref()
    }
}

impl EcdsaSignature {
    /// Checks whether the signature is non-zero and compact-serializes to scalars in range.
    /// This validates encoding shape only; it does not verify the signature against a message.
    pub fn is_valid(&self, secp: &Secp256k1) -> bool {
        match self.serialize_compact(secp) {
            Ok(compact) => {
                SecretKey::from_slice(secp, &compact[..32]).is_ok() &&
                SecretKey::from_slice(secp, &compact[32..]).is_ok()
            }
            Err(_) => false,
        }
    }

    #[inline]
    /// Converts a DER-encoded byte slice to a signature
    /// Note: Error InvalidSignature might be related to some invariant failures
    pub fn from_der(secp: &Secp256k1, data: &[u8]) -> Result<EcdsaSignature, Error> {
        let mut ret = EcdsaSignature::new();

        unsafe {
            if ffi::secp256k1_ecdsa_signature_parse_der(secp.ctx, ret.as_mut_ptr(),
                                                        data.as_ptr(), data.len() as libc::size_t) == 1
                && ret.is_valid(secp)
            {
                Ok(ret)
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Converts a 64-byte compact-encoded byte slice to a signature.
    /// Note: Error InvalidSignature might be related to some invariant failures
    pub fn from_compact(secp: &Secp256k1, data: &[u8]) -> Result<EcdsaSignature, Error> {
        let mut ret = EcdsaSignature::new();
        if data.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let ok = unsafe {
            ffi::secp256k1_ecdsa_signature_parse_compact(secp.ctx, ret.as_mut_ptr(),
                                                            data.as_ptr())
        };

        if ok==1 {
            if ret.is_valid(secp) {
                return Ok(ret);
            }
        }
        Err(Error::InvalidSignature)
    }

    /// Converts a "lax DER"-encoded byte slice to a signature. This is basically
    /// only useful for validating signatures in the Bitcoin blockchain from before
    /// 2016. It should never be used in new applications. This library does not
    /// support serializing to this "format"
    /// Note: This method return "DER shape was tolerated” with “signature parsed successfully."
    ///     Malformed signature canbe created because of that parsing.
    /// Note:  mwc-node & mwc-wallet should never use this API.
    pub fn from_der_lax(secp: &Secp256k1, data: &[u8]) -> Result<EcdsaSignature, Error> {
        unsafe {
            let mut ret = EcdsaSignature::new();
            if ffi::ecdsa_signature_parse_der_lax(secp.ctx, ret.as_mut_ptr(),
                                                  data.as_ptr(), data.len() as libc::size_t) == 1 {
                Ok(ret)
            } else {
                Err(Error::InvalidSignature)
            }
        }
    }

    /// Normalizes a signature to a "low S" form. In ECDSA, signatures are
    /// of the form (r, s) where r and s are numbers lying in some finite
    /// field. The verification equation will pass for (r, s) iff it passes
    /// for (r, -s), so it is possible to ``modify'' signatures in transit
    /// by flipping the sign of s. This does not constitute a forgery since
    /// the signed message still cannot be changed, but for some applications,
    /// changing even the signature itself can be a problem. Such applications
    /// require a "strong signature". It is believed that ECDSA is a strong
    /// signature except for this ambiguity in the sign of s, so to accomodate
    /// these applications libsecp256k1 will only accept signatures for which
    /// s is in the lower half of the field range. This eliminates the
    /// ambiguity.
    ///
    /// However, for some systems, signatures with high s-values are considered
    /// valid. (For example, parsing the historic Bitcoin blockchain requires
    /// this.) For these applications we provide this normalization function,
    /// which ensures that the s value lies in the lower half of its range.
    pub fn normalize_s(&mut self, secp: &Secp256k1) -> Result<(), Error> {
        let ok = unsafe {
            // Ignore return value, which indicates whether the sig
            // was already normalized. We don't care.
            ffi::secp256k1_ecdsa_signature_normalize(secp.ctx, self.as_mut_ptr(),
                                                     self.as_ptr())
        };
        if ok == 0 {
            Err(Error::InvalidSignature)
        }
        else {
            Ok(())
        }
    }

    #[inline]
    /// Serializes the signature in DER format
    pub fn serialize_der(&self, secp: &Secp256k1) -> Result<Vec<u8>, Error> {
        const RES_CAPACITY : usize = 72;
        let mut ret = vec![0; RES_CAPACITY];
        let mut len: size_t = ret.len() as size_t;
        let ok = unsafe {
            ffi::secp256k1_ecdsa_signature_serialize_der(secp.ctx, ret.as_mut_ptr(),
                                                                   &mut len, self.as_ptr())
        };
        if ok==1 && len<=RES_CAPACITY {
            ret.truncate(len as usize);
            Ok(ret)
        }
        else {
            Err(Error::SerializationError)
        }

    }

    #[inline]
    /// Serializes the signature in compact format
    pub fn serialize_compact(&self, secp: &Secp256k1) -> Result<[u8; 64], Error> {
        let mut ret = [0; 64];
        let ok = unsafe {
            ffi::secp256k1_ecdsa_signature_serialize_compact(secp.ctx, ret.as_mut_ptr(),
                                                                       self.as_ptr())
        };
        if ok==1 {
            Ok(ret)
        }
        else {
            Err(Error::SerializationError)
        }
    }

}

impl AggSigSignature {
    /// Blank invalid signature
    pub fn blank() -> AggSigSignature {
        AggSigSignature(ffi::Signature([0u8; constants::AGG_SIGNATURE_SIZE]))
    }

    /// Checks whether the aggsig signature is well-formed as a 64-byte `(R.x || s)` encoding.
    ///
    /// This validates encoding shape only; it does not verify the signature against a message.
    /// Note: It rejects `s == 0` signature which can be false positive. We are accepting that
    ///    because we want to reject the blank signatures
    pub fn is_valid(&self, secp: &Secp256k1) -> bool {
        aggsig_rx_lifts_to_point(secp, &self[0..32]) &&
        SecretKey::from_slice(secp, &self[32..]).is_ok()
    }

    /// Converts a 64-byte compact-encoded byte slice to a signature.
    /// Note: compact format is slightly different from raw format, the 32 byte parts are swapped.
    /// Note: Error InvalidSignature might be related to some invariant failures
    pub fn from_compact(secp: &Secp256k1, data: &[u8]) -> Result<AggSigSignature, Error> {
        let mut ret = AggSigSignature::new();
        if data.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let ok = unsafe {
            ffi::secp256k1_ecdsa_signature_parse_compact(secp.ctx, ret.as_mut_ptr(),
                                                         data.as_ptr())
        };

        if ok==1 {
            if ret.is_valid(secp) {
                return Ok(ret);
            }
        }
        Err(Error::InvalidSignature)
    }

    /// Serializes the aggsig signature through the legacy ECDSA compact serializer.
    ///
    /// This is not the raw aggsig `(R.x || s)` wire encoding. Use `to_raw_data` when the caller
    /// needs to preserve aggsig bytes exactly, such as JSON or network interchange.
    pub fn serialize_compact(
        &self,
        secp: &Secp256k1,
    ) -> Result<[u8; constants::AGG_SIGNATURE_SIZE], Error> {
        let mut ret = [0; 64];
        let ok = unsafe {
            ffi::secp256k1_ecdsa_signature_serialize_compact(secp.ctx, ret.as_mut_ptr(),
                                                             self.as_ptr())
        };
        if ok==1 {
            Ok(ret)
        }
        else {
            Err(Error::SerializationError)
        }
    }

    /// Returns the raw aggsig `(R.x || s)` bytes after validating the signature shape.
    ///
    /// Aggsig signatures are stored internally in the same raw wire format used by aggsig
    /// serialization. This method exists so aggsig callers do not need to go through the ECDSA
    /// compact serializer, which can transform the bytes and is the wrong encoding for Schnorr
    /// aggsig interchange.
    pub fn to_raw_data(
        &self,
        secp: &Secp256k1,
    ) -> Result<[u8; constants::AGG_SIGNATURE_SIZE], Error> {
        if !self.is_valid(secp) {
            return Err(Error::InvalidSignature);
        }
        Ok(self.0.0)
    }

    /// Serializes the raw aggsig `(R.x || s)` wire bytes without ECDSA conversion.
    ///
    /// This is an alias for `to_raw_data` with a serialization-oriented name for call sites that
    /// are writing aggsig signatures to external formats.
    pub fn serialize_raw(
        &self,
        secp: &Secp256k1,
    ) -> Result<[u8; constants::AGG_SIGNATURE_SIZE], Error> {
        self.to_raw_data(secp)
    }

    /// Stores raw bytes provided as a signature, with no conversion
    pub fn from_raw_data(secp: &Secp256k1, data: &[u8;constants::AGG_SIGNATURE_SIZE]) -> Result<AggSigSignature, Error> {
        let sign = AggSigSignature(ffi::Signature(data.clone()));
        if sign.is_valid(secp) {
            Ok(sign)
        }
        else {
            Err(Error::InvalidSignature)
        }
    }

}

impl serde::Serialize for EcdsaSignature {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where S: serde::Serializer
    {
        let secp = Secp256k1::with_caps(ContextFlag::None)
            .map_err(|e| serde::ser::Error::custom(format!("Failed to create secp context, {}", e)))?;
        (&self.serialize_compact(&secp)
            .map_err(|e| serde::ser::Error::custom(format!("Signature serialization error, {}", e)))?
            [..]
        ).serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for EcdsaSignature {
    fn deserialize<D>(d: D) -> Result<EcdsaSignature, D::Error>
        where D: serde::Deserializer<'de>
    {
        use serde::de;
        struct Visitor {
            marker: std::marker::PhantomData<EcdsaSignature>,
        }
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = EcdsaSignature;

            #[inline]
            fn visit_seq<A>(self, mut a: A) -> Result<EcdsaSignature, A::Error>
                where A: de::SeqAccess<'de>
            {
                let s = Secp256k1::with_caps(ContextFlag::None)
                    .map_err(|e| serde::de::Error::custom(format!("Failed to create secp context, {}", e)))?;

                let mut ret: [u8; constants::COMPACT_SIGNATURE_SIZE] = [0u8; constants::COMPACT_SIGNATURE_SIZE];

                for i in 0..constants::COMPACT_SIGNATURE_SIZE {
                    ret[i] = match a.next_element()? {
                        Some(c) => c,
                        None => return Err(::serde::de::Error::invalid_length(i, &self))
                    };
                }
                let one_after_last: Option<u8> = a.next_element()?;
                if one_after_last.is_some() {
                    return Err(serde::de::Error::invalid_length(constants::COMPACT_SIGNATURE_SIZE + 1, &self));
                }

                EcdsaSignature::from_compact(&s, &ret).map_err(
                    |e| match e {
                        Error::InvalidSignature => de::Error::invalid_value(de::Unexpected::Seq, &self),
                        _ => de::Error::custom(&e.to_string()),
                    }
                )
            }

            fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(f, "a sequence of {} bytes representing a syntactically well-formed compact signature",
                       constants::COMPACT_SIGNATURE_SIZE)
            }
        }

        // Begin actual function
        d.deserialize_seq(Visitor { marker: std::marker::PhantomData })
    }
}

impl AggSigPartialSignature {
    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::AggSigPartialSignature {
        &self.0 as *const _
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::AggSigPartialSignature {
        &mut self.0 as *mut _
    }

    /// Copy of ffi representaiton of the signature
    #[inline]
    pub fn as_ffi(&self) -> ffi::AggSigPartialSignature {
        self.0
    }

}

/// Creates a new signature from a FFI signature
impl From<ffi::AggSigPartialSignature> for AggSigPartialSignature {
    #[inline]
    fn from(sig: ffi::AggSigPartialSignature) -> AggSigPartialSignature {
        AggSigPartialSignature(sig)
    }
}


impl RecoverableSignature {
    /// Create a new zero filled instance of signature
    pub fn new() -> RecoverableSignature
    {
        RecoverableSignature(crate::ffi::RecoverableSignature::new())
    }

    #[inline]
    /// Converts a compact-encoded byte slice to a signature. This
    /// representation is nonstandard and defined by the libsecp256k1
    /// library.
    pub fn from_compact(secp: &Secp256k1, data: &[u8], recid: RecoveryId) -> Result<RecoverableSignature, Error> {
        let mut ret = RecoverableSignature::new();

        if data.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let ok = unsafe {
            ffi::secp256k1_ecdsa_recoverable_signature_parse_compact(secp.ctx, ret.as_mut_ptr(),
                                                                     data.as_ptr(), recid.0)
        };

        if ok == 1 {
            Ok(ret)
        } else
        {
            Err(Error::InvalidSignature)
        }
    }

    /// Obtains a raw pointer suitable for use with FFI functions
    #[inline]
    pub fn as_ptr(&self) -> *const ffi::RecoverableSignature {
        &self.0 as *const _
    }

    /// Obtains a raw mutable pointer suitable for use with FFI functions
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::RecoverableSignature {
        &mut self.0 as *mut _
    }

    #[inline]
    /// Serializes the recoverable signature in compact format
    pub fn serialize_compact(&self, secp: &Secp256k1) -> Result<(RecoveryId, [u8; 64]), Error> {
        let mut ret = [0u8; 64];
        let mut recid = 0i32;
        let err = unsafe {
            ffi::secp256k1_ecdsa_recoverable_signature_serialize_compact(
                secp.ctx, ret.as_mut_ptr(), &mut recid, self.as_ptr())
        };

        if err==1 {
            Ok((RecoveryId(recid), ret))
        }
        else {
            Err(Error::InvalidSignature)
        }
    }

    /// Converts a recoverable signature to a non-recoverable one (this is needed
    /// for verification
    /// Note: Error InvalidSignature might be related to some invariant failures
    #[inline]
    pub fn to_standard(&self, secp: &Secp256k1) -> Result<EcdsaSignature, Error> {
        let mut ret = EcdsaSignature::new();
        let ok = unsafe {
            ffi::secp256k1_ecdsa_recoverable_signature_convert(secp.ctx, ret.as_mut_ptr(), self.as_ptr())
        };
        if ok==1 && ret.is_valid(secp) {
            Ok(ret)
        }
        else {
            Err(Error::InvalidSignature)
        }
    }
}

/// A (hashed) message input to an ECDSA signature
pub struct Message([u8; constants::MESSAGE_SIZE]);
impl Copy for Message {}
impl_array_newtype!(Message, u8, constants::MESSAGE_SIZE);
// Note, message doesn't contain sensitive data, so it can be dumped with Debug output
impl_pretty_debug!(Message);

impl Message {
    /// Converts a `MESSAGE_SIZE`-byte slice to a message object
    #[inline]
    pub fn from_slice(data: &[u8]) -> Result<Message, Error> {
        match data.len() {
            constants::MESSAGE_SIZE => {
                let mut ret = [0; constants::MESSAGE_SIZE];
                ret[..].copy_from_slice(data);
                Ok(Message(ret))
            }
            _ => Err(Error::InvalidMessage)
        }
    }
}

/// Creates a message from a `MESSAGE_SIZE` byte array
impl From<[u8; constants::MESSAGE_SIZE]> for Message {
    fn from(buf: [u8; constants::MESSAGE_SIZE]) -> Message {
        Message(buf)
    }
}

/// An ECDSA error
#[derive(Copy, PartialEq, Eq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Error {
    /// A `Secp256k1` was used for an operation, but it was not created to
    /// support this (so necessary precomputations have not been done)
    IncapableContext,
    /// Signature failed verification
    IncorrectSignature,
    /// Badly sized message ("messages" are actually fixed-sized digests; see the `MESSAGE_SIZE`
    /// constant)
    InvalidMessage,
    /// Bad public key
    InvalidPublicKey,
    /// Bad commit
    InvalidCommit,
    /// Bad signature
    InvalidSignature,
    /// Bad secret key
    InvalidSecretKey,
    /// Secret key is zero
    ZeroSecretKey,
    /// Bad recovery id
    InvalidRecoveryId,
    /// Summing commitments led to incorrect result
    IncorrectCommitSum,
    /// Range proof is invalid
    InvalidRangeProof,
    /// Error creating partial signature
    PartialSigFailure,
    /// Failure subtracting two signatures
    SigSubtractionFailure,
    /// System random generator error
    SysRngFailure,
    /// Generic Secp Error, should be almost impossible to hit
    GenericError,
    /// Range proof generation failure. Very small chance
    RangeProofGeneration,
    /// Nonce export failure
    NonceExportError,
    /// Invalid parameters
    InvalidParameters,
    /// Serialization error
    SerializationError,
    /// Instance allcotion error
    AllocationError,
    /// AggSigContext is broken
    BrokenAggSigContext,
}

impl Error {
    fn as_str(&self) -> &str {
        match *self {
            Error::IncapableContext => "secp: context does not have sufficient capabilities",
            Error::IncorrectSignature => "secp: signature failed verification",
            Error::InvalidMessage => "secp: message was not 32 bytes (do you need to hash?)",
            Error::InvalidPublicKey => "secp: malformed public key",
            Error::InvalidCommit => "secp: malformed commit",
            Error::InvalidSignature => "secp: malformed signature",
            Error::InvalidSecretKey => "secp: malformed or out-of-range secret key",
            Error::ZeroSecretKey => "secp: zero secret key",
            Error::InvalidRecoveryId => "secp: bad recovery id",
            Error::IncorrectCommitSum => "secp: invalid pedersen commitment sum",
            Error::InvalidRangeProof => "secp: invalid range proof",
            Error::PartialSigFailure => "secp: partial sig (aggsig) failure",
            Error::SigSubtractionFailure => "secp: subtraction (aggsig) did not result in any valid signatures",
            Error::SysRngFailure => "secp: system generator failure",
            Error::GenericError => "secp: generic error",
            Error::RangeProofGeneration => "secp: unable to generate a range proof",
            Error::NonceExportError => "secp: nonce export failure",
            Error::InvalidParameters => "secp: invalid parameters",
            Error::SerializationError => "secp: serialization error",
            Error::AllocationError => "secp: instance allocation error",
            Error::BrokenAggSigContext => "secp: AggSigContext is broken",
        }
    }
}

// Passthrough Debug to Display, since errors should be user-visible
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The secp256k1 engine, used to execute all signature operations
pub struct Secp256k1 {
    ctx: *mut ffi::Context,
    caps: ContextFlag,
    bulletproof_gen: Option<NonNull<ffi::BulletproofGenerators>>,
}

// Note!!! Secp256k1 context is not safe to share between threads!
// secp library thread safety tight to Secp256k1 context thread safety.
//unsafe impl Send for Secp256k1 {}
//unsafe impl Sync for Secp256k1 {}
// Note: Clone for Secp256k1 is not enabled because we don't want share the conexts, as well as pass them between threads

/// Flags used to determine the capabilities of a `Secp256k1` object;
/// the more capabilities, the more expensive it is to create.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum ContextFlag {
    /// Can neither sign nor verify signatures (cheapest to create, useful
    /// for cases not involving signatures, such as creating keys from slices)
    None,
    /// Can sign but not verify signatures
    SignOnly,
    /// Can verify but not create signatures
    VerifyOnly,
    /// Can verify and create signatures
    Full,
    /// Can do all of the above plus pedersen commitments
    Commit,
}

// Passthrough Debug to Display, since caps should be user-visible
impl fmt::Display for ContextFlag {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        fmt::Debug::fmt(self, f)
    }
}

impl fmt::Debug for Secp256k1 {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Secp256k1 {{ [private], caps: {:?} }}", self.caps)
    }
}

impl Drop for Secp256k1 {
    fn drop(&mut self) {
        if let Some(gen) = self.bulletproof_gen {
            unsafe {
                ffi::secp256k1_bulletproof_generators_destroy(self.ctx,
                              gen.as_ptr());
            }
        }
        unsafe { ffi::secp256k1_context_destroy(self.ctx); }
    }
}

impl Secp256k1 {
    /// Whether this context supports range-proof verification.
    pub fn can_verify_range_proofs(&self) -> bool {
        self.caps != ContextFlag::None && self.caps != ContextFlag::SignOnly
    }

    /// Creates a new Secp256k1 context
    #[inline]
    pub fn new() -> Result<Secp256k1, Error> {
        Secp256k1::with_caps(ContextFlag::Full)
    }

    /// Creates a new Secp256k1 context with the specified capabilities
    /// Note: randomize is not called because we don't need it for every case. Caller suppose to
    ///   call randomize() for attack critical workflows
    pub fn with_caps(caps: ContextFlag) -> Result<Secp256k1, Error> {
        let flag = match caps {
            ContextFlag::None => ffi::SECP256K1_START_NONE,
            ContextFlag::SignOnly => ffi::SECP256K1_START_SIGN,
            ContextFlag::VerifyOnly => ffi::SECP256K1_START_VERIFY,
            ContextFlag::Full | ContextFlag::Commit => {
                ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY
            }
        };

        let ctx = unsafe { ffi::secp256k1_context_create(flag) };
        if ctx.is_null() {
            return Err(Error::GenericError);
        }

        let mut res = Secp256k1 {
            ctx,
            caps,
            bulletproof_gen: None,
        };

        match caps {
            ContextFlag::SignOnly | ContextFlag::Full | ContextFlag::Commit => res.randomize_priv(&mut SysRng)?,
            _ => {},
        }

        Ok(res)
    }

    /// Creates a new Secp256k1 context with no capabilities (just de/serialization)
    pub fn without_caps() -> Result<Secp256k1, Error> {
        Secp256k1::with_caps(ContextFlag::None)
    }

    /// (Re)randomizes the Secp256k1 context for cheap sidechannel resistence;
    /// see comment in libsecp256k1 commit d2275795f by Gregory Maxwell
    fn randomize_priv<R: TryCryptoRng>(&mut self, rng: &mut R) -> Result<(), Error> {
        let mut seed = [0u8; 32];
        rng.try_fill_bytes(&mut seed)
            .map_err(|_| Error::SysRngFailure)?;

        let res = unsafe {
            ffi::secp256k1_context_randomize(self.ctx, seed.as_ptr())
        };
        seed.zeroize();

        if res != 1 {
            return Err(Error::GenericError);
        }

        Ok(())
    }

    /// Generates a random keypair. Convenience function for `key::SecretKey::new`
    /// and `key::PublicKey::from_secret_key`; call those functions directly for
    /// batch key generation. Requires a signing-capable context.
    #[inline]
    pub fn generate_keypair<R: TryCryptoRng>(&self, rng: &mut R)
                                   -> Result<(key::SecretKey, key::PublicKey), Error> {
        let sk = key::SecretKey::new(self, rng)?;
        let pk = key::PublicKey::from_secret_key(self, &sk)?;
        Ok((sk, pk))
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn sign(&self, msg: &Message, sk: &key::SecretKey)
                -> Result<EcdsaSignature, Error> {
        if self.caps == ContextFlag::VerifyOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let mut ret = EcdsaSignature::new();
        let res = unsafe {
            ffi::secp256k1_ecdsa_sign(self.ctx, ret.as_mut_ptr(), msg.as_ptr(),
                                                 sk.as_ptr(), ffi::secp256k1_nonce_function_rfc6979,
                                                 ptr::null())
        };
        if res == 1 {
            Ok(ret)
        }
        else {
            Err(Error::InvalidSecretKey)
        }
    }

    /// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
    pub fn sign_recoverable(&self, msg: &Message, sk: &key::SecretKey)
                -> Result<RecoverableSignature, Error> {
        if self.caps == ContextFlag::VerifyOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let mut ret = RecoverableSignature::new();
        let ok = unsafe {
            ffi::secp256k1_ecdsa_sign_recoverable(self.ctx, ret.as_mut_ptr(), msg.as_ptr(),
                                                             sk.as_ptr(), ffi::secp256k1_nonce_function_rfc6979,
                                                             ptr::null())
        };
        if ok == 1 {
            Ok(RecoverableSignature::from(ret))
        }
        else {
            Err(Error::InvalidSecretKey)
        }
    }

    /// Determines the public key for which `sig` is a valid signature for
    /// `msg`. Requires a verify-capable context.
    pub fn recover(&self, msg: &Message, sig: &RecoverableSignature)
                  -> Result<key::PublicKey, Error> {
        if self.caps == ContextFlag::SignOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }

        let mut pk = ffi::PublicKey::blank();

        unsafe {
            if ffi::secp256k1_ecdsa_recover(self.ctx, &mut pk,
                                            sig.as_ptr(), msg.as_ptr()) != 1 {
                return Err(Error::InvalidSignature);
            }
        };
        key::PublicKey::from_secp256k1_pubkey(self, pk)
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using the public
    /// key `pubkey`. Returns `Ok(true)` on success. Note that this function cannot
    /// be used for Bitcoin consensus checking since there may exist signatures
    /// which OpenSSL would verify but not libsecp256k1, or vice-versa. Requires a
    /// verify-capable context.
    #[inline]
    pub fn verify(&self, msg: &Message, sig: &EcdsaSignature, pk: &key::PublicKey) -> Result<(), Error> {
        if self.caps == ContextFlag::SignOnly || self.caps == ContextFlag::None {
            return Err(Error::IncapableContext);
        }
        if !sig.is_valid(self) {
            return Err(Error::InvalidSignature);
        }

        if !pk.is_valid(&self) {
            return Err(Error::InvalidPublicKey);
        };

        let ok = unsafe { ffi::secp256k1_ecdsa_verify(self.ctx, sig.as_ptr(), msg.as_ptr(),
                                                       pk.as_ptr())
        };

        if ok == 1 {
            Ok(())
        } else {
            Err(Error::IncorrectSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::TryRng;
    use rand::rngs::SysRng;
    use crate::key::{SecretKey, PublicKey};
    use super::constants;
    use super::{Secp256k1, EcdsaSignature, RecoverableSignature, Message, RecoveryId, ContextFlag};
    use super::Error::{InvalidMessage, InvalidPublicKey, IncorrectSignature, InvalidSignature,
                       IncapableContext};

    macro_rules! hex {
        ($hex:expr) => {{
            let bytes = $hex.as_bytes();
            let mut vec = Vec::new();
            for i in (0..bytes.len()).step_by(2) {
                let high = (bytes[i] as char).to_digit(16).unwrap();
                let low = (bytes[i + 1] as char).to_digit(16).unwrap();
                vec.push(((high << 4) + low) as u8);
            }
            vec
        }};
    }

    #[test]
    fn capabilities() {
        let none = Secp256k1::with_caps(ContextFlag::None).unwrap();
        let sign = Secp256k1::with_caps(ContextFlag::SignOnly).unwrap();
        let vrfy = Secp256k1::with_caps(ContextFlag::VerifyOnly).unwrap();
        let full = Secp256k1::with_caps(ContextFlag::Full).unwrap();

        let mut msg = [0u8; 32];
        SysRng.try_fill_bytes(&mut msg).unwrap();
        let msg = Message::from_slice(&msg).unwrap();

        // Try key generation
        assert_eq!(none.generate_keypair(&mut SysRng), Err(IncapableContext));
        assert_eq!(vrfy.generate_keypair(&mut SysRng), Err(IncapableContext));
        assert!(sign.generate_keypair(&mut SysRng).is_ok());
        assert!(full.generate_keypair(&mut SysRng).is_ok());
        let (sk, pk) = full.generate_keypair(&mut SysRng).unwrap();

        // Try signing
        assert_eq!(none.sign(&msg, &sk), Err(IncapableContext));
        assert_eq!(vrfy.sign(&msg, &sk), Err(IncapableContext));
        assert!(sign.sign(&msg, &sk).is_ok());
        assert!(full.sign(&msg, &sk).is_ok());
        assert_eq!(none.sign_recoverable(&msg, &sk), Err(IncapableContext));
        assert_eq!(vrfy.sign_recoverable(&msg, &sk), Err(IncapableContext));
        assert!(sign.sign_recoverable(&msg, &sk).is_ok());
        assert!(full.sign_recoverable(&msg, &sk).is_ok());
        assert_eq!(sign.sign(&msg, &sk), full.sign(&msg, &sk));
        assert_eq!(sign.sign_recoverable(&msg, &sk), full.sign_recoverable(&msg, &sk));
        let sig = full.sign(&msg, &sk).unwrap();
        let sigr = full.sign_recoverable(&msg, &sk).unwrap();

        // Try verifying
        assert_eq!(none.verify(&msg, &sig, &pk), Err(IncapableContext));
        assert_eq!(sign.verify(&msg, &sig, &pk), Err(IncapableContext));
        assert!(vrfy.verify(&msg, &sig, &pk).is_ok());
        assert!(full.verify(&msg, &sig, &pk).is_ok());

        // Try pk recovery
        assert_eq!(none.recover(&msg, &sigr), Err(IncapableContext));
        assert_eq!(sign.recover(&msg, &sigr), Err(IncapableContext));
        assert!(vrfy.recover(&msg, &sigr).is_ok());
        assert!(full.recover(&msg, &sigr).is_ok());

        assert_eq!(vrfy.recover(&msg, &sigr),
                   full.recover(&msg, &sigr));
        assert_eq!(full.recover(&msg, &sigr), Ok(pk));

        // Check that we can produce keys from slices with no precomputation
        let (pk_slice, sk_slice) = (&pk.serialize_vec(&none, true).unwrap(), &sk[..]);
        let new_pk = PublicKey::from_slice(&none, pk_slice).unwrap();
        let new_sk = SecretKey::from_slice(&none, sk_slice).unwrap();
        assert_eq!(sk, new_sk);
        assert_eq!(pk, new_pk);
    }

    #[test]
    fn recid_sanity_check() {
        let one = RecoveryId(1);
        assert_eq!(one, one.clone());
    }

    #[test]
    fn invalid_pubkey() {
        let s = Secp256k1::new().unwrap();
        let sig = RecoverableSignature::from_compact(&s, &[1; 64], RecoveryId(0)).unwrap();
        let pk = PublicKey::blank();
        let mut msg = [0u8; 32];
        SysRng.try_fill_bytes(&mut msg).unwrap();
        let msg = Message::from_slice(&msg).unwrap();

        assert_eq!(s.verify(&msg, &sig.to_standard(&s).unwrap(), &pk), Err(InvalidPublicKey));
    }

    #[test]
    fn invalid_ecdsa_signature_encoding() {
        let secp = Secp256k1::new().unwrap();
        let sig = EcdsaSignature::new();
        let (_, pk) = secp.generate_keypair(&mut SysRng).unwrap();
        let msg = Message::from_slice(&[1u8; 32]).unwrap();

        assert!(!sig.is_valid(&secp));
        assert_eq!(secp.verify(&msg, &sig, &pk), Err(InvalidSignature));
    }

    #[test]
    fn sign() {
        let s = Secp256k1::new().unwrap();
        let one = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let sk = SecretKey::from_slice(&s, &one).unwrap();
        let msg = Message::from_slice(&one).unwrap();

        let sig = s.sign_recoverable(&msg, &sk).unwrap();
        assert_eq!(Ok(sig), RecoverableSignature::from_compact(&s, &[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89],
            RecoveryId(1)))
    }

    #[test]
    fn signature_serialize_roundtrip() {
        let s = Secp256k1::new().unwrap();

        let mut msg = [0; 32];
        for _ in 0..100 {
            SysRng.try_fill_bytes(&mut msg).unwrap();
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, _) = s.generate_keypair(&mut SysRng).unwrap();
            let sig1 = s.sign(&msg, &sk).unwrap();
            let der = sig1.serialize_der(&s).unwrap();
            let sig2 = EcdsaSignature::from_der(&s, &der[..]).unwrap();
            assert_eq!(sig1, sig2);

            let compact = sig1.serialize_compact(&s).unwrap();
            let sig2 = EcdsaSignature::from_compact(&s, &compact[..]).unwrap();
            assert_eq!(sig1, sig2);

            round_trip_serde!(sig1);

            assert!(EcdsaSignature::from_compact(&s, &der[..]).is_err());
            assert!(EcdsaSignature::from_compact(&s, &compact[0..4]).is_err());
            assert!(EcdsaSignature::from_der(&s, &compact[..]).is_err());
            assert!(EcdsaSignature::from_der(&s, &der[0..4]).is_err());
         }
    }

    #[test]
    fn signature_lax_der() {
        macro_rules! check_lax_sig(
            ($hex:expr) => ({
                let secp = Secp256k1::without_caps().unwrap();
                let sig = hex!($hex);
                assert!(EcdsaSignature::from_der_lax(&secp, &sig[..]).is_ok());
            })
        );

        check_lax_sig!("304402204c2dd8a9b6f8d425fcd8ee9a20ac73b619906a6367eac6cb93e70375225ec0160220356878eff111ff3663d7e6bf08947f94443845e0dcc54961664d922f7660b80c");
        check_lax_sig!("304402202ea9d51c7173b1d96d331bd41b3d1b4e78e66148e64ed5992abd6ca66290321c0220628c47517e049b3e41509e9d71e480a0cdc766f8cdec265ef0017711c1b5336f");
        check_lax_sig!("3045022100bf8e050c85ffa1c313108ad8c482c4849027937916374617af3f2e9a881861c9022023f65814222cab09d5ec41032ce9c72ca96a5676020736614de7b78a4e55325a");
        check_lax_sig!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
        check_lax_sig!("3046022100eaa5f90483eb20224616775891397d47efa64c68b969db1dacb1c30acdfc50aa022100cf9903bbefb1c8000cf482b0aeeb5af19287af20bd794de11d82716f9bae3db1");
        check_lax_sig!("3045022047d512bc85842ac463ca3b669b62666ab8672ee60725b6c06759e476cebdc6c102210083805e93bd941770109bcc797784a71db9e48913f702c56e60b1c3e2ff379a60");
        check_lax_sig!("3044022023ee4e95151b2fbbb08a72f35babe02830d14d54bd7ed1320e4751751d1baa4802206235245254f58fd1be6ff19ca291817da76da65c2f6d81d654b5185dd86b8acf");
    }

    #[test]
    fn sign_and_verify() {
        let s = Secp256k1::new().unwrap();

        let mut msg = [0; 32];
        for _ in 0..100 {
            SysRng.try_fill_bytes(&mut msg).unwrap();
            let msg = Message::from_slice(&msg).unwrap();

            let (sk, pk) = s.generate_keypair(&mut SysRng).unwrap();
            let sig = s.sign(&msg, &sk).unwrap();
            assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
         }
    }

    #[test]
    fn sign_and_verify_extreme() {
        let s = Secp256k1::new().unwrap();

        // Wild keys: 1, CURVE_ORDER - 1
        // Wild msgs: 0, 1, CURVE_ORDER - 1, CURVE_ORDER
        let mut wild_keys = [[0; 32]; 2];
        let mut wild_msgs = [[0; 32]; 4];

        wild_keys[0][0] = 1;
        wild_msgs[1][0] = 1;

        use crate::constants;
        wild_keys[1][..].copy_from_slice(&constants::CURVE_ORDER[..]);
        wild_msgs[1][..].copy_from_slice(&constants::CURVE_ORDER[..]);
        wild_msgs[2][..].copy_from_slice(&constants::CURVE_ORDER[..]);

        wild_keys[1][0] -= 1;
        wild_msgs[1][0] -= 1;

        for key in wild_keys.iter().map(|k| SecretKey::from_slice(&s, &k[..]).unwrap()) {
            for msg in wild_msgs.iter().map(|m| Message::from_slice(&m[..]).unwrap()) {
                let sig = s.sign(&msg, &key).unwrap();
                let pk = PublicKey::from_secret_key(&s, &key).unwrap();
                assert_eq!(s.verify(&msg, &sig, &pk), Ok(()));
            }
        }
    }

    #[test]
    fn sign_and_verify_fail() {
        let s = Secp256k1::new().unwrap();

        let mut msg = [0u8; 32];
        SysRng.try_fill_bytes(&mut msg).unwrap();
        let msg = Message::from_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut SysRng).unwrap();

        let sigr = s.sign_recoverable(&msg, &sk).unwrap();
        let sig = sigr.to_standard(&s).unwrap();

        let mut msg = [0u8; 32];
        SysRng.try_fill_bytes(&mut msg).unwrap();
        let msg = Message::from_slice(&msg).unwrap();
        assert_eq!(s.verify(&msg, &sig, &pk), Err(IncorrectSignature));

        let recovered_key = s.recover(&msg, &sigr).unwrap();
        assert!(recovered_key != pk);
    }

    #[test]
    fn sign_with_recovery() {
        let s = Secp256k1::new().unwrap();

        let mut msg = [0u8; 32];
        SysRng.try_fill_bytes(&mut msg).unwrap();
        let msg = Message::from_slice(&msg).unwrap();

        let (sk, pk) = s.generate_keypair(&mut SysRng).unwrap();

        let sig = s.sign_recoverable(&msg, &sk).unwrap();

        assert_eq!(s.recover(&msg, &sig), Ok(pk));
    }

    #[test]
    fn bad_recovery() {
        let s = Secp256k1::new().unwrap();

        let msg = Message::from_slice(&[0x55; 32]).unwrap();

        // Zero is not a valid sig
        let sig = RecoverableSignature::from_compact(&s, &[0; 64], RecoveryId(0)).unwrap();
        assert_eq!(s.recover(&msg, &sig), Err(InvalidSignature));
        // ...but 111..111 is
        let sig = RecoverableSignature::from_compact(&s, &[1; 64], RecoveryId(0)).unwrap();
        assert!(s.recover(&msg, &sig).is_ok());
    }

    #[test]
    fn test_bad_slice() {
        let s = Secp256k1::new().unwrap();
        assert_eq!(EcdsaSignature::from_der(&s, &[0; constants::MAX_SIGNATURE_SIZE + 1]),
                   Err(InvalidSignature));
        assert_eq!(EcdsaSignature::from_der(&s, &[0; constants::MAX_SIGNATURE_SIZE]),
                   Err(InvalidSignature));

        assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE - 1]),
                   Err(InvalidMessage));
        assert_eq!(Message::from_slice(&[0; constants::MESSAGE_SIZE + 1]),
                   Err(InvalidMessage));
        assert!(Message::from_slice(&[0; constants::MESSAGE_SIZE]).is_ok());
    }

    #[test]
    fn test_from_der_rejects_invalid_scalars() {
        let s = Secp256k1::new().unwrap();
        let der_with_zero_r = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];

        assert_eq!(EcdsaSignature::from_der(&s, &der_with_zero_r), Err(InvalidSignature));
    }

    #[test]
    fn test_debug_output() {
        let s = Secp256k1::new().unwrap();
        let sig = RecoverableSignature::from_compact(&s, &[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89],
            RecoveryId(1)).unwrap();
        assert_eq!(&format!("{:?}", sig), "RecoverableSignature(98882e09f4ed6dc3659e43fc771e0cafa60b1f926f2b77041f744721adff7366898cb609d0ee128d06ae9aa3c48020ff9f705e02f80e1280a8ade05216971a4c01)");

        let msg = Message([1, 2, 3, 4, 5, 6, 7, 8,
                           9, 10, 11, 12, 13, 14, 15, 16,
                           17, 18, 19, 20, 21, 22, 23, 24,
                           25, 26, 27, 28, 29, 30, 31, 255]);
        assert_eq!(&format!("{:?}", msg), "Message(0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fff)");
    }

    #[test]
    fn test_recov_sig_serialize_compact() {
        let s = Secp256k1::new().unwrap();

        let recid_in = RecoveryId(1);
        let bytes_in = &[
            0x66, 0x73, 0xff, 0xad, 0x21, 0x47, 0x74, 0x1f,
            0x04, 0x77, 0x2b, 0x6f, 0x92, 0x1f, 0x0b, 0xa6,
            0xaf, 0x0c, 0x1e, 0x77, 0xfc, 0x43, 0x9e, 0x65,
            0xc3, 0x6d, 0xed, 0xf4, 0x09, 0x2e, 0x88, 0x98,
            0x4c, 0x1a, 0x97, 0x16, 0x52, 0xe0, 0xad, 0xa8,
            0x80, 0x12, 0x0e, 0xf8, 0x02, 0x5e, 0x70, 0x9f,
            0xff, 0x20, 0x80, 0xc4, 0xa3, 0x9a, 0xae, 0x06,
            0x8d, 0x12, 0xee, 0xd0, 0x09, 0xb6, 0x8c, 0x89];
        let sig = RecoverableSignature::from_compact(
            &s, bytes_in, recid_in).unwrap();
        let (recid_out, bytes_out) = sig.serialize_compact(&s).unwrap();
        assert_eq!(recid_in, recid_out);
        assert_eq!(&bytes_in[..], &bytes_out[..]);
    }

    #[test]
    fn test_recov_id_conversion_between_i32() {
        assert!(RecoveryId::from_i32(-1).is_err());
        assert!(RecoveryId::from_i32(0).is_ok());
        assert!(RecoveryId::from_i32(1).is_ok());
        assert!(RecoveryId::from_i32(2).is_ok());
        assert!(RecoveryId::from_i32(3).is_ok());
        assert!(RecoveryId::from_i32(4).is_err());
        let id0 = RecoveryId::from_i32(0).unwrap();
        assert_eq!(id0.to_i32(), 0);
        let id1 = RecoveryId(1);
        assert_eq!(id1.to_i32(), 1);
    }

    #[test]
    fn test_low_s() {
        // nb this is a transaction on testnet
        // txid 8ccc87b72d766ab3128f03176bb1c98293f2d1f85ebfaf07b82cc81ea6891fa9
        //      input number 3
        let sig = hex!("3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45");
        let pk = hex!("031ee99d2b786ab3b0991325f2de8489246a6a3fdb700f6d0511b1d80cf5f4cd43");
        let msg = hex!("a4965ca63b7d8562736ceec36dfa5a11bf426eb65be8ea3f7a49ae363032da0d");

        let secp = Secp256k1::new().unwrap();
        let mut sig = EcdsaSignature::from_der(&secp, &sig[..]).unwrap();
        let pk = PublicKey::from_slice(&secp, &pk[..]).unwrap();
        let msg = Message::from_slice(&msg[..]).unwrap();

        // without normalization we expect this will fail
        assert_eq!(secp.verify(&msg, &sig, &pk), Err(IncorrectSignature));
        // after normalization it should pass
        sig.normalize_s(&secp).unwrap();
        assert_eq!(secp.verify(&msg, &sig, &pk), Ok(()));
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use rand::{Rng,TryCryptoRng};
    use rand::rngs::SysRng;
    use test::{Bencher, black_box};

    use super::{Secp256k1, Message};

    #[bench]
    pub fn generate(bh: &mut Bencher) {
        struct CounterRng(u32);
        impl Rng for CounterRng {
            fn next_u32(&mut self) -> u32 { self.0 += 1; self.0 }
        }

        let s = Secp256k1::new().unwrap();
        let mut r = CounterRng(0);
        bh.iter( || {
            let (sk, pk) = s.generate_keypair(&mut r).unwrap();
            black_box(sk);
            black_box(pk);
        });
    }

    #[bench]
    pub fn bench_sign(bh: &mut Bencher) {
        let s = Secp256k1::new().unwrap();
        let mut msg = [0u8; 32];
        SysRng.try_fill_bytes(&mut msg).unwrap();
        let msg = Message::from_slice(&msg).unwrap();
        let (sk, _) = s.generate_keypair(&mut SysRng).unwrap();

        bh.iter(|| {
            let sig = s.sign(&msg, &sk).unwrap();
            black_box(sig);
        });
    }

    #[bench]
    pub fn bench_verify(bh: &mut Bencher) {
        let s = Secp256k1::new().unwrap();
        let mut msg = [0u8; 32];
        SysRng.try_fill_bytes(&mut msg).unwrap();
        let msg = Message::from_slice(&msg).unwrap();
        let (sk, pk) = s.generate_keypair(&mut SysRng).unwrap();
        let sig = s.sign(&msg, &sk).unwrap();

        bh.iter(|| {
            let res = s.verify(&msg, &sig, &pk).unwrap();
            black_box(res);
        });
    }

    #[bench]
    pub fn bench_recover(bh: &mut Bencher) {
        let s = Secp256k1::new().unwrap();
        let mut msg = [0u8; 32];
        SysRng.try_fill_bytes(&mut msg).unwrap();
        let msg = Message::from_slice(&msg).unwrap();
        let (sk, _) = s.generate_keypair(&mut SysRng).unwrap();
        let sig = s.sign_recoverable(&msg, &sk).unwrap();

        bh.iter(|| {
            let res = s.recover(&msg, &sig).unwrap();
            black_box(res);
        });
    }
}
