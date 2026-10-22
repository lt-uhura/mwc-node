// Rust secp256k1 bindings for aggsig functions
// 2018 The Mwc developers
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

//! # Aggregated Signature (a.k.a. Schnorr) Functionality

use libc::size_t;
use crate::{constants, ffi, ContextFlag};
use crate::key::{PublicKey, SecretKey};
use std::ptr;
use crate::Secp256k1;
use crate::{AggSigPartialSignature, AggSigSignature, Error, Message};
use zeroize::Zeroize;
use rand::rngs::SysRng;
use rand::TryRng;

const SCRATCH_SPACE_SIZE: size_t = 1024 * 1024;

/// The 256 bits 0
pub const ZERO_256: [u8; 32] = [
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Single-Signer (plain old Schnorr, sans-multisig) export nonce
/// Returns: Ok(SecretKey) on success
/// In:
/// msg: the message to sign
/// seckey: the secret key
pub fn export_secnonce_single(secp: &Secp256k1) -> Result<SecretKey, Error> {
	if secp.caps == ContextFlag::VerifyOnly || secp.caps == ContextFlag::None {
		return Err(Error::IncapableContext);
	}

	let mut return_key : [u8; constants::SECRET_KEY_SIZE] = [0u8; constants::SECRET_KEY_SIZE];
	let mut seed = [0u8; 32];
	SysRng.try_fill_bytes(&mut seed)
		.map_err(|_| Error::SysRngFailure)?;

	let retval = unsafe {
		ffi::secp256k1_aggsig_export_secnonce_single(
			secp.ctx,
			return_key.as_mut_ptr(),
			seed.as_ptr(),
		)
	};
	seed.zeroize();
	if retval != 1 {
		return Err(Error::NonceExportError);
	}

	let return_key = SecretKey::from_slice(secp, &return_key)?;
	Ok(return_key)
}

macro_rules! is_valid_pubkey {
	(reterr => $secp:expr, $e:expr) => {
		match $e {
			Some(n) => {
				if !n.is_valid($secp) {
					return Err(Error::InvalidPublicKey);
				}
				n.as_ptr()
			},
			None => ptr::null(),
		}
	};
	(retfalse => $secp:expr, $e:expr) => {
		match $e {
			Some(n) => {
				if !n.is_valid($secp) {
					return Ok(false);
				}
				n.as_ptr()
			},
			None => ptr::null(),
		}
	};
}

/// Single-Signer (plain old Schnorr, sans-multisig) signature creation
/// Returns: Ok(AggSigSignature) on success
/// In:
/// msg: the message to sign
/// seckey: the secret key
/// extra: if Some(), add this key to s
/// secnonce: if Some(SecretKey), the secret nonce to use. If None, generate a nonce
/// pubnonce: if Some(PublicKey), overrides the public nonce to encode as part of e
/// pubkey_for_e: public key material to encode as part of e; must be supplied
/// final_nonce_sum: if Some(PublicKey), overrides the public nonce to encode as part of e
pub fn sign_single(
	secp: &Secp256k1,
	msg: &Message,
	seckey: &SecretKey,
	secnonce: Option<&SecretKey>,
	extra: Option<&SecretKey>,
	pubnonce: Option<&PublicKey>,
	pubkey_for_e: &PublicKey,
	final_nonce_sum: Option<&PublicKey>,
) -> Result<AggSigSignature, Error> {
	if secp.caps == ContextFlag::VerifyOnly || secp.caps == ContextFlag::None {
		return Err(Error::IncapableContext);
	}

	let mut retsig = AggSigSignature::new();

	let secnonce = match secnonce {
		Some(n) => n.as_ptr(),
		None => ptr::null(),
	};

	let pubnonce = is_valid_pubkey!(reterr => secp, pubnonce);

	let extra = match extra {
		Some(e) => e.as_ptr(),
		None => ptr::null(),
	};

	let final_nonce_sum = is_valid_pubkey!(reterr => secp, final_nonce_sum);

	if !pubkey_for_e.is_valid(secp) {
		return Err(Error::InvalidPublicKey);
	}
	let pe = pubkey_for_e.as_ptr();

	// Note, seed it needed only if secnonce_final_nonce_sum is not provided.
	// But let's not make assumptions about secp256k1_aggsig_sign_single internals that
	// that can be changed and generate seed every time.
	let mut seed = [0u8; 32];
	SysRng.try_fill_bytes(&mut seed)
		.map_err(|_| Error::SysRngFailure)?;

	let retval = unsafe {
		ffi::secp256k1_aggsig_sign_single(
			secp.ctx,
			retsig.as_mut_ptr(),
			msg.as_ptr(),
			seckey.as_ptr(),
			secnonce,
			extra,
			pubnonce,
			final_nonce_sum,
			pe,
			seed.as_ptr(),
		)
	};
	seed.zeroize();
	if retval != 1 {
		return Err(Error::InvalidSignature);
	}
	if !retsig.is_valid(secp) {
		return Err(Error::InvalidSignature);
	}
	Ok(retsig)
}

/// Single-Signer (plain old Schnorr, sans-multisig) signature verification
/// Returns: Ok(bool) on success
/// In:
/// sig: The signature
/// msg: the message to verify
/// pubnonce: if Some(PublicKey) overrides the public nonce used to calculate e
/// pubkey: the public key
/// pubkey_total: The total of all public keys included in the message challenge e
/// is_partial: whether this is a partial sig, or a fully-combined sig
/// Note: invalid public keys and signatures are not reported as an error.
///    they are reported and invalid signature. Idea that user can pass any combinations of
///    PK and Signatures so we need to varify them, no extra details are expected.
/// Note: Validation internal error will be reported as false
pub fn verify_single(
	secp: &Secp256k1,
	sig: &AggSigSignature,
	msg: &Message,
	pubnonce: Option<&PublicKey>,
	pubkey: &PublicKey,
	pubkey_total_for_e: &PublicKey,
	extra_pubkey: Option<&PublicKey>,
	is_partial: bool,
) -> Result<bool, Error> {
	if secp.caps == ContextFlag::SignOnly || secp.caps == ContextFlag::None {
		return Err(Error::IncapableContext);
	}

	let pubnonce = is_valid_pubkey!(retfalse => secp, pubnonce);
	let extra = is_valid_pubkey!(retfalse => secp, extra_pubkey);

	if !pubkey.is_valid(secp) {
		return Ok(false);
	}
	if !pubkey_total_for_e.is_valid(secp) {
		return Ok(false);
	}
	if !sig.is_valid(secp) {
		return Ok(false);
	}
	let pe = pubkey_total_for_e.as_ptr();

	let is_partial = match is_partial {
		true => 1,
		false => 0,
	};

	let retval = unsafe {
		ffi::secp256k1_aggsig_verify_single(
			secp.ctx,
			sig.0.as_ptr(),
			msg.as_ptr(),
			pubnonce,
			pubkey.as_ptr(),
			pe,
			extra,
			is_partial,
		)
	};
	// Note: Validation internal error will be reported as false, chances of false negative are accepted
	Ok(retval==1)
}


/// Batch Schnorr signature verification
/// Returns: true on success
/// In:
/// sigs: The aggsig signatures
/// msg: The messages to verify
/// pubkey: The public keys
/// Note, return false might happens because of internal errors.
pub fn verify_batch(
	secp: &Secp256k1,
	sigs: &Vec<AggSigSignature>,
	msgs: &Vec<Message>,
	pub_keys: &Vec<PublicKey>,
) -> Result<bool,Error> {
	if secp.caps == ContextFlag::SignOnly || secp.caps == ContextFlag::None {
		return Err(Error::IncapableContext);
	}

	if sigs.len() > 1048575 {
		return Err(Error::InvalidParameters);
	}

	if sigs.len() != msgs.len() || sigs.len() != pub_keys.len() {
		// Intentionally response as false, not an error.
		return Ok(false);
	}

	for pk in pub_keys {
		if !pk.is_valid(secp) {
			// Intentionally response as false, not an error.
			return Ok(false);
		}
	}
	for sig in sigs {
		if !sig.is_valid(secp) {
			// Intentionally response as false, not an error.
			return Ok(false);
		}
	}

	let sigs_vec = map_vec!(sigs, |s| s.as_ptr());
	let msgs_vec = map_vec!(msgs, |m| m.as_ptr());
	let pub_keys_vec = map_vec!(pub_keys, |pk| pk.as_ptr());

	unsafe {
		let scratch = ffi::secp256k1_scratch_space_create(secp.ctx, SCRATCH_SPACE_SIZE);
		// Note ffi::secp256k1_scratch_space_create will not return the NULL, it will crash instead.
		//  Checking for null for extra layer

		if scratch.is_null() {
			return Err(Error::AllocationError);
		}
		let result = ffi::secp256k1_schnorrsig_verify_batch(
			secp.ctx,
			scratch,
			sigs_vec.as_ptr(),
			msgs_vec.as_ptr(),
			pub_keys_vec.as_ptr(),
			sigs.len(),
		);
		ffi::secp256k1_scratch_space_destroy(scratch);
		// Note, return false might happens because of internal errors.
		// result==0 might be because of internal error
		Ok(result == 1)
	}
}

/// Single-Signer addition of Signatures
/// Returns: Ok(AggSigSignature) on success
/// In:
/// sig1: sig1 to add
/// sig2: sig2 to add
/// pubnonce_total: sum of public nonces
pub fn add_signatures_single(
	secp: &Secp256k1,
	sigs: Vec<&AggSigSignature>,
	pubnonce_total: &PublicKey,
) -> Result<AggSigSignature, Error> {
	if secp.caps == ContextFlag::VerifyOnly || secp.caps == ContextFlag::None {
		return Err(Error::IncapableContext);
	}

	if sigs.is_empty() {
		return Err(Error::InvalidParameters);
	}
	if !pubnonce_total.is_valid(secp) {
		return Err(Error::InvalidPublicKey);
	}
	for sig in &sigs {
		if !sig.is_valid(secp) {
			return Err(Error::InvalidSignature);
		}
	}

	let mut retsig = AggSigSignature::new();
	let sig_vec = map_vec!(sigs, |s| s.as_ptr());
	let retval = unsafe {
		ffi::secp256k1_aggsig_add_signatures_single(
			secp.ctx,
			retsig.as_mut_ptr(),
			sig_vec.as_ptr(),
			sig_vec.len(),
			pubnonce_total.as_ptr(),
		)
	};
	if retval != 1 || !retsig.is_valid(secp) {
		return Err(Error::InvalidSignature);
	}
	Ok(retsig)
}

/// Subtraction of partial signature from a signature
/// Returns: Ok((AggSigSignature, None)) on success if the resulting signature has only one possibility
///          Ok((AggSigSignature, AggSigSignature)) on success if the resulting signature could be one of either possiblity
/// In:
/// sig: completed signature from which to subtact a partial
/// partial_sig: the partial signature to subtract
pub fn subtract_partial_signature(
	secp: &Secp256k1,
	sig: &AggSigSignature,
	partial_sig: &AggSigSignature,
) -> Result<(AggSigSignature, Option<AggSigSignature>), Error> {
	if !sig.is_valid(secp) || !partial_sig.is_valid(secp) {
		return Err(Error::InvalidSignature);
	}

	// Here we are passing to secp256k1_aggsig_subtract_partial_signature two zero initialized buffers: [0; 64]
	let mut ret_partsig = AggSigSignature::new();
	let mut ret_partsig_alt = AggSigSignature::new();
	let retval = unsafe {
		ffi::secp256k1_aggsig_subtract_partial_signature(
			secp.ctx,
			ret_partsig.as_mut_ptr(),
			ret_partsig_alt.as_mut_ptr(),
			sig.as_ptr(),
			partial_sig.as_ptr(),
		)
	};

	match retval {
		-1 => Err(Error::SigSubtractionFailure),
		1 => {
			if !ret_partsig.is_valid(secp) {
				Err(Error::InvalidSignature)
			}
			else {
				Ok((ret_partsig, None))
			}
		},
		2 => {
			if !ret_partsig.is_valid(secp) || !ret_partsig_alt.is_valid(secp) {
				Err(Error::InvalidSignature)
			}
			else {
				Ok((ret_partsig, Some(ret_partsig_alt)))
			}
		},
		_ => Err(Error::GenericError)
	}
}


/// Manages an instance of an aggsig multisig context, and provides all methods
/// to act on that context
/// Note, Clone can't be supported because of Drop that release aggsig_ctx
#[derive(Debug)]
pub struct AggSigContext {
	secp: Option<Secp256k1>,
	aggsig_ctx: *mut ffi::AggSigContext,
	pubkeys: Vec<PublicKey>,
}

impl AggSigContext {
	#[inline]
	fn has_valid_index(&self, index: usize) -> bool {
		index < self.pubkeys.len()
	}

	/// Creates new aggsig context with a new random seed
	pub fn new(pubkeys: &Vec<PublicKey>) -> Result<AggSigContext, Error> {
		if pubkeys.is_empty() || pubkeys.len()>1048575 {
			return Err(Error::InvalidParameters)
		}

		let secp = Secp256k1::with_caps(ContextFlag::Full)?;

		let mut ffi_pubkeys: Vec<ffi::PublicKey> = Vec::with_capacity(pubkeys.len());
		for pk in pubkeys {
			if !pk.is_valid(&secp) {
				return Err(Error::InvalidPublicKey);
			}
			ffi_pubkeys.push(pk.as_ffi());
		}

		let mut seed = [0u8; 32];
		SysRng.try_fill_bytes(&mut seed)
			.map_err(|_| Error::SysRngFailure)?;

		let aggsig_ctx = unsafe {
			ffi::secp256k1_aggsig_context_create(
				secp.ctx,
				ffi_pubkeys.as_ptr(),
				ffi_pubkeys.len(),
				seed.as_ptr(),
			)
		};
		seed.zeroize();

		// Note, normally ffi::secp256k1_aggsig_context_create will never return null, it will crash instead.
		// There is nothing what we can do about that.
		if aggsig_ctx.is_null() {
			return Err(Error::AllocationError);
		}

		Ok(AggSigContext {
				secp: Some(secp),
				aggsig_ctx,
				pubkeys: pubkeys.clone(),
			})
	}

	/// Generate a nonce pair for a single signature part in an aggregated signature
	/// Returns: true on success
	///          false if a nonce has already been generated for this index or internal error happens
	/// In: index: which signature to generate a nonce for
	/// Note: since 'nonce has already been generated' and 'internal error during generation' mean that
	///     nonce must be rejected, we don't need distinguish those events for caller.
	/// Note: generate_nonce using cached data from the self.secp context.
	pub fn generate_nonce(&self, index: usize) -> Result<bool, Error> {
		if !self.has_valid_index(index) {
			return Err(Error::InvalidParameters);
		}
		let secp = self.secp.as_ref().ok_or(Error::BrokenAggSigContext)?;

		let retval =
			unsafe { ffi::secp256k1_aggsig_generate_nonce(secp.ctx, self.aggsig_ctx, index) };

		Ok(retval == 1)
	}

	/// Generate a single signature part in an aggregated signature
	/// Returns: Ok(AggSigPartialSignature) on success
	/// In:
	/// msg: the message to sign
	/// seckey: the secret key
	/// index: which index to generate a partial sig for
	pub fn partial_sign(
		&mut self,
		msg: Message,
		seckey: SecretKey,
		index: usize,
	) -> Result<AggSigPartialSignature, Error> {
		if !self.has_valid_index(index) {
			return Err(Error::InvalidParameters);
		}

		let secp = self.secp.as_ref().ok_or(Error::BrokenAggSigContext)?;

		let mut retsig = AggSigPartialSignature::from(ffi::AggSigPartialSignature::new());
		let retval = unsafe {
			ffi::secp256k1_aggsig_partial_sign(
				secp.ctx,
				self.aggsig_ctx,
				retsig.as_mut_ptr(),
				msg.as_ptr(),
				seckey.as_ptr(),
				index,
			)
		};
		if retval != 1 {
			/* Even error might be recoverable, but it is not part of supported workflow. Treat as non recoverable is acceptable */
			self.secp = None;
			self.destroy_aggsig_ctx();
			return Err(Error::PartialSigFailure);
		}
		Ok(retsig)
	}

	/// Aggregate multiple signature parts into a single aggregated signature
	/// Returns: Ok(AggSigSignature) on success
	/// In:
	/// partial_sigs: vector of partial signatures
	/// Note, it is a caller responsibility to validate that every signer slot completed the
	/// 			required `generate_nonce` and `partial_sign` steps.
	/// Note, any non-success causes the wrapper to mark the context broken and destroy `aggsig_ctx`
	///      It is acceptable for our usage, even  one attacker-controlled bad partial signature a
	/// 	 permanent local denial of service for the signing round instead of a recoverable error.
	pub fn combine_signatures(
		&mut self,
		partial_sigs: &Vec<AggSigPartialSignature>,
	) -> Result<AggSigSignature, Error> {
		if partial_sigs.len() != self.pubkeys.len() {
			return Err(Error::PartialSigFailure)
		}

		let mut retsig = AggSigSignature::new();
		let mut ffi_sigs: Vec<ffi::AggSigPartialSignature> = Vec::with_capacity(partial_sigs.len());
		for sig in partial_sigs {
			ffi_sigs.push(sig.as_ffi());
		}
		let secp = self.secp.as_ref().ok_or(Error::BrokenAggSigContext)?;

		let retval = unsafe {
			ffi::secp256k1_aggsig_combine_signatures(
				secp.ctx,
				self.aggsig_ctx,
				retsig.as_mut_ptr(),
				ffi_sigs.as_ptr(),
				ffi_sigs.len(),
			)
		};
		if retval != 1 {
			self.secp = None;
			self.destroy_aggsig_ctx();
			return Err(Error::PartialSigFailure);
		}
		Ok(retsig)
	}

	/// Verifies aggregate sig against the participant set used to create this context.
	/// Returns: true if valid, okay if not
	/// In:
	/// msg: message to verify
	/// sig: combined signature
	/// Note: internal verification failures such as scratch-space creation/use failure reported
	///     as faled verification - false negative.  It is accepted, sinse memory starvation is fatal in any case.
	pub fn verify(&self, sig: AggSigSignature, msg: Message) -> Result<bool,Error> {
		let secp = self.secp.as_ref().ok_or(Error::BrokenAggSigContext)?;

		if !sig.is_valid(&secp) {
			return Ok(false);
		}

		let mut ffi_pks: Vec<ffi::PublicKey> = Vec::with_capacity(self.pubkeys.len());
		for pk in &self.pubkeys {
			ffi_pks.push(pk.as_ffi());
		}

		let retval = unsafe {
			ffi::secp256k1_aggsig_build_scratch_and_verify(
				secp.ctx,
				sig.as_ptr(),
				msg.as_ptr(),
				ffi_pks.as_ptr(),
				ffi_pks.len(),
			)
		};
		Ok(retval == 1)
	}

	fn destroy_aggsig_ctx(&mut self) {
		if !self.aggsig_ctx.is_null() {
			unsafe {
				ffi::secp256k1_aggsig_context_destroy(self.aggsig_ctx);
			}
			self.aggsig_ctx = ptr::null_mut();
		}
	}
}

impl Drop for AggSigContext {
	fn drop(&mut self) {
		self.destroy_aggsig_ctx();
	}
}

#[cfg(test)]
mod tests {
	use super::{
		add_signatures_single, export_secnonce_single, sign_single, verify_single, verify_batch,
		AggSigContext, Secp256k1,
	};
	use crate::aggsig::subtract_partial_signature;
	use crate::constants;
	use crate::ffi;
	use crate::key::{PublicKey, SecretKey};
	use rand::TryRng;
	use rand::rngs::SysRng;
	use crate::ContextFlag;
	use crate::{AggSigPartialSignature, AggSigSignature, Message};

	#[test]
	fn test_aggsig_multisig() {
		test_aggsig_multisig_impl(Secp256k1::with_caps(ContextFlag::SignOnly).unwrap()).unwrap();
	}

	fn test_aggsig_multisig_impl(secp: Secp256k1) -> Result<(), crate::Error> {
		let numkeys = 5;
		let mut keypairs: Vec<(SecretKey, PublicKey)> = vec![];
		for _ in 0..numkeys {
			keypairs.push(secp.generate_keypair(&mut SysRng)?);
		}
		let pks: Vec<PublicKey> = keypairs.clone().into_iter().map(|(_, p)| p).collect();
		println!(
			"Creating aggsig context with {} pubkeys: {:?}",
			pks.len(),
			pks
		);
		let mut aggsig = AggSigContext::new(&pks)?;
		println!("Generating nonces for each index");
		for i in 0..numkeys {
			let retval = aggsig.generate_nonce(i).unwrap();
			println!("{} returned {}", i, retval);
			assert!(retval == true);
		}

		assert!(aggsig.generate_nonce(1000).is_err());

		let mut msg = [0u8; 32];
		SysRng.try_fill_bytes(&mut msg).unwrap();
		let msg = Message::from_slice(&msg).unwrap();
		let mut partial_sigs: Vec<AggSigPartialSignature> = vec![];
		for i in 0..numkeys {
			println!(
				"Partial sign message: {:?} at index {}, SK:{:?}",
				msg, i, keypairs[i].0
			);

			let result = aggsig.partial_sign(msg, keypairs[i].0.clone(), i);
			match result {
				Ok(ps) => {
					println!("Partial sig: {:?}", ps);
					partial_sigs.push(ps);
				}
				Err(e) => panic!("Partial sig failed: {}", e),
			}
		}

		let result = aggsig.combine_signatures(&partial_sigs);

		let combined_sig = match result {
			Ok(cs) => {
				println!("Combined sig: {:?}", cs);
				cs
			}
			Err(e) => panic!("Combining partial sig failed: {}", e),
		};

		println!(
			"Verifying Combined sig: {:?}, msg: {:?}, pks:{:?}",
			combined_sig, msg, pks
		);
		let result = aggsig.verify(combined_sig, msg).unwrap();
		println!("Signature verification: {}", result);
		assert!(result);

		Ok(())
	}

	#[test]
	fn test_aggsig_single() {
		let secp = Secp256k1::with_caps(ContextFlag::Full).unwrap();
		let (sk, pk) = secp.generate_keypair(&mut SysRng).unwrap();

		println!(
			"Performing aggsig single context with seckey, pubkey: {:?},{:?}",
			sk, pk
		);

		let mut msg = [0u8; 32];
		SysRng.try_fill_bytes(&mut msg).unwrap();
		let msg = Message::from_slice(&msg).unwrap();
		let sig = sign_single(&secp, &msg, &sk, None, None, None, &pk, None).unwrap();

		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			sig, msg, pk
		);
		let result = verify_single(&secp, &sig, &msg, None, &pk, &pk, None, false).unwrap();
		println!("Signature verification single (correct): {}", result);
		assert!(result == true);

		let mut msg = [0u8; 32];
		SysRng.try_fill_bytes(&mut msg).unwrap();
		let msg = Message::from_slice(&msg).unwrap();
		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			sig, msg, pk
		);
		let result = verify_single(&secp, &sig, &msg, None, &pk, &pk, None, false).unwrap();
		println!("Signature verification single (wrong message): {}", result);
		assert!(result == false);

		// test optional extra key
		let mut msg = [0u8; 32];
		SysRng.try_fill_bytes(&mut msg).unwrap();
		let msg = Message::from_slice(&msg).unwrap();
		let (sk_extra, pk_extra) = secp.generate_keypair(&mut SysRng).unwrap();
		let sig = sign_single(&secp, &msg, &sk, None, Some(&sk_extra), None, &pk, None).unwrap();
		let result = verify_single(&secp, &sig, &msg, None, &pk, &pk, Some(&pk_extra), false).unwrap();
		assert!(result == true);
	}

	#[test]
	fn test_aggsig_batch() {
		let secp = Secp256k1::with_caps(ContextFlag::Full).unwrap();

		let mut sigs: Vec<AggSigSignature> = vec![];
		let mut msgs: Vec<Message> = vec![];
		let mut pub_keys: Vec<PublicKey> = vec![];

		for _ in 0..100 {
			let (sk, pk) = secp.generate_keypair(&mut SysRng).unwrap();
			let mut msg = [0u8; 32];
			SysRng.try_fill_bytes(&mut msg).unwrap();

			let msg = Message::from_slice(&msg).unwrap();
			let sig = sign_single(&secp, &msg, &sk, None, None, None, &pk, None).unwrap();

			let result_single = verify_single(&secp, &sig, &msg, None, &pk, &pk, None, false).unwrap();
			assert!(result_single == true);

			pub_keys.push(pk);
			msgs.push(msg);
			sigs.push(sig);
		}

		println!("Verifying aggsig batch of 100");
		let result = verify_batch(&secp, &sigs, &msgs, &pub_keys).unwrap();
		assert!(result == true);

		// Checking capabilities
		let secp_none = Secp256k1::with_caps(ContextFlag::None).unwrap();
		let secp_sign_only = Secp256k1::with_caps(ContextFlag::SignOnly).unwrap();
		let secp_verify_only = Secp256k1::with_caps(ContextFlag::VerifyOnly).unwrap();
		let secp_full = Secp256k1::with_caps(ContextFlag::Full).unwrap();
		let secp_commit = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		assert!(verify_batch(&secp_none, &sigs, &msgs, &pub_keys).is_err());
		assert!(verify_batch(&secp_sign_only, &sigs, &msgs, &pub_keys).is_err());
		assert!(verify_batch(&secp_verify_only, &sigs, &msgs, &pub_keys).is_ok());
		assert!(verify_batch(&secp_full, &sigs, &msgs, &pub_keys).is_ok());
		assert!(verify_batch(&secp_commit, &sigs, &msgs, &pub_keys).is_ok());

	}

	#[test]
	fn test_aggsig_signature_validation() {
		let secp_sign = Secp256k1::with_caps(ContextFlag::SignOnly).unwrap();
		let secp_verify = Secp256k1::with_caps(ContextFlag::VerifyOnly).unwrap();
		let zero_sig = AggSigSignature::new();
		let (sk, pk) = secp_sign.generate_keypair(&mut SysRng).unwrap();
		let (_nonce_sk, nonce_pk) = secp_sign.generate_keypair(&mut SysRng).unwrap();
		let msg = Message::from_slice(&[42u8; 32]).unwrap();
		let valid_sig = sign_single(&secp_sign, &msg, &sk, None, None, None, &pk, None).unwrap();

		assert!(!zero_sig.is_valid(&secp_verify));
		assert_eq!(
			verify_single(&secp_verify, &zero_sig, &msg, None, &pk, &pk, None, false).unwrap(),
			false
		);
		assert_eq!(
			add_signatures_single(&secp_sign, vec![&zero_sig], &nonce_pk),
			Err(crate::Error::InvalidSignature)
		);
		assert_eq!(
			subtract_partial_signature(&secp_sign, &zero_sig, &valid_sig),
			Err(crate::Error::InvalidSignature)
		);

		let mut invalid_non_lift = [0u8; 64];
		invalid_non_lift[63] = 1;
		let mut found_invalid_rx = false;
		for candidate in 1u16..=u16::MAX {
			let mut compressed = [0u8; constants::COMPRESSED_PUBLIC_KEY_SIZE];
			compressed[0] = 0x02;
			compressed[31] = (candidate >> 8) as u8;
			compressed[32] = candidate as u8;
			if PublicKey::from_slice(&secp_verify, &compressed).is_err() {
				invalid_non_lift[30] = (candidate >> 8) as u8;
				invalid_non_lift[31] = candidate as u8;
				found_invalid_rx = true;
				break;
			}
		}
		assert!(found_invalid_rx);
		let invalid_non_lift_sig = AggSigSignature {
			0: ffi::Signature(invalid_non_lift),
		};

		assert!(!invalid_non_lift_sig.is_valid(&secp_verify));
		assert_eq!(
			verify_single(&secp_verify, &invalid_non_lift_sig, &msg, None, &pk, &pk, None, false).unwrap(),
			false
		);
		assert_eq!(
			add_signatures_single(&secp_sign, vec![&invalid_non_lift_sig], &nonce_pk),
			Err(crate::Error::InvalidSignature)
		);
		assert_eq!(
			subtract_partial_signature(&secp_sign, &invalid_non_lift_sig, &valid_sig),
			Err(crate::Error::InvalidSignature)
		);
	}

	#[test]
	fn test_aggsig_from_compact() {
		let secp = Secp256k1::with_caps(ContextFlag::Full).unwrap();
		let (sk, pk) = secp.generate_keypair(&mut SysRng).unwrap();
		let msg = Message::from_slice(&[7u8; 32]).unwrap();
		let sig = sign_single(&secp, &msg, &sk, None, None, None, &pk, None).unwrap();

		let compact = sig.serialize_compact(&secp).unwrap();
		assert_ne!(&compact[..], sig.as_ref());

		let parsed = AggSigSignature::from_compact(&secp, &compact).unwrap();
		assert_eq!(parsed, sig);
		assert!(parsed.is_valid(&secp));
		assert_eq!(
			verify_single(&secp, &parsed, &msg, None, &pk, &pk, None, false).unwrap(),
			true
		);
		assert_eq!(*parsed.as_ref(), *sig.as_ref());
	}

	#[test]
	fn test_aggsig_fuzz() {
		let secp = Secp256k1::with_caps(ContextFlag::Full).unwrap();
		let (sk, pk) = secp.generate_keypair(&mut SysRng).unwrap();

		println!(
			"Performing aggsig single context with seckey, pubkey: {:?},{:?}",
			sk, pk
		);

		let mut msg = [0u8; 32];
		SysRng.try_fill_bytes(&mut msg).unwrap();
		let msg = Message::from_slice(&msg).unwrap();
		let sig = sign_single(&secp, &msg, &sk, None, None, None, &pk, None).unwrap();

		// force sig[32..] as 0 to simulate Fuzz test
		let corrupted = &mut [0u8; 64];
		let mut i = 0;
		for elem in corrupted[..32].iter_mut() {
			*elem = sig.0[i];
			i += 1;
		}
		let corrupted_sig: AggSigSignature = AggSigSignature {
			0: ffi::Signature(*corrupted),
		};
		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			corrupted_sig, msg, pk
		);
		let result = verify_single(&secp, &corrupted_sig, &msg, None, &pk, &pk, None, false).unwrap();
		println!("Signature verification single (correct): {}", result);
		assert!(result == false);

		// force sig[0..32] as 0 to simulate Fuzz test
		let corrupted = &mut [0u8; 64];
		let mut i = 32;
		for elem in corrupted[32..].iter_mut() {
			*elem = sig.0[i];
			i += 1;
		}
		let corrupted_sig: AggSigSignature = AggSigSignature {
			0: ffi::Signature(*corrupted),
		};
		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			corrupted_sig, msg, pk
		);
		let result = verify_single(&secp, &corrupted_sig, &msg, None, &pk, &pk, None, false).unwrap();
		println!("Signature verification single (correct): {}", result);
		assert!(result == false);

		// force pk as 0 to simulate Fuzz test
		let zero_pk = PublicKey::blank();
		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			sig, msg, zero_pk
		);
		let result = verify_single(&secp, &sig, &msg, None, &zero_pk, &pk, None, false).unwrap();
		println!("Signature verification single (correct): {}", result);
		assert!(result == false);

		let mut sigs: Vec<AggSigSignature> = vec![];
		sigs.push(sig);
		let mut msgs: Vec<Message> = vec![];
		msgs.push(msg);
		let mut pub_keys: Vec<PublicKey> = vec![];
		pub_keys.push(zero_pk);
		println!(
			"Verifying aggsig batch: {:?}, msg: {:?}, pk:{:?}",
			sig, msg, zero_pk
		);
		let result = verify_batch(&secp, &sigs, &msgs, &pub_keys).unwrap();
		println!("Signature verification batch: {}", result);
		assert!(result == false);


		// force pk[0..32] as 0 to simulate Fuzz test
		let corrupted = &mut [0u8; 64];
		let mut i = 32;
		for elem in corrupted[32..].iter_mut() {
			*elem = pk.0[i];
			i += 1;
		}
		let corrupted_pk: PublicKey = PublicKey {
			0: ffi::PublicKey(*corrupted),
		};
		println!(
			"Verifying aggsig single: {:?}, msg: {:?}, pk:{:?}",
			sig, msg, corrupted_pk
		);
		let result = verify_single(&secp, &sig, &msg, None, &corrupted_pk, &pk, None, false).unwrap();
		println!("Signature verification single (correct): {}", result);
		assert!(result == false);

		// more tests on other parameters
		let zero_pk = PublicKey::blank();
		let result = verify_single(
			&secp,
			&sig,
			&msg,
			Some(&zero_pk),
			&zero_pk,
			&zero_pk,
			Some(&zero_pk),
			false,
		)
		.unwrap();
		assert!(result == false);

		let mut msg = [0u8; 32];
		SysRng.try_fill_bytes(&mut msg).unwrap();
		let msg = Message::from_slice(&msg).unwrap();
		if sign_single(
			&secp,
			&msg,
			&sk,
			None,
			None,
			Some(&zero_pk),
			&zero_pk,
			None,
		).is_ok()
		{
			panic!("sign_single should fail on zero public key, but not!");
		}
	}

	#[test]
	fn test_secp_cap() {
		let secp_none = Secp256k1::with_caps(ContextFlag::None).unwrap();
		let secp_sign_only = Secp256k1::with_caps(ContextFlag::SignOnly).unwrap();
		let secp_verify_only = Secp256k1::with_caps(ContextFlag::VerifyOnly).unwrap();
		let secp_full = Secp256k1::with_caps(ContextFlag::Full).unwrap();
		let secp_commit = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		assert!(export_secnonce_single(&secp_none).is_err());
		assert!(export_secnonce_single(&secp_sign_only).is_ok());
		assert!(export_secnonce_single(&secp_verify_only).is_err());
		assert!(export_secnonce_single(&secp_full).is_ok());
		assert!(export_secnonce_single(&secp_commit).is_ok());

		let mut msg = [0u8; 32];
		SysRng.try_fill_bytes(&mut msg).unwrap();
		let msg = Message::from_slice(&msg).unwrap();

		let (sk1, _pk1) = secp_full.generate_keypair(&mut SysRng).unwrap();
		let (_sk2, pk2) = secp_full.generate_keypair(&mut SysRng).unwrap();

		let secnonce_1 = export_secnonce_single(&secp_full).unwrap();
		let secnonce_2 = export_secnonce_single(&secp_full).unwrap();

		let _ = PublicKey::from_secret_key(&secp_full, &secnonce_1).unwrap();
		let pubnonce_2 = PublicKey::from_secret_key(&secp_full, &secnonce_2).unwrap();

		let mut nonce_sum = pubnonce_2.clone();
		let _ = nonce_sum.add_exp_assign(&secp_full, &secnonce_1);

		let mut pk_sum = pk2.clone();
		let _ = pk_sum.add_exp_assign(&secp_full, &sk1);

		assert!(sign_single( &secp_none, &msg, &sk1, Some(&secnonce_1), None, Some(&nonce_sum), &pk_sum, Some(&nonce_sum) ).is_err());
		assert!(sign_single( &secp_sign_only, &msg, &sk1, Some(&secnonce_1), None, Some(&nonce_sum), &pk_sum, Some(&nonce_sum) ).is_ok());
		assert!(sign_single( &secp_verify_only, &msg, &sk1, Some(&secnonce_1), None, Some(&nonce_sum), &pk_sum, Some(&nonce_sum) ).is_err());
		assert!(sign_single( &secp_full, &msg, &sk1, Some(&secnonce_1), None, Some(&nonce_sum), &pk_sum, Some(&nonce_sum) ).is_ok());
		assert!(sign_single( &secp_commit, &msg, &sk1, Some(&secnonce_1), None, Some(&nonce_sum), &pk_sum, Some(&nonce_sum) ).is_ok());


		let (sk, pk) = secp_full.generate_keypair(&mut SysRng).unwrap();
		let mut msg = [0u8; 32];
		SysRng.try_fill_bytes(&mut msg).unwrap();
		let msg = Message::from_slice(&msg).unwrap();
		let (sk_extra, pk_extra) = secp_full.generate_keypair(&mut SysRng).unwrap();
		let sig = sign_single(&secp_full, &msg, &sk, None, Some(&sk_extra), None, &pk, None).unwrap();

		assert!( verify_single(&secp_none, &sig, &msg, None, &pk, &pk, Some(&pk_extra), false).is_err());
		assert!( verify_single(&secp_sign_only, &sig, &msg, None, &pk, &pk, Some(&pk_extra), false).is_err());
		assert!( verify_single(&secp_verify_only, &sig, &msg, None, &pk, &pk, Some(&pk_extra), false).is_ok());
		assert!( verify_single(&secp_full, &sig, &msg, None, &pk, &pk, Some(&pk_extra), false).is_ok());
		assert!( verify_single(&secp_commit, &sig, &msg, None, &pk, &pk, Some(&pk_extra), false).is_ok());
	}

	#[test]
	fn test_aggsig_exchange() {
		for _ in 0..20 {
			let secp = Secp256k1::with_caps(ContextFlag::Full).unwrap();
			// Generate keys for sender, receiver
			let (sk1, pk1) = secp.generate_keypair(&mut SysRng).unwrap();
			let (sk2, pk2) = secp.generate_keypair(&mut SysRng).unwrap();

			// Generate nonces for sender, receiver
			let secnonce_1 = export_secnonce_single(&secp).unwrap();
			let secnonce_2 = export_secnonce_single(&secp).unwrap();

			// Calculate public nonces
			let _ = PublicKey::from_secret_key(&secp, &secnonce_1).unwrap();
			let pubnonce_2 = PublicKey::from_secret_key(&secp, &secnonce_2).unwrap();

			// And get the total
			let mut nonce_sum = pubnonce_2.clone();
			let _ = nonce_sum.add_exp_assign(&secp, &secnonce_1);

			// Random message
			let mut msg = [0u8; 32];
			SysRng.try_fill_bytes(&mut msg).unwrap();
			let msg = Message::from_slice(&msg).unwrap();

			// Add public keys (for storing in e)
			let mut pk_sum = pk2.clone();
			let _ = pk_sum.add_exp_assign(&secp, &sk1);

			// Receiver signs
			let sig1 = sign_single(
				&secp,
				&msg,
				&sk1,
				Some(&secnonce_1),
				None,
				Some(&nonce_sum),
				&pk_sum,
				Some(&nonce_sum)
			).unwrap();

			// Sender verifies receivers sig
			let result = verify_single(
				&secp,
				&sig1,
				&msg,
				Some(&nonce_sum),
				&pk1,
				&pk_sum,
				None,
				true,
			).unwrap();
			assert!(result == true);

			// Sender signs
			let sig2 = sign_single(
				&secp,
				&msg,
				&sk2,
				Some(&secnonce_2),
				None,
				Some(&nonce_sum),
				&pk_sum,
				Some(&nonce_sum)
			).unwrap();

			// Receiver verifies sender's sig
			let result = verify_single(
				&secp,
				&sig2,
				&msg,
				Some(&nonce_sum),
				&pk2,
				&pk_sum,
				None,
				true,
			).unwrap();
			assert!(result == true);

			let sig_vec = vec![&sig1, &sig2];
			// Receiver calculates final sig
			let final_sig = add_signatures_single(&secp, sig_vec.clone(), &nonce_sum).unwrap();

			let secp_none = Secp256k1::with_caps(ContextFlag::None).unwrap();
			let secp_sign_only = Secp256k1::with_caps(ContextFlag::SignOnly).unwrap();
			let secp_verify_only = Secp256k1::with_caps(ContextFlag::VerifyOnly).unwrap();
			let secp_full = Secp256k1::with_caps(ContextFlag::Full).unwrap();
			let secp_commit = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
			assert!(add_signatures_single(&secp_none, sig_vec.clone(), &nonce_sum).is_err());
			assert!(add_signatures_single(&secp_sign_only, sig_vec.clone(), &nonce_sum).is_ok());
			assert!(add_signatures_single(&secp_verify_only, sig_vec.clone(), &nonce_sum).is_err());
			assert!(add_signatures_single(&secp_full, sig_vec.clone(), &nonce_sum).is_ok());
			assert!(add_signatures_single(&secp_commit, sig_vec.clone(), &nonce_sum).is_ok());

			// Verification of final sig:
			let result = verify_single(
				&secp,
				&final_sig,
				&msg,
				None,
				&pk_sum,
				&pk_sum,
				None,
				false,
			).unwrap();
			assert!(result == true);

			// Subtract sig1 from final sig
			let (res_sig, res_sig_opt) = subtract_partial_signature(&secp, &final_sig, &sig1).unwrap();
			assert!(res_sig == sig2 || res_sig_opt == Some(sig2));

			// Subtract sig2 from final sig for good measure
			let (res_sig, res_sig_opt) = subtract_partial_signature(&secp, &final_sig, &sig2).unwrap();
			assert!(res_sig == sig1 || res_sig_opt == Some(sig1));
		}
	}
}
