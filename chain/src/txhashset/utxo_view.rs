// Copyright 2019 The Grin Developers
// Copyright 2024 The MWC Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Lightweight readonly view into output MMR for convenience.

use crate::error::Error;
use crate::store::Batch;
use crate::types::{
	leftover_prune_info, leftover_prune_sync_log_ok, mark_leftover_prune_recovery, CommitPos,
};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::pmmr::{self, ReadablePMMR, ReadonlyPMMR};
use mwc_core::core::{Block, BlockHeader, Inputs, Output, OutputIdentifier, Transaction};
use mwc_core::global;
use mwc_core::ser;
use mwc_crates::log::{error, info};
use mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_store::pmmr::PMMRBackend;
use std::collections::BTreeSet;
use std::sync::Mutex;

/// Readonly view of the UTXO set (based on output MMR).
pub struct UTXOView<'a> {
	header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
	output_pmmr: ReadonlyPMMR<'a, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
	rproof_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
}

/// Last full PMMR scan miss for stale output_pos recovery.
/// Tight stored-body replay retries the same commitment against the same PMMR;
/// skip repeating the ~300ms scan until HEAD/PMMR progress changes it.
struct StalePosScanMiss {
	commit: Commitment,
	mmr_size: u64,
	stale_pos: u64,
}

static LAST_STALE_POS_SCAN_MISS: Mutex<Option<StalePosScanMiss>> = Mutex::new(None);

fn stale_pos_scan_miss_cached(commit: &Commitment, mmr_size: u64, stale_pos: u64) -> bool {
	match LAST_STALE_POS_SCAN_MISS.lock() {
		Ok(guard) => match guard.as_ref() {
			Some(miss) => {
				miss.commit == *commit && miss.mmr_size == mmr_size && miss.stale_pos == stale_pos
			}
			None => false,
		},
		Err(_) => false,
	}
}

fn cache_stale_pos_scan_miss(commit: Commitment, mmr_size: u64, stale_pos: u64) {
	if let Ok(mut guard) = LAST_STALE_POS_SCAN_MISS.lock() {
		*guard = Some(StalePosScanMiss {
			commit,
			mmr_size,
			stale_pos,
		});
	}
}

fn clear_stale_pos_scan_miss(commit: &Commitment) {
	if let Ok(mut guard) = LAST_STALE_POS_SCAN_MISS.lock() {
		if guard.as_ref().map(|m| m.commit == *commit).unwrap_or(false) {
			*guard = None;
		}
	}
}

/// Leftover spent-index / prune from a HEAD reset that did not unprune.
/// `None` (index cleared by skip_start_blockchain_validation) is leftover, not proof of a spend in this PMMR.
fn leftover_spent_index_after_head(batch: &Batch<'_>, commit: &Commitment) -> Result<bool, Error> {
	let head_height = match batch.head() {
		Ok(head) => head.height,
		Err(e) if e.store_error_is_not_found() => 0,
		Err(e) => {
			return Err(Error::StoreErr(
				e,
				"leftover spent index lookup head".into(),
			));
		}
	};
	match batch.get_spent_commitments(commit) {
		Ok(Some(records)) => Ok(records
			.iter()
			.all(|record| record.spending_block.height > head_height)),
		Ok(None) => Ok(true),
		Err(e) => Err(Error::StoreErr(
			e,
			"leftover spent index lookup commitments".into(),
		)),
	}
}

fn leftover_log_height(batch: &Batch<'_>) -> u64 {
	match batch.head() {
		Ok(head) => head.height,
		_ => 0,
	}
}

/// Last known PMMR pos from a leftover spent-index row (spend height still above HEAD).
fn leftover_spent_output_pos(
	batch: &Batch<'_>,
	commit: &Commitment,
) -> Result<Option<CommitPos>, Error> {
	let head_height = match batch.head() {
		Ok(head) => head.height,
		Err(e) if e.store_error_is_not_found() => 0,
		Err(e) => {
			return Err(Error::StoreErr(
				e,
				"leftover spent pos lookup head".into(),
			));
		}
	};
	match batch.get_spent_commitments(commit) {
		Ok(Some(records))
			if !records.is_empty()
				&& records
					.iter()
					.all(|record| record.spending_block.height > head_height) =>
		{
			Ok(records.last().map(|record| record.spent_output))
		}
		Ok(_) => Ok(None),
		Err(e) => Err(Error::StoreErr(e, "leftover spent pos lookup".into())),
	}
}

impl<'a> UTXOView<'a> {
	/// Build a new UTXO view.
	pub fn new(
		header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
		output_pmmr: ReadonlyPMMR<'a, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
		rproof_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
	) -> UTXOView<'a> {
		UTXOView {
			header_pmmr,
			output_pmmr,
			rproof_pmmr,
		}
	}

	/// Validate a block against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_block(
		&self,
		block: &Block,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		self.validate_outputs(block.outputs(), batch)?;
		self.validate_inputs(&block.inputs(), batch)
	}

	/// Validate a transaction against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_tx(
		&self,
		tx: &Transaction,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		self.validate_outputs(tx.outputs(), batch)?;
		self.validate_inputs(&tx.inputs(), batch)
	}

	/// Validate candidate outputs against the current UTXO set without checking
	/// transaction inputs or kernels. No duplicate output commitments are allowed.
	pub fn validate_outputs(&self, outputs: &[Output], batch: &Batch<'_>) -> Result<(), Error> {
		let mut output_commits = BTreeSet::new();
		for output in outputs {
			if !output_commits.insert(output.commitment()) {
				return Err(Error::DuplicateCommitment(output.commitment()));
			}
			self.validate_output(output, batch)?;
		}
		Ok(())
	}

	/// Validate the provided inputs.
	/// Returns a vec of output identifiers corresponding to outputs
	/// that would be spent by the provided inputs.
	/// No duplicate input commitments or resolved output positions.
	pub fn validate_inputs(
		&self,
		inputs: &Inputs,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		let mut input_commits = BTreeSet::new();
		let mut input_pos = BTreeSet::new();
		match inputs {
			Inputs::CommitOnly(inputs) => {
				let outputs_spent: Result<Vec<_>, Error> = inputs
					.iter()
					.map(|input| {
						if !input_commits.insert(input.commitment()) {
							return Err(Error::DuplicateCommitment(input.commitment()));
						}
						self.validate_input(input.commitment(), batch)
							.and_then(|(out, pos)| {
								if !input_pos.insert(pos.pos) {
									return Err(Error::DuplicateCommitment(out.commitment()));
								}
								Ok((out, pos))
							})
					})
					.collect();
				outputs_spent
			}
			Inputs::FeaturesAndCommit(inputs) => {
				let outputs_spent: Result<Vec<_>, Error> = inputs
					.iter()
					.map(|input| {
						if !input_commits.insert(input.commitment()) {
							return Err(Error::DuplicateCommitment(input.commitment()));
						}
						self.validate_input(input.commitment(), batch)
							.and_then(|(out, pos)| {
								// Unspent output found.
								// Check input matches full output identifier.
								let input_identifier = OutputIdentifier::from(input);
								if ser::hashes_equal(
									batch.get_context_id(),
									&out,
									&input_identifier,
								)? {
									if !input_pos.insert(pos.pos) {
										return Err(Error::DuplicateCommitment(out.commitment()));
									}
									Ok((out, pos))
								} else {
									error!("input mismatch: {:?}, {:?}, {:?}", out, pos, input);
									Err(Error::InputMismatch(input.commitment()))
								}
							})
					})
					.collect();
				outputs_spent
			}
		}
	}

	// Input is valid if it is spending an (unspent) output
	// that currently exists in the output MMR.
	// Note: We lookup by commitment. Caller must compare the full input as necessary.
	fn validate_input(
		&self,
		input: Commitment,
		batch: &Batch<'_>,
	) -> Result<(OutputIdentifier, CommitPos), Error> {
		let pos = batch.get_output_pos_height(&input)?;
		if let Some(pos1) = pos {
			let pos0 = pos1.pos.checked_sub(1).ok_or_else(|| {
				mwc_store::Error::DataOverflow(format!(
					"UTXOView::validate_input pos1.pos={}",
					pos1.pos
				))
			})?;
			match self.output_pmmr.get_data(pos0)? {
				Some(out) if out.commitment() == input => return Ok((out, pos1)),
				Some(_) | None => {
					return self.recover_stale_output_pos(input, Some(pos1), batch);
				}
			}
		}
		// Missing output_pos: a rolled-back leftover apply (or skip_start index
		// clear) can delete the row while the PMMR file still holds the leaf.
		// Do not AlreadySpent until file recovery has been tried.
		self.recover_stale_output_pos(input, None, batch)
	}

	fn recover_stale_output_pos(
		&self,
		input: Commitment,
		stale: Option<CommitPos>,
		batch: &Batch<'_>,
	) -> Result<(OutputIdentifier, CommitPos), Error> {
		let log_height = leftover_log_height(batch);
		let leftover = leftover_spent_index_after_head(batch, &input)?;
		if stale.is_none() && !leftover {
			return Err(Error::AlreadySpent(input));
		}

		if let Some(pos1) = stale {
			if leftover_prune_sync_log_ok(log_height) {
				info!(
					"output_pos stale at pos {} for commitment {:?}; looking up in current PMMR",
					pos1.pos, input
				);
			}
		}

		// O(1): leftover prune at indexed pos, leftover spent-index pos, or neither.
		// get_data is None because the leaf_set still has the future spend; the file
		// retains the leaf until compact.
		let file_pos = match stale {
			Some(pos1) => Some(pos1),
			None => leftover_spent_output_pos(batch, &input)?,
		};
		if let Some(pos1) = file_pos {
			if let Some(pos0) = pos1.pos.checked_sub(1) {
				if let Some(out) = self.output_pmmr.get_data_from_file(pos0)? {
					if out.commitment() == input && leftover {
						mark_leftover_prune_recovery();
						if stale.is_none() {
							leftover_prune_info(
								log_height,
								format_args!(
									"already-spent leftover with no output_pos; recovered from PMMR file at pos {}",
									pos1.pos
								),
							);
						} else if leftover_prune_sync_log_ok(log_height) {
							info!(
								"already-spent index leftover for commitment {:?}; treating as unspent in current PMMR",
								input
							);
						}
						return self.finish_stale_output_pos_recovery(
							input,
							out,
							pos0,
							pos1.height,
							batch,
						);
					}
				}
			}
		}

		let mmr_size = self.output_pmmr.unpruned_size();
		let miss_pos = stale.map(|p| p.pos).unwrap_or(0);
		if stale_pos_scan_miss_cached(&input, mmr_size, miss_pos) {
			if leftover_prune_sync_log_ok(log_height) {
				info!(
					"output_pos stale at pos {} for commitment {:?}; not present in current PMMR",
					miss_pos, input
				);
			}
			return Err(Error::AlreadySpent(input));
		}

		let recover_height = stale.map(|p| p.height).unwrap_or(log_height);

		if let Some((out, found_pos0)) =
			find_unspent_output_by_commitment(&self.output_pmmr, &input)?
		{
			return self.finish_stale_output_pos_recovery(
				input,
				out,
				found_pos0,
				recover_height,
				batch,
			);
		}

		// Unspent bitmap (leaf_set) can lag leftover prunes. Walk file data too.
		if leftover {
			if let Some((out, found_pos0)) = find_output_including_pruned(&self.output_pmmr, &input)?
			{
				mark_leftover_prune_recovery();
				let found_pos1 = found_pos0.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"UTXOView::recover_stale_output_pos found_pos0={}",
						found_pos0
					))
				})?;
				if stale.is_none() {
					leftover_prune_info(
						log_height,
						format_args!(
							"already-spent leftover with no output_pos; recovered from PMMR file at pos {}",
							found_pos1
						),
					);
				} else if leftover_prune_sync_log_ok(log_height) {
					info!(
						"already-spent index leftover for commitment {:?}; treating as unspent in current PMMR",
						input
					);
				}
				return self.finish_stale_output_pos_recovery(
					input,
					out,
					found_pos0,
					recover_height,
					batch,
				);
			}
		}
		cache_stale_pos_scan_miss(input, mmr_size, miss_pos);
		if leftover_prune_sync_log_ok(log_height) {
			info!(
				"output_pos stale at pos {} for commitment {:?}; not present in current PMMR",
				miss_pos, input
			);
		}
		Err(Error::AlreadySpent(input))
	}

	fn finish_stale_output_pos_recovery(
		&self,
		input: Commitment,
		out: OutputIdentifier,
		found_pos0: u64,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<(OutputIdentifier, CommitPos), Error> {
		let found_pos1 = found_pos0.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"UTXOView::recover_stale_output_pos found_pos0={}",
				found_pos0
			))
		})?;
		let recovered = CommitPos {
			pos: found_pos1,
			height,
		};
		let log_height = leftover_log_height(batch);
		match batch.save_output_pos_height(&input, recovered) {
			Ok(()) => {
				mark_leftover_prune_recovery();
				if leftover_prune_sync_log_ok(log_height) {
					info!(
						"output_pos recovered at pos {} for commitment {:?}",
						found_pos1, input
					);
				}
			}
			Err(mwc_store::Error::BatchTypeError(_)) => {
				mark_leftover_prune_recovery();
				if leftover_prune_sync_log_ok(log_height) {
					info!(
						"output_pos recovered at pos {} for commitment {:?} (index not updated, read batch)",
						found_pos1, input
					);
				}
			}
			Err(e) => {
				return Err(Error::StoreErr(e, "repair stale output_pos".into()));
			}
		}
		clear_stale_pos_scan_miss(&input);
		Ok((out, recovered))
	}

	// Output is valid if it would not result in a duplicate commitment in the output MMR.
	fn validate_output(&self, output: &Output, batch: &Batch<'_>) -> Result<(), Error> {
		let commit = output.commitment();
		match batch.get_output_pos(&commit) {
			Ok(pos0) => match self.output_pmmr.get_data(pos0)? {
				Some(out_mmr) if out_mmr.commitment() == commit => {
					return Err(Error::DuplicateCommitment(commit));
				}
				Some(_) | None => {
					let stale_pos1 = pos0.checked_add(1).ok_or_else(|| {
						Error::DataOverflow(format!(
							"UTXOView::validate_output stale pos0={}",
							pos0
						))
					})?;
					if leftover_prune_sync_log_ok(leftover_log_height(batch)) {
						info!(
							"output_pos stale at pos {} for commitment {:?}; looking up in current PMMR",
							stale_pos1, commit
						);
					}
					if find_unspent_output_by_commitment(&self.output_pmmr, &commit)?.is_some() {
						return Err(Error::DuplicateCommitment(commit));
					}
				}
			},
			Err(e) if e.store_error_is_not_found() => {}
			Err(e) => return Err(Error::StoreErr(e, "utxo view get output pos".to_string())),
		}
		Ok(())
	}

	/// Retrieves an unspent output using its PMMR position
	pub fn get_unspent_output_at(&self, pos0: u64) -> Result<Output, Error> {
		match self.output_pmmr.get_data(pos0)? {
			Some(output_id) => match self.rproof_pmmr.get_data(pos0)? {
				Some(rproof) => Ok(output_id.into_output(rproof.into())),
				None => Err(Error::RangeproofNotFound(format!("at position {}", pos0))),
			},
			None => Err(Error::OutputNotFound(format!("at position {}", pos0))),
		}
	}

	/// Verify we are not attempting to spend any coinbase outputs
	/// that have not sufficiently matured.
	pub fn verify_coinbase_maturity(
		&self,
		context_id: u32,
		inputs: &Inputs,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		let inputs = inputs.to_commit_wrappers(context_id)?;

		// Lookup the outputs being spent.
		let spent: Result<Vec<_>, _> = inputs
			.iter()
			.map(|x| self.validate_input(x.commitment(), batch))
			.collect();

		// Find the max pos of any coinbase being spent.
		let pos = spent?
			.iter()
			.filter_map(|(out, pos)| {
				if out.features.is_coinbase() {
					Some(pos.pos)
				} else {
					None
				}
			})
			.max();

		if let Some(pos) = pos {
			// If we have not yet reached 1440 blocks then
			// we can fail immediately as coinbase cannot be mature.
			if height < global::coinbase_maturity(context_id) {
				return Err(Error::ImmatureCoinbase);
			}

			// Find the "cutoff" pos in the output MMR based on the
			// header from 1,000 blocks ago.
			// Safe: height was checked against coinbase_maturity above.
			let cutoff_height = height - global::coinbase_maturity(context_id);
			let cutoff_header = self.get_header_by_height(cutoff_height, batch)?;
			let cutoff_pos = cutoff_header.output_mmr_size;

			// If any output pos exceed the cutoff_pos
			// we know they have not yet sufficiently matured.
			if pos > cutoff_pos {
				return Err(Error::ImmatureCoinbase);
			}
		}

		Ok(())
	}

	/// Get the header hash for the specified pos from the underlying MMR backend.
	fn get_header_hash(&self, pos1: u64) -> Result<Option<Hash>, Error> {
		let pos0 = pos1.checked_sub(1).ok_or_else(|| {
			Error::DataOverflow(format!("UTXOView::get_header_hash, pos1={}", pos1))
		})?;

		match self.header_pmmr.get_data(pos0)? {
			Some(header) => Ok(Some(header.hash(self.header_pmmr.get_context_id())?)),
			None => Ok(None),
		}
	}

	/// Get the header at the specified height based on the current state of the extension.
	/// Derives the MMR pos from the height (insertion index) and retrieves the header hash.
	/// Looks the header up in the db by hash.
	pub fn get_header_by_height(
		&self,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<BlockHeader, Error> {
		let pos1 = pmmr::insertion_to_pmmr_index(height)?
			.checked_add(1)
			.ok_or_else(|| {
				Error::DataOverflow(format!("UTXOView::get_header_by_height, height={}", height))
			})?;
		if let Some(hash) = self.get_header_hash(pos1)? {
			let header = batch.get_block_header(&hash)?;
			Ok(header)
		} else {
			Err(Error::Other(format!("get header for height {}", height)))
		}
	}
}

/// Scan unspent output PMMR leaves for `commit`. Used when output_pos is stale
/// after a PMMR rebuild that did not rewrite leftover index rows.
pub(crate) fn find_unspent_output_by_commitment(
	output_pmmr: &ReadonlyPMMR<'_, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
	commit: &Commitment,
) -> Result<Option<(OutputIdentifier, u64)>, Error> {
	for pos0 in output_pmmr.leaf_pos_iter()? {
		let pos0 = pos0?;
		if let Some(out) = output_pmmr.get_data(pos0)? {
			if out.commitment() == *commit {
				return Ok(Some((out, pos0)));
			}
		}
	}
	Ok(None)
}

/// Scan every leaf position, including pruned-but-not-compacted file data.
/// `leaf_pos_iter` / `get_data` skip the leaf_set; leftover prunes from a HEAD
/// reset without rewind are invisible to the unspent bitmap.
pub(crate) fn find_output_including_pruned(
	output_pmmr: &ReadonlyPMMR<'_, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
	commit: &Commitment,
) -> Result<Option<(OutputIdentifier, u64)>, Error> {
	let size = output_pmmr.unpruned_size();
	for pos0 in 0..size {
		if !pmmr::is_leaf(pos0) {
			continue;
		}
		if let Some(out) = output_pmmr.get_data_from_file(pos0)? {
			if out.commitment() == *commit {
				return Ok(Some((out, pos0)));
			}
		}
	}
	Ok(None)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::store::ChainStore;
	use mwc_core::core::pmmr::PMMR;
	use mwc_core::core::{CommitWrapper, Input, OutputFeatures, TransactionBody};
	use mwc_core::ser::ProtocolVersion;
	use mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_store::types::VariableSizeMetadataValidation;
	use std::fs;
	use std::path::Path;

	#[test]
	fn get_header_hash_rejects_zero_position() {
		let chain_dir = "target/get_header_hash_rejects_zero_position";
		let _ = fs::remove_dir_all(chain_dir);

		{
			let root = Path::new(chain_dir);
			let header_dir = root.join("header");
			let output_dir = root.join("output");
			let rproof_dir = root.join("rangeproof");
			fs::create_dir_all(&header_dir).unwrap();
			fs::create_dir_all(&output_dir).unwrap();
			fs::create_dir_all(&rproof_dir).unwrap();

			let header_backend = PMMRBackend::<BlockHeader>::new(
				&header_dir,
				false,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let output_backend = PMMRBackend::<OutputIdentifier>::new(
				&output_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let rproof_backend = PMMRBackend::<RangeProof>::new(
				&rproof_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, 0);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);

			let err = utxo.get_header_hash(0).unwrap_err();
			match err {
				Error::DataOverflow(msg) => {
					assert!(msg.contains("UTXOView::get_header_hash"), "{}", msg);
				}
				other => panic!("expected data overflow error, got {:?}", other),
			}
		}

		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_block_rejects_duplicate_output_commitments_with_distinct_identifiers() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/validate_block_rejects_duplicate_output_commitments_with_distinct_identifiers";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(42).unwrap();
		let block = Block {
			header: BlockHeader::default(0),
			body: TransactionBody {
				inputs: Inputs::default(),
				outputs: vec![
					Output::new(OutputFeatures::Plain, commit, RangeProof::zero()),
					Output::new(OutputFeatures::Coinbase, commit, RangeProof::zero()),
				],
				kernels: vec![],
			},
		};

		{
			let root = Path::new(chain_dir);
			let header_dir = root.join("header");
			let output_dir = root.join("output");
			let rproof_dir = root.join("rangeproof");
			fs::create_dir_all(&header_dir).unwrap();
			fs::create_dir_all(&output_dir).unwrap();
			fs::create_dir_all(&rproof_dir).unwrap();

			let header_backend = PMMRBackend::<BlockHeader>::new(
				&header_dir,
				false,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let output_backend = PMMRBackend::<OutputIdentifier>::new(
				&output_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let rproof_backend = PMMRBackend::<RangeProof>::new(
				&rproof_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, 0);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
			let batch = store.batch_read().unwrap();

			let err = utxo.validate_block(&block, &batch).unwrap_err();
			match err {
				Error::DuplicateCommitment(duplicate) => assert_eq!(duplicate, commit),
				other => panic!("expected duplicate commitment error, got {:?}", other),
			}
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_tx_rejects_duplicate_output_commitments_with_distinct_identifiers() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/validate_tx_rejects_duplicate_output_commitments_with_distinct_identifiers";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(42).unwrap();
		let tx = Transaction::empty()
			.with_output(
				0,
				Output::new(OutputFeatures::Plain, commit, RangeProof::zero()),
			)
			.unwrap()
			.with_output(
				0,
				Output::new(OutputFeatures::Coinbase, commit, RangeProof::zero()),
			)
			.unwrap();

		{
			let root = Path::new(chain_dir);
			let header_dir = root.join("header");
			let output_dir = root.join("output");
			let rproof_dir = root.join("rangeproof");
			fs::create_dir_all(&header_dir).unwrap();
			fs::create_dir_all(&output_dir).unwrap();
			fs::create_dir_all(&rproof_dir).unwrap();

			let header_backend = PMMRBackend::<BlockHeader>::new(
				&header_dir,
				false,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let output_backend = PMMRBackend::<OutputIdentifier>::new(
				&output_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let rproof_backend = PMMRBackend::<RangeProof>::new(
				&rproof_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, 0);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
			let batch = store.batch_read().unwrap();

			let err = utxo.validate_tx(&tx, &batch).unwrap_err();
			match err {
				Error::DuplicateCommitment(duplicate) => assert_eq!(duplicate, commit),
				other => panic!("expected duplicate commitment error, got {:?}", other),
			}
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_output_allows_create_when_output_pos_is_stale() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_output_allows_create_when_output_pos_is_stale";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(42).unwrap();
		let output = Output::new(OutputFeatures::Plain, commit, RangeProof::zero());

		{
			let root = Path::new(chain_dir);
			let header_dir = root.join("header");
			let output_dir = root.join("output");
			let rproof_dir = root.join("rangeproof");
			fs::create_dir_all(&header_dir).unwrap();
			fs::create_dir_all(&output_dir).unwrap();
			fs::create_dir_all(&rproof_dir).unwrap();

			let header_backend = PMMRBackend::<BlockHeader>::new(
				&header_dir,
				false,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let output_backend = PMMRBackend::<OutputIdentifier>::new(
				&output_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let rproof_backend = PMMRBackend::<RangeProof>::new(
				&rproof_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			{
				let batch = store.batch_write().unwrap();
				batch
					.save_output_pos_height(&commit, CommitPos { pos: 1, height: 0 })
					.unwrap();
				batch.commit().unwrap();
			}

			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, 0);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
			let batch = store.batch_read().unwrap();

			utxo.validate_output(&output, &batch).expect(
				"stale output_pos must not block creating an output missing from the current PMMR",
			);
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_input_recovers_stale_output_pos_from_current_pmmr() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_input_recovers_stale_output_pos_from_current_pmmr";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(42).unwrap();

		{
			let root = Path::new(chain_dir);
			let header_dir = root.join("header");
			let output_dir = root.join("output");
			let rproof_dir = root.join("rangeproof");
			fs::create_dir_all(&header_dir).unwrap();
			fs::create_dir_all(&output_dir).unwrap();
			fs::create_dir_all(&rproof_dir).unwrap();

			let header_backend = PMMRBackend::<BlockHeader>::new(
				&header_dir,
				false,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let mut output_backend = PMMRBackend::<OutputIdentifier>::new(
				&output_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let rproof_backend = PMMRBackend::<RangeProof>::new(
				&rproof_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			let output = OutputIdentifier::new(OutputFeatures::Plain, &commit);
			let output_size = {
				let mut output_pmmr = PMMR::at(&mut output_backend, 0);
				assert_eq!(output_pmmr.push(&output).unwrap(), 0);
				output_pmmr.size()
			};

			{
				let batch = store.batch_write().unwrap();
				batch
					.save_output_pos_height(
						&commit,
						CommitPos {
							pos: 938305,
							height: 7,
						},
					)
					.unwrap();
				batch.commit().unwrap();
			}

			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, output_size);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
			let batch = store.batch_read().unwrap();

			let (out, pos) = utxo.validate_input(commit, &batch).unwrap();
			assert_eq!(out.commitment(), commit);
			assert_eq!(pos.pos, 1);
			assert_eq!(pos.height, 7);
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_input_treats_stale_output_pos_absent_from_pmmr_as_spent() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_input_treats_stale_output_pos_absent_from_pmmr_as_spent";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(42).unwrap();

		{
			let root = Path::new(chain_dir);
			let header_dir = root.join("header");
			let output_dir = root.join("output");
			let rproof_dir = root.join("rangeproof");
			fs::create_dir_all(&header_dir).unwrap();
			fs::create_dir_all(&output_dir).unwrap();
			fs::create_dir_all(&rproof_dir).unwrap();

			let header_backend = PMMRBackend::<BlockHeader>::new(
				&header_dir,
				false,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let output_backend = PMMRBackend::<OutputIdentifier>::new(
				&output_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let rproof_backend = PMMRBackend::<RangeProof>::new(
				&rproof_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			{
				let batch = store.batch_write().unwrap();
				batch
					.save_output_pos_height(
						&commit,
						CommitPos {
							pos: 938305,
							height: 7,
						},
					)
					.unwrap();
				batch.commit().unwrap();
			}

			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, 0);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
			let batch = store.batch_read().unwrap();

			let err = utxo.validate_input(commit, &batch).unwrap_err();
			match err {
				Error::AlreadySpent(spent) => assert_eq!(spent, commit),
				other => panic!("expected AlreadySpent, got {:?}", other),
			}
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	fn leftover_prune_fixture(
		chain_dir: &str,
		store: &ChainStore,
		commit: Commitment,
		indexed_pos: u64,
	) -> (
		PMMRBackend<BlockHeader>,
		PMMRBackend<OutputIdentifier>,
		PMMRBackend<RangeProof>,
		u64,
	) {
		let root = Path::new(chain_dir);
		let header_dir = root.join("header");
		let output_dir = root.join("output");
		let rproof_dir = root.join("rangeproof");
		fs::create_dir_all(&header_dir).unwrap();
		fs::create_dir_all(&output_dir).unwrap();
		fs::create_dir_all(&rproof_dir).unwrap();

		let header_backend = PMMRBackend::<BlockHeader>::new(
			&header_dir,
			false,
			ProtocolVersion(2),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let mut output_backend = PMMRBackend::<OutputIdentifier>::new(
			&output_dir,
			true,
			ProtocolVersion(2),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let rproof_backend = PMMRBackend::<RangeProof>::new(
			&rproof_dir,
			true,
			ProtocolVersion(2),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let output = OutputIdentifier::new(OutputFeatures::Plain, &commit);
		let output_size = {
			let mut output_pmmr = PMMR::at(&mut output_backend, 0);
			assert_eq!(output_pmmr.push(&output).unwrap(), 0);
			assert!(output_pmmr.prune(0).unwrap());
			output_pmmr.size()
		};

		{
			let batch = store.batch_write().unwrap();
			batch
				.save_output_pos_height(
					&commit,
					CommitPos {
						pos: indexed_pos,
						height: 7,
					},
				)
				.unwrap();
			batch.commit().unwrap();
		}

		(header_backend, output_backend, rproof_backend, output_size)
	}

	#[test]
	fn validate_input_recovers_leftover_prune_at_indexed_pos() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_input_recovers_leftover_prune_at_indexed_pos";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(42).unwrap();

		{
			let (header_backend, output_backend, rproof_backend, output_size) =
				leftover_prune_fixture(chain_dir, &store, commit, 1);
			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, output_size);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
			let batch = store.batch_read().unwrap();

			let (out, pos) = utxo.validate_input(commit, &batch).unwrap();
			assert_eq!(out.commitment(), commit);
			assert_eq!(pos.pos, 1);
			assert_eq!(pos.height, 7);
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_input_recovers_leftover_prune_when_indexed_pos_is_wrong() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_input_recovers_leftover_prune_when_indexed_pos_is_wrong";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(42).unwrap();

		{
			let (header_backend, output_backend, rproof_backend, output_size) =
				leftover_prune_fixture(chain_dir, &store, commit, 938305);
			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, output_size);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
			let batch = store.batch_read().unwrap();

			let (out, pos) = utxo.validate_input(commit, &batch).unwrap();
			assert_eq!(out.commitment(), commit);
			assert_eq!(pos.pos, 1);
			assert_eq!(pos.height, 7);
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_input_recovers_leftover_prune_with_no_output_pos() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_input_recovers_leftover_prune_with_no_output_pos";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(42).unwrap();

		{
			let (header_backend, output_backend, rproof_backend, output_size) =
				leftover_prune_fixture(chain_dir, &store, commit, 1);
			{
				let batch = store.batch_write().unwrap();
				batch.delete_output_pos_height(&commit).unwrap();
				batch.commit().unwrap();
			}
			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, output_size);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
			let batch = store.batch_read().unwrap();

			let (out, pos) = utxo.validate_input(commit, &batch).unwrap();
			assert_eq!(out.commitment(), commit);
			assert_eq!(pos.pos, 1);
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_inputs_rejects_duplicate_input_commitments() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_inputs_rejects_duplicate_input_commitments";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(42).unwrap();

		{
			let root = Path::new(chain_dir);
			let header_dir = root.join("header");
			let output_dir = root.join("output");
			let rproof_dir = root.join("rangeproof");
			fs::create_dir_all(&header_dir).unwrap();
			fs::create_dir_all(&output_dir).unwrap();
			fs::create_dir_all(&rproof_dir).unwrap();

			let header_backend = PMMRBackend::<BlockHeader>::new(
				&header_dir,
				false,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let mut output_backend = PMMRBackend::<OutputIdentifier>::new(
				&output_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let rproof_backend = PMMRBackend::<RangeProof>::new(
				&rproof_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			let output = OutputIdentifier::new(OutputFeatures::Plain, &commit);
			let output_size = {
				let mut output_pmmr = PMMR::at(&mut output_backend, 0);
				assert_eq!(output_pmmr.push(&output).unwrap(), 0);
				output_pmmr.size()
			};

			{
				let batch = store.batch_write().unwrap();
				batch
					.save_output_pos_height(&commit, CommitPos { pos: 1, height: 0 })
					.unwrap();
				batch.commit().unwrap();
			}

			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, output_size);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
			let batch = store.batch_read().unwrap();

			let input = Input::new(OutputFeatures::Plain, commit);
			let inputs = Inputs::FeaturesAndCommit(vec![input, input]);
			let err = utxo.validate_inputs(&inputs, &batch).unwrap_err();
			match err {
				Error::DuplicateCommitment(duplicate) => assert_eq!(duplicate, commit),
				other => panic!("expected duplicate commitment error, got {:?}", other),
			}

			let input = CommitWrapper::from(commit);
			let inputs = Inputs::CommitOnly(vec![input, input]);
			let err = utxo.validate_inputs(&inputs, &batch).unwrap_err();
			match err {
				Error::DuplicateCommitment(duplicate) => assert_eq!(duplicate, commit),
				other => panic!("expected duplicate commitment error, got {:?}", other),
			}
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_inputs_classifies_feature_mismatch_as_bad_data() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_inputs_classifies_feature_mismatch_as_bad_data";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(42).unwrap();

		{
			let root = Path::new(chain_dir);
			let header_dir = root.join("header");
			let output_dir = root.join("output");
			let rproof_dir = root.join("rangeproof");
			fs::create_dir_all(&header_dir).unwrap();
			fs::create_dir_all(&output_dir).unwrap();
			fs::create_dir_all(&rproof_dir).unwrap();

			let header_backend = PMMRBackend::<BlockHeader>::new(
				&header_dir,
				false,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let mut output_backend = PMMRBackend::<OutputIdentifier>::new(
				&output_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			let rproof_backend = PMMRBackend::<RangeProof>::new(
				&rproof_dir,
				true,
				ProtocolVersion(2),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			let output = OutputIdentifier::new(OutputFeatures::Plain, &commit);
			let output_size = {
				let mut output_pmmr = PMMR::at(&mut output_backend, 0);
				assert_eq!(output_pmmr.push(&output).unwrap(), 0);
				output_pmmr.size()
			};

			{
				let batch = store.batch_write().unwrap();
				batch
					.save_output_pos_height(&commit, CommitPos { pos: 1, height: 0 })
					.unwrap();
				batch.commit().unwrap();
			}

			let header_pmmr = ReadonlyPMMR::at(&header_backend, 0);
			let output_pmmr = ReadonlyPMMR::at(&output_backend, output_size);
			let rproof_pmmr = ReadonlyPMMR::at(&rproof_backend, 0);
			let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
			let batch = store.batch_read().unwrap();
			let inputs =
				Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Coinbase, commit)]);

			let err = utxo.validate_inputs(&inputs, &batch).unwrap_err();
			match &err {
				Error::InputMismatch(mismatch) => assert_eq!(*mismatch, commit),
				other => panic!("expected input mismatch error, got {:?}", other),
			}
			assert!(err.is_bad_data(), "{:?}", err);
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}
}
