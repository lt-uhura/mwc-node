// Copyright 2019 The Grin Developers
// Copyright 2024 The MWC Developers
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

//! Common storage-related types
use mwc_crates::memmap2;
use mwc_crates::tempfile::tempfile;

use crate::{open_existing_regular_file, open_regular_file, sync_parent_dir};
use mwc_core::ser::{
	self, BinWriter, ProtocolVersion, Readable, Reader, StreamingReader, Writeable, Writer,
};
use mwc_crates::log::debug;
use mwc_crates::parking_lot::Mutex;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, ErrorKind, Seek, SeekFrom, Write};
use std::marker;
#[cfg(unix)]
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

// A single read-ahead page per file, independent of archive or session size.
// Large records bypass this cache. The OS supplies its own reclaimable file cache.
const READ_CACHE_BYTES: usize = 16 * 1024;

#[derive(Default)]
struct ReadCache {
	offset: u64,
	bytes: Vec<u8>,
}

fn ser_error_to_io(context: &str, err: ser::Error) -> io::Error {
	io::Error::new(io::ErrorKind::Other, format!("{}, {}", context, err))
}

fn validate_append_only_path(path: &Path) -> io::Result<()> {
	if path
		.extension()
		.and_then(|ext| ext.to_str())
		.map(|ext| ext.eq_ignore_ascii_case("tmp"))
		.unwrap_or(false)
	{
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!(
				"append-only file path must not use the reserved .tmp extension: {}",
				path.display()
			),
		));
	}
	Ok(())
}

fn paths_alias_existing_file(left: &Path, right: &Path) -> io::Result<bool> {
	if left == right {
		return Ok(true);
	}

	match mwc_crates::same_file::is_same_file(left, right) {
		Ok(alias) => Ok(alias),
		Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
		Err(e) => Err(e),
	}
}

fn open_existing_or_create_regular_file<F>(
	path: &Path,
	configure_options: F,
) -> io::Result<(File, bool)>
where
	F: Fn(&mut OpenOptions),
{
	let mut options = OpenOptions::new();
	configure_options(&mut options);
	match open_regular_file(path, &mut options) {
		Ok(file) => Ok((file, false)),
		Err(e) if e.kind() == ErrorKind::NotFound => {
			let mut options = OpenOptions::new();
			configure_options(&mut options);
			options.create_new(true);
			match open_regular_file(path, &mut options) {
				Ok(file) => Ok((file, true)),
				Err(e) if e.kind() == ErrorKind::AlreadyExists => {
					let mut options = OpenOptions::new();
					configure_options(&mut options);
					open_regular_file(path, &mut options).map(|file| (file, false))
				}
				Err(e) => Err(e),
			}
		}
		Err(e) => Err(e),
	}
}

fn fixed_size_elmts(byte_len: u64, elmt_size: u16, context: &str) -> io::Result<u64> {
	if elmt_size == 0 {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!("{} has zero-sized fixed elements", context),
		));
	}
	let elmt_size = elmt_size as u64;
	if byte_len % elmt_size != 0 {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			format!(
				"{} byte length is not aligned to fixed element size: byte_len={}, elmt_size={}",
				context, byte_len, elmt_size
			),
		));
	}
	Ok(byte_len / elmt_size)
}

/// Represents a single entry in the size_file.
/// Offset (in bytes) and size (in bytes) of a variable sized entry
/// in the corresponding data_file.
/// i.e. To read a single entry from the data_file at position p, read
/// the entry in the size_file to obtain the offset (and size) and then
/// read those bytes from the data_file.
#[derive(Clone, Debug)]
pub struct SizeEntry {
	/// Offset (bytes) in the corresponding data_file.
	pub offset: u64,
	/// Size (bytes) in the corresponding data_file.
	pub size: u16,
}

impl SizeEntry {
	/// Length of a size entry (8 + 2 bytes) for convenience.
	pub const LEN: u16 = 8 + 2;
}

impl Readable for SizeEntry {
	fn read<R: Reader>(reader: &mut R) -> Result<SizeEntry, ser::Error> {
		Ok(SizeEntry {
			offset: reader.read_u64()?,
			size: reader.read_u16()?,
		})
	}
}

impl Writeable for SizeEntry {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u64(self.offset)?;
		writer.write_u16(self.size)?;
		Ok(())
	}
}

/// Are we dealing with "fixed size" data or "variable size" data in a data file?
pub enum SizeInfo {
	/// Fixed size data.
	FixedSize(u16),
	/// Variable size data.
	VariableSize(Box<AppendOnlyFile<SizeEntry>>),
}

/// Validation level for variable-size append-only metadata on open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VariableSizeMetadataValidation {
	/// Fully deserialize the data file and compare every generated size entry.
	Full,
	/// Validate the existing size file structurally, without deserializing data.
	/// This is intended for trusted, locally maintained PMMR files on startup.
	Fast,
}

/// Data file (MMR) wrapper around an append-only file.
pub struct DataFile<T> {
	file: AppendOnlyFile<T>,
}

impl<T> DataFile<T>
where
	T: Readable + Writeable + Debug,
{
	/// Open (or create) a file at the provided path on disk.
	pub fn open<P>(
		path: P,
		size_info: SizeInfo,
		version: ProtocolVersion,
		context_id: u32,
		metadata_validation: VariableSizeMetadataValidation,
	) -> io::Result<DataFile<T>>
	where
		P: AsRef<Path> + Debug,
	{
		Ok(DataFile {
			file: AppendOnlyFile::open(path, size_info, version, context_id, metadata_validation)?,
		})
	}

	/// Append an element to the file.
	/// Will not be written to disk until flush() is subsequently called.
	/// Alternatively discard() may be called to discard any pending changes.
	pub fn append(&mut self, data: &T) -> io::Result<u64> {
		self.file.append_elmt(data)?;
		self.size_unsync()
	}

	/// Append a slice of multiple elements to the file.
	/// Will not be written to disk until flush() is subsequently called.
	/// Alternatively discard() may be called to discard any pending changes.
	pub fn extend_from_slice(&mut self, data: &[T]) -> io::Result<u64> {
		self.file.append_elmts(data)?;
		self.size_unsync()
	}

	/// Read an element from the file by position.
	/// Assumes we have already "shifted" the position to account for pruned data.
	/// Note: PMMR API is 1-indexed, but backend storage is 0-indexed.
	///
	/// Makes no assumptions about the size of the elements in bytes.
	/// Elements can be of variable size (handled internally in the append-only file impl).
	///
	pub fn read(&self, position: u64) -> io::Result<Option<T>> {
		let pos = position.checked_sub(1).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::InvalidInput,
				"DataFile positions are 1-indexed",
			)
		})?;
		self.file.read_optional_as_elmt(pos)
	}

	/// Rewind the backend file to the specified position.
	pub fn rewind(&mut self, position: u64) -> io::Result<()> {
		self.file.rewind(position)
	}

	/// Truncate unsynced appended elements back to the specified position.
	pub(crate) fn truncate_unsynced(&mut self, position: u64) -> io::Result<()> {
		self.file.truncate_unsynced(position)
	}

	/// Flush unsynced changes to the file to disk.
	pub fn flush(&mut self) -> io::Result<()> {
		self.file.flush()
	}

	/// Discard any unsynced changes to the file.
	pub fn discard(&mut self) {
		self.file.discard()
	}

	/// Size of the file in number of elements (not bytes).
	pub fn size(&self) -> io::Result<u64> {
		self.file.size_in_elmts()
	}

	/// Size of the unsync'd file, in elements (not bytes).
	pub(crate) fn size_unsync(&self) -> io::Result<u64> {
		self.file.size_unsync_in_elmts()
	}

	/// Path of the underlying file
	pub fn path(&self) -> &Path {
		self.file.path()
	}

	/// Drop underlying file handles
	pub fn release(&mut self) {
		self.file.release();
	}

	/// Write the file out to disk, pruning removed elements.
	pub fn write_tmp_pruned(&self, prune_pos: &[u64]) -> io::Result<()> {
		// Need to convert from 1-index to 0-index (don't ask).
		let prune_idx = prune_pos
			.iter()
			.map(|&x| {
				x.checked_sub(1).ok_or_else(|| {
					io::Error::new(
						io::ErrorKind::InvalidInput,
						"prune position must be 1-based and nonzero",
					)
				})
			})
			.collect::<io::Result<Vec<_>>>()?;
		self.file.write_tmp_pruned(prune_idx.as_slice())
	}

	/// Replace with file at tmp path.
	/// Rebuild and initialize from new file.
	pub fn replace_with_tmp(&mut self) -> io::Result<()> {
		self.file.replace_with_tmp()
	}
}

/// Wrapper for a file that can be read at any position (random read) but for
/// which writes are append only. Reads are backed by a memory map (mmap(2)),
/// relying on the operating system for fast access and caching. The memory
/// map is reallocated to expand it when new writes are flushed.
///
/// Despite being append-only, the file can still be pruned and truncated. The
/// former simply happens by rewriting it, ignoring some of the data. The
/// latter by truncating the underlying file and re-creating the mmap.
pub struct AppendOnlyFile<T> {
	path: PathBuf,
	file: Option<File>,
	size_info: SizeInfo,
	version: ProtocolVersion,
	context_id: u32,
	mmap: Option<memmap2::Mmap>,

	// Buffer of unsync'd bytes. These bytes will be appended to the file when flushed.
	buffer: Vec<u8>,
	buffer_start_pos: u64,
	buffer_start_pos_bak: Option<u64>,
	// iOS uses positional I/O so file growth and rewinds never remap live memory.
	positional_io: bool,
	read_cache: Mutex<ReadCache>,
	parent_dir_needs_sync: bool,
	_marker: marker::PhantomData<T>,
}

impl<T> AppendOnlyFile<T>
where
	T: Debug + Readable + Writeable,
{
	/// Open a file (existing or not) with buffered appends and platform-specific reads.
	pub fn open<P>(
		path: P,
		size_info: SizeInfo,
		version: ProtocolVersion,
		context_id: u32,
		metadata_validation: VariableSizeMetadataValidation,
	) -> io::Result<AppendOnlyFile<T>>
	where
		P: AsRef<Path> + Debug,
	{
		let path = path.as_ref();
		validate_append_only_path(path)?;

		if let SizeInfo::VariableSize(size_file) = &size_info {
			if paths_alias_existing_file(size_file.path.as_path(), path)? {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					format!(
						"same path or backing file for data and size file: data={}, size={}",
						path.display(),
						size_file.path.display()
					),
				));
			}
			if size_file.has_unsynced_state() {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					format!(
						"cannot open variable-size append-only file {} with unsynced size file state in {}",
						path.display(),
						size_file.path.display()
					),
				));
			}
		}

		let mut aof = AppendOnlyFile {
			file: None,
			path: path.to_path_buf(),
			size_info,
			version,
			context_id,
			mmap: None,
			buffer: vec![],
			buffer_start_pos: 0,
			buffer_start_pos_bak: None,
			positional_io: cfg!(any(target_os = "ios", feature = "test-ios-storage")),
			read_cache: Mutex::new(ReadCache::default()),
			parent_dir_needs_sync: false,
			_marker: marker::PhantomData,
		};
		aof.init()?;

		// (Re)build the size file if inconsistent with the data file.
		// This will occur during "fast sync" as we do not sync the size_file
		// and must build it locally.
		// And we can *only* do this after init() the data file (so we know sizes).
		if let SizeInfo::VariableSize(_) = &aof.size_info {
			let metadata_matches = match metadata_validation {
				VariableSizeMetadataValidation::Full => {
					aof.variable_size_metadata_matches_data()?
				}
				VariableSizeMetadataValidation::Fast => {
					aof.variable_size_metadata_offsets_cover_data()?
				}
			};
			if !metadata_matches {
				aof.rebuild_size_file()?;

				// (Re)init the entire file as we just rebuilt the size_file
				// and things may have changed.
				aof.init()?;
			}
		}

		Ok(aof)
	}

	/// (Re)init an underlying file and its associated memmap.
	/// Taking care to initialize the mmap_offset_cache for each element.
	pub fn init(&mut self) -> io::Result<()> {
		if let SizeInfo::VariableSize(ref mut size_file) = self.size_info {
			size_file.init()?;
		}

		let (file, created) = open_existing_or_create_regular_file(&self.path, |options| {
			options.read(true).write(true);
		})?;
		self.parent_dir_needs_sync |= created;

		self.mmap = None;
		*self.read_cache.get_mut() = ReadCache::default();
		let file_len = file.metadata()?.len();
		if file_len == 0 {
			self.buffer_start_pos = 0;
		} else {
			if !self.positional_io {
				self.mmap = Some(Self::map_file(&file)?);
			}
			self.buffer_start_pos = self.size_in_elmts()?;
		}
		self.file = Some(file);

		Ok(())
	}

	fn size_in_elmts(&self) -> io::Result<u64> {
		match self.size_info {
			SizeInfo::FixedSize(elmt_size) => {
				fixed_size_elmts(self.size()?, elmt_size, "append-only file")
			}
			SizeInfo::VariableSize(ref size_file) => size_file.size_in_elmts(),
		}
	}

	fn size_unsync_in_elmts(&self) -> io::Result<u64> {
		match self.size_info {
			SizeInfo::FixedSize(elmt_size) => {
				let elem_idx =
					fixed_size_elmts(self.buffer.len() as u64, elmt_size, "append-only buffer")?;
				let pos = self.buffer_start_pos.checked_add(elem_idx).ok_or_else(|| {
					io::Error::new(
						ErrorKind::Other,
						format!(
							"size_unsync_in_elmts data overflow buffer_start_pos={} elem_idx={}",
							self.buffer_start_pos, elem_idx
						),
					)
				})?;
				Ok(pos)
			}
			SizeInfo::VariableSize(ref size_file) => size_file.size_unsync_in_elmts(),
		}
	}

	/// Append element to append-only file by serializing it to bytes and appending the bytes.
	fn append_elmt(&mut self, data: &T) -> io::Result<()> {
		let mut bytes = ser::ser_vec(self.context_id, data, self.version)
			.map_err(|e| ser_error_to_io("Fail to append data", e))?;
		self.validate_serialized_elmt_size(bytes.len())?;
		self.append(&mut bytes)?;
		Ok(())
	}

	fn validate_serialized_elmt_size(&self, byte_len: usize) -> io::Result<()> {
		if let SizeInfo::FixedSize(elmt_size) = &self.size_info {
			let expected = usize::from(*elmt_size);
			if byte_len != expected {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					format!(
						"fixed-size append serialized {} bytes, expected {} bytes",
						byte_len, expected
					),
				));
			}
		}
		Ok(())
	}

	/// Validate variable-size metadata by rebuilding the expected metadata from
	/// the data file itself.
	///
	/// This is the full validation path. It deserializes each element from the
	/// data file with `T::read`, tracks how many bytes each element consumed, and
	/// compares every generated `(offset, size)` pair with the corresponding
	/// `SizeEntry` in the size file. It also verifies that the size file has no
	/// extra entries after the data file is fully consumed.
	///
	/// Because this reads and deserializes the entire data file, it can detect
	/// metadata that is structurally contiguous but does not match the actual
	/// serialization boundaries of `T`. It is also the more expensive startup
	/// check.
	fn variable_size_metadata_matches_data(&self) -> io::Result<bool> {
		let size_file = match &self.size_info {
			SizeInfo::VariableSize(size_file) => size_file,
			SizeInfo::FixedSize(_) => return Ok(true),
		};

		let reader = open_existing_regular_file(&self.path)?;
		let file_len = reader.metadata()?.len();
		let mut buf_reader = BufReader::new(reader);
		let mut streaming_reader =
			StreamingReader::new(&mut buf_reader, self.version, self.context_id);

		let mut pos = 0u64;
		let mut current_offset = 0u64;
		while streaming_reader.total_bytes_read() < file_len {
			T::read(&mut streaming_reader).map_err(|e| {
				ser_error_to_io("Fail to read while validating variable-size file", e)
			})?;
			let bytes_read = streaming_reader.total_bytes_read();
			let size = bytes_read.checked_sub(current_offset).ok_or_else(|| {
				io::Error::new(
					io::ErrorKind::InvalidData,
					format!(
						"variable-size validation offset moved backwards: bytes_read={}, current_offset={}",
						bytes_read, current_offset
					),
				)
			})?;
			if size == 0 {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					format!(
						"variable-size validation read zero bytes at offset {}",
						current_offset
					),
				));
			}
			let size = u16::try_from(size).map_err(|_| {
				io::Error::new(
					io::ErrorKind::Other,
					format!(
						"DataOverflow, AppendOnlyFile::variable_size_metadata_matches_data, size={}",
						size
					),
				)
			})?;

			match size_file.read_optional_as_elmt(pos)? {
				Some(entry) if entry.offset == current_offset && entry.size == size => {}
				_ => return Ok(false),
			}

			current_offset = bytes_read;
			pos = pos.checked_add(1).ok_or_else(|| {
				io::Error::new(
					io::ErrorKind::Other,
					format!(
						"DataOverflow, AppendOnlyFile::variable_size_metadata_matches_data, pos={}",
						pos
					),
				)
			})?;
		}

		Ok(pos == size_file.size_in_elmts()?)
	}

	/// Validate variable-size metadata structurally without deserializing the
	/// data file.
	///
	/// This is the fast validation path. It checks only that the size file
	/// entries form a contiguous byte range starting at offset 0, that every
	/// entry has a non-zero size, that no entry runs past the data file length,
	/// and that the final covered offset is exactly the data file length.
	///
	/// This proves the existing offsets cover the bytes on disk, but it does not
	/// prove those offsets are the same boundaries that `T::read` would produce.
	/// Use this only when the data and size files are trusted to have been
	/// maintained together locally.
	fn variable_size_metadata_offsets_cover_data(&self) -> io::Result<bool> {
		let size_file = match &self.size_info {
			SizeInfo::VariableSize(size_file) => size_file,
			SizeInfo::FixedSize(_) => return Ok(true),
		};

		let reader = open_existing_regular_file(&self.path)?;
		let file_len = reader.metadata()?.len();
		let entry_count = size_file.size_in_elmts()?;
		if file_len == 0 {
			return Ok(entry_count == 0);
		}
		if entry_count == 0 {
			return Ok(false);
		}

		let mut expected_offset = 0u64;
		for pos in 0..entry_count {
			let entry = size_file.read_as_elmt(pos)?;
			if entry.offset != expected_offset || entry.size == 0 {
				return Ok(false);
			}
			expected_offset = entry.offset.checked_add(entry.size as u64).ok_or_else(|| {
				io::Error::new(
					io::ErrorKind::Other,
					format!(
						"DataOverflow, AppendOnlyFile::variable_size_metadata_offsets_cover_data, offset={} size={}",
						entry.offset, entry.size
					),
				)
			})?;
			if expected_offset > file_len {
				return Ok(false);
			}
		}

		Ok(expected_offset == file_len)
	}

	/// Iterate over the slice and append each element.
	fn append_elmts(&mut self, data: &[T]) -> io::Result<()> {
		for x in data {
			self.append_elmt(x)?;
		}
		Ok(())
	}

	/// Append data to the file. Until the append-only file is synced, data is
	/// only written to memory.
	pub fn append(&mut self, bytes: &mut [u8]) -> io::Result<()> {
		match &mut self.size_info {
			SizeInfo::FixedSize(elmt_size) => {
				if *elmt_size == 0 {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"fixed-size append has zero-sized elements",
					));
				}
				if bytes.len() % usize::from(*elmt_size) != 0 {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						format!(
							"fixed-size append {} bytes not aligned to element size {}",
							bytes.len(),
							elmt_size
						),
					));
				}
			}
			SizeInfo::VariableSize(size_file) => {
				if bytes.is_empty() {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"variable-size append cannot be empty",
					));
				}
				let size = u16::try_from(bytes.len()).map_err(|_| {
					io::Error::new(
						io::ErrorKind::InvalidData,
						format!("variable-size append too large: {} bytes", bytes.len()),
					)
				})?;
				let next_pos = size_file.size_unsync_in_elmts()?;
				let offset = if next_pos == 0 {
					0
				} else {
					let prev_entry = size_file.read_as_elmt(next_pos - 1)?;
					prev_entry
						.offset
						.checked_add(prev_entry.size as u64)
						.ok_or_else(|| {
							io::Error::new(
								io::ErrorKind::InvalidData,
								format!(
									"variable-size append offset overflow: offset={}, size={}",
									prev_entry.offset, prev_entry.size
								),
							)
						})?
				};
				size_file.append_elmt(&SizeEntry { offset, size })?;
			}
		}

		self.buffer.extend_from_slice(bytes);
		Ok(())
	}

	// Returns the offset and size of bytes to read.
	// If pos is in the buffer then caller needs to remember to account for this
	// when reading from the buffer.
	fn offset_and_size(&self, pos: u64) -> io::Result<(u64, u16)> {
		match self.size_info {
			SizeInfo::FixedSize(elmt_size) => {
				let pos = pos.checked_mul(elmt_size as u64).ok_or_else(|| {
					io::Error::new(
						ErrorKind::Other,
						format!(
							"offset_and_size data overflow pos={} elmt_size={}",
							pos, elmt_size
						),
					)
				})?;
				Ok((pos, elmt_size))
			}
			SizeInfo::VariableSize(ref size_file) => {
				// Otherwise we need to calculate offset and size from entries in the size_file.
				let entry = size_file.read_as_elmt(pos)?;
				Ok((entry.offset, entry.size))
			}
		}
	}

	/// Rewinds the data file back to a previous position.
	/// Rewinds persisted state directly, or truncates unsynced buffered state
	/// when the target position is still in the append buffer.
	pub fn rewind(&mut self, pos: u64) -> io::Result<()> {
		let current_size = self.size_unsync_in_elmts()?;
		if pos > current_size {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!(
					"cannot rewind append-only file forward from {} to {}",
					current_size, pos
				),
			));
		}
		if pos == current_size {
			return Ok(());
		}
		if pos >= self.buffer_start_pos {
			return self.truncate_unsynced(pos);
		}

		if let SizeInfo::VariableSize(size_file) = &mut self.size_info {
			size_file.rewind(pos)?;
		}

		if self.buffer_start_pos_bak.is_none() {
			self.buffer_start_pos_bak = Some(self.buffer_start_pos);
		}
		self.buffer_start_pos = pos;
		self.buffer.clear();
		Ok(())
	}

	fn truncate_unsynced(&mut self, pos: u64) -> io::Result<()> {
		let current_size = self.size_unsync_in_elmts()?;
		if pos > current_size {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!(
					"cannot truncate append-only file forward from {} to {}",
					current_size, pos
				),
			));
		}
		if pos < self.buffer_start_pos {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!(
					"cannot truncate persisted append-only file from {} to {}",
					self.buffer_start_pos, pos
				),
			));
		}

		let keep = pos.checked_sub(self.buffer_start_pos).ok_or_else(|| {
			io::Error::new(
				ErrorKind::Other,
				format!(
					"truncate_unsynced underflow pos={} buffer_start_pos={}",
					pos, self.buffer_start_pos
				),
			)
		})?;
		let new_len = self.buffer_len_for_unsynced_elmts(keep)?;
		if new_len > self.buffer.len() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!(
					"computed unsynced buffer length {} exceeds buffer length {}",
					new_len,
					self.buffer.len()
				),
			));
		}
		if let SizeInfo::VariableSize(size_file) = &mut self.size_info {
			size_file.truncate_unsynced(pos)?;
		}
		self.buffer.truncate(new_len);
		Ok(())
	}

	fn buffer_len_for_unsynced_elmts(&self, keep: u64) -> io::Result<usize> {
		let len = match self.size_info {
			SizeInfo::FixedSize(elmt_size) => {
				keep.checked_mul(elmt_size as u64).ok_or_else(|| {
					io::Error::new(
						ErrorKind::Other,
						format!(
							"buffer_len_for_unsynced_elmts overflow keep={} elmt_size={}",
							keep, elmt_size
						),
					)
				})?
			}
			SizeInfo::VariableSize(_) => {
				if keep == 0 {
					0
				} else {
					let last_pos = self
						.buffer_start_pos
						.checked_add(keep)
						.and_then(|pos| pos.checked_sub(1))
						.ok_or_else(|| {
							io::Error::new(
								ErrorKind::Other,
								format!(
									"buffer_len_for_unsynced_elmts overflow buffer_start_pos={} keep={}",
									self.buffer_start_pos, keep
								),
							)
						})?;
					let (last_offset, last_size) = self.offset_and_size(last_pos)?;
					let buffer_offset = if self.buffer_start_pos == 0 {
						0
					} else {
						let prev_pos = self.buffer_start_pos - 1;
						let (prev_offset, prev_size) = self.offset_and_size(prev_pos)?;
						prev_offset.checked_add(prev_size as u64).ok_or_else(|| {
							io::Error::new(
								ErrorKind::Other,
								format!(
									"buffer_len_for_unsynced_elmts overflow prev_offset={} prev_size={}",
									prev_offset, prev_size
								),
							)
						})?
					};
					last_offset
						.checked_add(last_size as u64)
						.and_then(|end| end.checked_sub(buffer_offset))
						.ok_or_else(|| {
							io::Error::new(
								ErrorKind::Other,
								format!(
									"buffer_len_for_unsynced_elmts invalid offsets last_offset={} last_size={} buffer_offset={}",
									last_offset, last_size, buffer_offset
								),
							)
						})?
				}
			}
		};
		usize::try_from(len).map_err(|_| {
			io::Error::new(
				ErrorKind::Other,
				format!(
					"buffer_len_for_unsynced_elmts len does not fit usize: {}",
					len
				),
			)
		})
	}

	fn buffer_start_offset(&self) -> io::Result<u64> {
		match self.size_info {
			SizeInfo::FixedSize(elmt_size) => self
				.buffer_start_pos
				.checked_mul(elmt_size as u64)
				.ok_or_else(|| {
					io::Error::new(
						ErrorKind::Other,
						format!(
							"buffer_start_offset overflow buffer_start_pos={} elmt_size={}",
							self.buffer_start_pos, elmt_size
						),
					)
				}),
			SizeInfo::VariableSize(_) => {
				if self.buffer_start_pos == 0 {
					return Ok(0);
				}
				let (offset, size) = self.offset_and_size(self.buffer_start_pos - 1)?;
				offset.checked_add(size as u64).ok_or_else(|| {
					io::Error::new(
						ErrorKind::Other,
						format!(
							"buffer_start_offset overflow offset={} size={}",
							offset, size
						),
					)
				})
			}
		}
	}

	fn map_file(file: &File) -> io::Result<memmap2::Mmap> {
		// Safety: AppendOnlyFile drops its own mmap before any internal
		// truncation or replacement, then remaps only after the mutation has
		// been fsynced. PMMR startup rejects symlink and non-regular PMMR file
		// paths before opening them. Callers must not externally mutate or
		// truncate the mapped file while this AppendOnlyFile is live.
		unsafe { memmap2::Mmap::map(file) }
	}

	fn has_unsynced_state(&self) -> bool {
		if !self.buffer.is_empty() || self.buffer_start_pos_bak.is_some() {
			return true;
		}

		match &self.size_info {
			SizeInfo::VariableSize(size_file) => size_file.has_unsynced_state(),
			SizeInfo::FixedSize(_) => false,
		}
	}

	/// Syncs all writes (fsync). Desktop refreshes the mapping; iOS invalidates
	/// its bounded positional read cache without mapping the PMMR.
	pub fn flush(&mut self) -> io::Result<()> {
		self.flush_storage()
	}

	fn flush_storage(&mut self) -> io::Result<()> {
		let mut timing = mwc_util::sync_diagnostics::Metric::PmmrFlush.start();
		let buffer_start_offset = self.buffer_start_offset()?;
		// Invalidate before mutation, including when persistence later fails.
		self.mmap = None;
		// Invalidate bytes, but retain the bounded page allocation across batches.
		// Even a failed flush must leave no readable cached bytes. init/release
		// still drop the allocation when the backing file is replaced or closed.
		self.read_cache.get_mut().bytes.clear();
		self.file = None;
		let (mut file, created) = open_existing_or_create_regular_file(&self.path, |options| {
			options.read(true).write(true);
		})?;
		self.parent_dir_needs_sync |= created;

		// Make flush retry-safe. If a previous flush wrote bytes but failed
		// before clearing the buffer, truncate back to the logical buffered
		// start before writing the buffer again.
		file.set_len(buffer_start_offset)?;
		file.seek(SeekFrom::Start(buffer_start_offset))?;
		file.write_all(&self.buffer[..])?;
		{
			let mut sync_timing = mwc_util::sync_diagnostics::Metric::PmmrFsync.start();
			file.sync_all()?;
			sync_timing.success();
		}
		if self.parent_dir_needs_sync {
			sync_parent_dir(&self.path)?;
			self.parent_dir_needs_sync = false;
		}

		if let SizeInfo::VariableSize(size_file) = &mut self.size_info {
			// Flush size metadata only after the data file is durable. If this
			// fails, a later retry will truncate and rewrite the data buffer.
			size_file.flush()?
		}

		let buffer_start_pos = self.size_in_elmts()?;
		// Note: file must be non-empty to memory map it
		if self.positional_io || file.metadata()?.len() == 0 {
			self.mmap = None;
		} else {
			self.mmap = Some(Self::map_file(&file)?);
		}

		self.buffer.clear();
		self.buffer_start_pos = buffer_start_pos;
		self.buffer_start_pos_bak = None;
		self.file = Some(file);

		timing.success();
		Ok(())
	}

	// Owned results allow bounded caching without exposing references that could
	// outlive cache replacement. Positional reads do not share a seek cursor.
	#[cfg(unix)]
	fn read_from_file(&self, offset: u64, length: u16) -> io::Result<Vec<u8>> {
		let file = self.file.as_ref().ok_or_else(|| {
			io::Error::new(
				ErrorKind::Other,
				"PMMR file is unavailable after a failed flush",
			)
		})?;
		let len = usize::from(length);
		let end = offset
			.checked_add(u64::from(length))
			.ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "PMMR read offset overflow"))?;
		let mut cache = self.read_cache.lock();
		if offset >= cache.offset && end <= cache.offset + cache.bytes.len() as u64 {
			let start = (offset - cache.offset) as usize;
			return Ok(cache.bytes[start..start + len].to_vec());
		}
		let page = offset / READ_CACHE_BYTES as u64 * READ_CACHE_BYTES as u64;
		if end - page > READ_CACHE_BYTES as u64 {
			drop(cache);
			let mut bytes = vec![0; len];
			file.read_exact_at(&mut bytes, offset)?;
			return Ok(bytes);
		}
		let file_len = file.metadata()?.len();
		if end > file_len {
			return Err(io::Error::new(ErrorKind::UnexpectedEof, "short PMMR file"));
		}
		let read_len = (file_len - page).min(READ_CACHE_BYTES as u64) as usize;
		// Publish only a complete successful read; an error leaves no stale page.
		cache.bytes.clear();
		cache.bytes.resize(read_len, 0);
		if let Err(error) = file.read_exact_at(&mut cache.bytes, page) {
			cache.bytes.clear();
			return Err(error);
		}
		cache.offset = page;
		let start = (offset - page) as usize;
		Ok(cache.bytes[start..start + len].to_vec())
	}

	#[cfg(not(unix))]
	fn read_from_file(&self, _offset: u64, _length: u16) -> io::Result<Vec<u8>> {
		Err(io::Error::new(
			ErrorKind::Unsupported,
			"positional PMMR test backend requires Unix",
		))
	}

	/// Discard the current non-flushed data.
	pub fn discard(&mut self) {
		if let Some(buffer_start_pos_bak) = self.buffer_start_pos_bak.take() {
			// discarding a rewound state, restore the buffer start
			self.buffer_start_pos = buffer_start_pos_bak;
		}

		// Discarding the data file will discard the associated size file if we have one.
		if let SizeInfo::VariableSize(size_file) = &mut self.size_info {
			size_file.discard();
		}

		self.buffer = vec![];
	}

	/// Read the bytes representing the element at the given position (0-indexed).
	/// Uses the offset cache to determine the offset to read from and the size
	/// in bytes to actually read.
	/// Borrows desktop mapped bytes or returns an owned positional read on iOS.
	pub fn read(&self, pos: u64) -> io::Result<Option<Cow<'_, [u8]>>> {
		if pos >= self.size_unsync_in_elmts()? {
			return Ok(None);
		}
		let (offset, length) = self.offset_and_size(pos)?;
		let res = if pos < self.buffer_start_pos {
			if self.positional_io {
				Cow::Owned(self.read_from_file(offset, length)?)
			} else {
				Cow::Borrowed(self.read_from_mmap(offset, length)?)
			}
		} else {
			let (buffer_offset, _) = self.offset_and_size(self.buffer_start_pos)?;
			let offset = offset.checked_sub(buffer_offset).ok_or_else(|| {
				io::Error::new(
					io::ErrorKind::InvalidData,
					format!(
						"buffer offset is before buffer start: offset={}, buffer_offset={}",
						offset, buffer_offset
					),
				)
			})?;
			Cow::Borrowed(self.read_from_buffer(offset, length)?)
		};
		Ok(Some(res))
	}

	fn read_as_elmt(&self, pos: u64) -> io::Result<T> {
		self.read_optional_as_elmt(pos)?.ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::NotFound,
				format!("no element at append-only file position {}", pos),
			)
		})
	}

	fn read_optional_as_elmt(&self, pos: u64) -> io::Result<Option<T>> {
		let data = match self.read(pos)? {
			Some(data) => data,
			None => return Ok(None),
		};
		ser::deserialize_strict(&mut &data[..], self.version, self.context_id)
			.map(Some)
			.map_err(|e| ser_error_to_io("Fail to deserialize data", e))
	}

	// Read length bytes starting at offset from the buffer.
	fn read_from_buffer(&self, offset: u64, length: u16) -> io::Result<&[u8]> {
		let start = usize::try_from(offset).map_err(|_| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				format!("buffer offset does not fit usize: {}", offset),
			)
		})?;
		let end = start.checked_add(length as usize).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				format!(
					"buffer read range overflow: offset={}, length={}",
					offset, length
				),
			)
		})?;
		self.buffer.get(start..end).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::UnexpectedEof,
				format!(
					"buffer read out of bounds: offset={}, length={}, buffer_len={}",
					offset,
					length,
					self.buffer.len()
				),
			)
		})
	}

	// Read length bytes starting at offset from the mmap.
	fn read_from_mmap(&self, offset: u64, length: u16) -> io::Result<&[u8]> {
		let mmap = self.mmap.as_ref().ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::UnexpectedEof,
				"mmap is not initialized for file-backed read",
			)
		})?;
		let start = usize::try_from(offset).map_err(|_| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				format!("mmap offset does not fit usize: {}", offset),
			)
		})?;
		let end = start.checked_add(length as usize).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				format!(
					"mmap read range overflow: offset={}, length={}",
					offset, length
				),
			)
		})?;
		mmap.get(start..end).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::UnexpectedEof,
				format!(
					"mmap read out of bounds: offset={}, length={}, mmap_len={}",
					offset,
					length,
					mmap.len()
				),
			)
		})
	}

	/// Create a new tempfile containing the contents of this append only file.
	/// This allows callers to see a consistent view of the data without
	/// locking the append only file.
	pub fn as_temp_file(&self) -> io::Result<File> {
		let mut reader = BufReader::new(open_existing_regular_file(&self.path)?);
		let mut writer = BufWriter::new(tempfile()?);
		io::copy(&mut reader, &mut writer)?;

		// Remember to seek back to start of the file as the caller is likely
		// to read this file directly without reopening it.
		writer.seek(SeekFrom::Start(0))?;

		let file = writer.into_inner()?;
		Ok(file)
	}

	fn tmp_path(&self) -> PathBuf {
		// Compaction intentionally reuses a deterministic temporary path and
		// truncates it on each attempt. This avoids accumulating orphaned temp
		// files in worst-case failure/retry scenarios.
		self.path.with_extension("tmp")
	}

	/// Saves a copy of the current file content, skipping data at the provided
	/// prune positions. prune_pos must be ordered.
	pub fn write_tmp_pruned(&self, prune_pos: &[u64]) -> io::Result<()> {
		let reader = open_existing_regular_file(&self.path)?;
		let file_len = reader.metadata()?.len();
		let mut buf_reader = BufReader::new(reader);
		let mut streaming_reader =
			StreamingReader::new(&mut buf_reader, self.version, self.context_id);

		let mut options = OpenOptions::new();
		options.write(true).create(true).truncate(true);
		let mut buf_writer = BufWriter::new(open_regular_file(&self.tmp_path(), &mut options)?);

		let mut current_pos = 0u64;
		let mut prune_pos = prune_pos;
		{
			let mut bin_writer = BinWriter::new(&mut buf_writer, self.version, self.context_id);
			while streaming_reader.total_bytes_read() < file_len {
				let bytes_before = streaming_reader.total_bytes_read();
				let elmt = T::read(&mut streaming_reader)
					.map_err(|e| ser_error_to_io("Fail to read at write_tmp_pruned", e))?;
				let bytes_read = streaming_reader.total_bytes_read();
				if bytes_read <= bytes_before {
					return Err(io::Error::new(
						io::ErrorKind::InvalidData,
						format!(
							"write_tmp_pruned read made no progress at offset {}",
							bytes_before
						),
					));
				}
				if prune_pos.first().copied() == Some(current_pos) {
					// Pruned pos, moving on.
					prune_pos = &prune_pos[1..];
				} else {
					// Not pruned, write to file.
					elmt.write(&mut bin_writer)
						.map_err(|e| ser_error_to_io("Fail to write at write_tmp_pruned", e))?;
				}
				current_pos = current_pos.checked_add(1).ok_or_else(|| {
					io::Error::new(
						io::ErrorKind::InvalidData,
						format!("write_tmp_pruned position overflow at {}", current_pos),
					)
				})?;
			}
		}
		if let Some(pos) = prune_pos.first() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!(
					"prune position {} was not found while compacting {} elements from {}",
					pos,
					current_pos,
					self.path.display()
				),
			));
		}
		buf_writer.flush()?;
		buf_writer.get_ref().sync_all()?;
		Ok(())
	}

	/// Replace the underlying file with the file at tmp path.
	/// Rebuild and initialize from the new file.
	pub fn replace_with_tmp(&mut self) -> io::Result<()> {
		if self.has_unsynced_state() {
			return Err(io::Error::new(
				io::ErrorKind::InvalidInput,
				format!(
					"cannot replace append-only file {} with unsynced state",
					self.path.display()
				),
			));
		}

		// Replace the underlying file -
		// pmmr_data.tmp -> pmmr_data.bin
		self.replace(&self.tmp_path())?;

		// Now rebuild our size file to reflect the pruned data file.
		// This will replace the underlying file internally.
		if let SizeInfo::VariableSize(_) = &self.size_info {
			self.rebuild_size_file()?;
		}

		// Now (re)init the file and associated size_file so everything is consistent.
		self.init()?;

		Ok(())
	}

	fn rebuild_size_file(&mut self) -> io::Result<()> {
		if let SizeInfo::VariableSize(size_file) = &mut self.size_info {
			// Note: Reading from data file and writing sizes to the associated (tmp) size_file.
			let tmp_path = size_file.path.with_extension("tmp");
			debug!("rebuild_size_file: {:?}", tmp_path);

			// Scope the reader and writer to within the block so we can safely replace files later on.
			{
				let reader = open_existing_regular_file(&self.path)?;
				let file_len = reader.metadata()?.len();
				let mut buf_reader = BufReader::new(reader);
				let mut streaming_reader =
					StreamingReader::new(&mut buf_reader, self.version, self.context_id);

				let mut options = OpenOptions::new();
				options.write(true).create(true).truncate(true);
				let mut buf_writer = BufWriter::new(open_regular_file(&tmp_path, &mut options)?);

				let mut current_offset = 0;
				{
					let mut bin_writer =
						BinWriter::new(&mut buf_writer, self.version, self.context_id);
					while streaming_reader.total_bytes_read() < file_len {
						T::read(&mut streaming_reader)
							.map_err(|e| ser_error_to_io("Fail to read at rebuild_size_file", e))?;
						let bytes_read = streaming_reader.total_bytes_read();
						let size = bytes_read.checked_sub(current_offset).ok_or_else(|| {
							io::Error::new(
								io::ErrorKind::InvalidData,
								format!(
									"rebuild_size_file offset moved backwards: bytes_read={}, current_offset={}",
									bytes_read, current_offset
								),
							)
						})?;
						if size == 0 {
							return Err(io::Error::new(
								io::ErrorKind::InvalidData,
								format!(
									"rebuild_size_file read zero bytes at offset {}",
									current_offset
								),
							));
						}
						let size = u16::try_from(size).map_err(|_| {
							io::Error::new(
								io::ErrorKind::Other,
								format!(
									"DataOverflow, AppendOnlyFile::rebuild_size_file, size={}",
									size
								),
							)
						})?;
						let entry = SizeEntry {
							offset: current_offset,
							size,
						};

						// Not pruned, write to file.
						entry.write(&mut bin_writer).map_err(|e| {
							ser_error_to_io("Fail to write at rebuild_size_file", e)
						})?;

						current_offset = bytes_read;
					}
				}
				buf_writer.flush()?;
				buf_writer.get_ref().sync_all()?;
			}

			// Replace the underlying file for our size_file -
			// pmmr_size.tmp -> pmmr_size.bin
			size_file.replace(&tmp_path)?;
		}

		Ok(())
	}

	/// Replace the underlying file with another file, deleting the original.
	/// Takes an optional size_file path in addition to path.
	fn replace<P>(&mut self, with: P) -> io::Result<()>
	where
		P: AsRef<Path> + Debug,
	{
		self.release();
		// Keep the legacy remove-then-rename behavior. This leaves a gap where
		// the original file is gone if rename fails, but callers currently rely
		// on this replacement path and compaction has no cross-file transaction.
		fs::remove_file(&self.path)?;
		fs::rename(with, &self.path)?;
		sync_parent_dir(&self.path)?;
		Ok(())
	}

	/// Release underlying file handles.
	pub fn release(&mut self) {
		self.mmap = None;
		self.file = None;
		*self.read_cache.get_mut() = ReadCache::default();

		// Remember to release the size_file as well if we have one.
		if let SizeInfo::VariableSize(size_file) = &mut self.size_info {
			size_file.release();
		}
	}

	/// Current size of the file in bytes.
	pub fn size(&self) -> io::Result<u64> {
		fs::metadata(&self.path).map(|md| md.len())
	}

	/// Path of the underlying file
	pub fn path(&self) -> &Path {
		&self.path
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Debug)]
	struct TestElem;

	impl Readable for TestElem {
		fn read<R: Reader>(reader: &mut R) -> Result<TestElem, ser::Error> {
			reader.read_u32()?;
			Ok(TestElem)
		}
	}

	impl Writeable for TestElem {
		fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
			writer.write_u32(0)
		}
	}

	#[test]
	fn open_variable_size_rejects_same_data_and_size_file_path() {
		let temp_dir = mwc_crates::tempfile::tempdir().unwrap();
		let data_path = temp_dir.path().join("data.bin");
		let size_file = AppendOnlyFile::<SizeEntry>::open(
			&data_path,
			SizeInfo::FixedSize(SizeEntry::LEN),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let err = match AppendOnlyFile::<TestElem>::open(
			&data_path,
			SizeInfo::VariableSize(Box::new(size_file)),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		) {
			Ok(_) => panic!("expected aliased size file path to be rejected"),
			Err(err) => err,
		};

		assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("same path"));
	}

	#[test]
	fn open_variable_size_rejects_same_data_and_size_file_dot_path_alias() {
		let temp_dir = mwc_crates::tempfile::tempdir().unwrap();
		let data_path = temp_dir.path().join("data.bin");
		let aliased_data_path = temp_dir.path().join(".").join("data.bin");
		let size_file = AppendOnlyFile::<SizeEntry>::open(
			&data_path,
			SizeInfo::FixedSize(SizeEntry::LEN),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let err = match AppendOnlyFile::<TestElem>::open(
			&aliased_data_path,
			SizeInfo::VariableSize(Box::new(size_file)),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		) {
			Ok(_) => panic!("expected aliased size file path to be rejected"),
			Err(err) => err,
		};

		assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("same path"));
	}

	#[test]
	fn open_variable_size_rejects_same_data_and_size_file_hard_link_alias() {
		let temp_dir = mwc_crates::tempfile::tempdir().unwrap();
		let size_path = temp_dir.path().join("data.bin");
		let data_path = temp_dir.path().join("data_link.bin");
		let size_file = AppendOnlyFile::<SizeEntry>::open(
			&size_path,
			SizeInfo::FixedSize(SizeEntry::LEN),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		fs::hard_link(&size_path, &data_path).unwrap();

		let err = match AppendOnlyFile::<TestElem>::open(
			&data_path,
			SizeInfo::VariableSize(Box::new(size_file)),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		) {
			Ok(_) => panic!("expected aliased size file backing file to be rejected"),
			Err(err) => err,
		};

		assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("backing file"));
	}

	#[test]
	fn open_variable_size_rejects_unsynced_size_file_state() {
		let temp_dir = mwc_crates::tempfile::tempdir().unwrap();
		let data_path = temp_dir.path().join("data.bin");
		let size_path = temp_dir.path().join("data_size.bin");
		let mut size_file = AppendOnlyFile::<SizeEntry>::open(
			&size_path,
			SizeInfo::FixedSize(SizeEntry::LEN),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		size_file
			.append_elmt(&SizeEntry { offset: 0, size: 4 })
			.unwrap();

		let err = match AppendOnlyFile::<TestElem>::open(
			&data_path,
			SizeInfo::VariableSize(Box::new(size_file)),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		) {
			Ok(_) => panic!("expected dirty size file state to be rejected"),
			Err(err) => err,
		};

		assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("unsynced size file state"));
	}

	#[test]
	fn truncate_unsynced_rejects_metadata_len_beyond_buffer() {
		let temp_dir = mwc_crates::tempfile::tempdir().unwrap();
		let data_path = temp_dir.path().join("data.bin");
		let size_path = temp_dir.path().join("data_size.bin");
		let size_file = AppendOnlyFile::<SizeEntry>::open(
			&size_path,
			SizeInfo::FixedSize(SizeEntry::LEN),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let mut file = AppendOnlyFile::<TestElem>::open(
			&data_path,
			SizeInfo::VariableSize(Box::new(size_file)),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		file.append(&mut [1, 2, 3, 4]).unwrap();
		file.flush().unwrap();
		file.append(&mut [5, 6, 7, 8]).unwrap();
		file.append(&mut [9, 10, 11, 12]).unwrap();

		let SizeInfo::VariableSize(size_file) = &mut file.size_info else {
			panic!("expected variable-size file");
		};
		size_file.buffer.clear();
		for entry in [
			SizeEntry {
				offset: 4,
				size: 100,
			},
			SizeEntry { offset: 8, size: 4 },
		] {
			size_file
				.buffer
				.extend(ser::ser_vec(0, &entry, ProtocolVersion(1)).unwrap());
		}

		let err = file.rewind(2).unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
		assert!(err.to_string().contains("exceeds buffer length"));
		assert_eq!(file.buffer.len(), 8);
		let SizeInfo::VariableSize(size_file) = &file.size_info else {
			panic!("expected variable-size file");
		};
		assert_eq!(size_file.buffer.len(), 2 * usize::from(SizeEntry::LEN));
	}

	#[test]
	fn positional_flush_reuses_allocation_without_reusing_cached_bytes() {
		let dir = mwc_crates::tempfile::tempdir().unwrap();
		let path = dir.path().join("reuse.bin");
		let mut file = AppendOnlyFile::<TestElem>::open(
			&path, SizeInfo::FixedSize(4), ProtocolVersion(1), 0,
			VariableSizeMetadataValidation::Full,
		).unwrap();
		file.positional_io = true;
		file.append(&mut vec![1; READ_CACHE_BYTES * 2]).unwrap();
		file.flush().unwrap();
		file.read_from_file(READ_CACHE_BYTES as u64, 4).unwrap();
		let allocation = file.read_cache.lock().bytes.as_ptr();
		let capacity = file.read_cache.lock().bytes.capacity();
		file.rewind((READ_CACHE_BYTES / 4) as u64).unwrap();
		file.append(&mut vec![2; READ_CACHE_BYTES]).unwrap();
		file.flush().unwrap();
		assert!(file.read_cache.lock().bytes.is_empty());
		assert_eq!(file.read_cache.lock().bytes.as_ptr(), allocation);
		assert_eq!(file.read_from_file(READ_CACHE_BYTES as u64, 4).unwrap(), vec![2; 4]);
		assert_eq!(file.read_cache.lock().bytes.as_ptr(), allocation);
		assert_eq!(file.read_cache.lock().bytes.capacity(), capacity);
		assert!(capacity <= READ_CACHE_BYTES);

		// A failure opening the destination must also invalidate cached data.
		file.path = dir.path().join("missing-parent").join("data.bin");
		assert!(file.flush().is_err());
		assert!(file.read_cache.lock().bytes.is_empty());
		assert_eq!(file.read_cache.lock().bytes.as_ptr(), allocation);
		assert!(file.read_from_file(READ_CACHE_BYTES as u64, 4).is_err());
		file.path = path;
		file.flush().unwrap();
		assert_eq!(file.read_from_file(READ_CACHE_BYTES as u64, 4).unwrap(), vec![2; 4]);
	}

	#[test]
	fn positional_flush_rewinds_and_rewrites_durable_bytes() {
		let dir = mwc_crates::tempfile::tempdir().unwrap();
		let path = dir.path().join("data.bin");
		let mut file = AppendOnlyFile::<TestElem>::open(
			&path,
			SizeInfo::FixedSize(4),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		file.positional_io = true;
		for _ in 0..4 {
			file.append_elmt(&TestElem).unwrap();
		}
		file.flush().unwrap();
		assert_eq!(file.read(1).unwrap().unwrap().as_ref(), &[0; 4]);
		file.rewind(1).unwrap();
		// Deliberately use different bytes to detect stale read-cache entries.
		file.append(&mut [0, 0, 0, 7]).unwrap();
		file.flush().unwrap();
		assert!(file.mmap.is_none());
		assert_eq!(file.size().unwrap(), 8);
		assert_eq!(file.read(1).unwrap().unwrap().as_ref(), &[0, 0, 0, 7]);
		file.rewind(1).unwrap();
		file.flush().unwrap();
		assert_eq!(file.size().unwrap(), 4);
		assert!(file.read(1).unwrap().is_none());
		drop(file);
		let reopened = AppendOnlyFile::<TestElem>::open(
			&path,
			SizeInfo::FixedSize(4),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		assert_eq!(reopened.size_in_elmts().unwrap(), 1);
	}

	#[test]
	fn positional_cache_is_bounded_across_growth_and_discard() {
		let dir = mwc_crates::tempfile::tempdir().unwrap();
		let path = dir.path().join("data.bin");
		let mut file = AppendOnlyFile::<TestElem>::open(
			&path,
			SizeInfo::FixedSize(4),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		file.positional_io = true;
		for batch in 0..8 {
			for _ in 0..8192 {
				file.append_elmt(&TestElem).unwrap();
			}
			file.flush().unwrap();
			for pos in [0, 4095, (batch + 1) * 8192 - 1] {
				assert_eq!(file.read(pos).unwrap().unwrap().as_ref(), &[0; 4]);
				assert!(file.read_cache.lock().bytes.capacity() <= READ_CACHE_BYTES);
			}
			assert!(file.buffer.is_empty());
			assert!(file.mmap.is_none());
		}
		let size = file.size_in_elmts().unwrap();
		file.rewind(1).unwrap();
		file.append(&mut [0, 0, 0, 9]).unwrap();
		file.discard();
		assert_eq!(file.size_in_elmts().unwrap(), size);
		assert_eq!(file.read(1).unwrap().unwrap().as_ref(), &[0; 4]);
	}

	#[test]
	fn positional_read_handles_page_boundary_and_reports_short_file() {
		let dir = mwc_crates::tempfile::tempdir().unwrap();
		let path = dir.path().join("data.bin");
		let mut file = AppendOnlyFile::<TestElem>::open(
			&path,
			SizeInfo::FixedSize(4),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		file.positional_io = true;
		for _ in 0..8192 {
			file.append_elmt(&TestElem).unwrap();
		}
		file.flush().unwrap();
		file.read_from_file(0, 4).unwrap();
		let cache_allocation = file.read_cache.lock().bytes.as_ptr();
		file.read_from_file(READ_CACHE_BYTES as u64, 4).unwrap();
		assert_eq!(cache_allocation, file.read_cache.lock().bytes.as_ptr());
		assert_eq!(
			file.read_from_file(READ_CACHE_BYTES as u64 - 2, 4).unwrap(),
			vec![0; 4]
		);
		assert_eq!(file.read_from_file(0, 32000).unwrap().len(), 32000);
		assert!(file.read_cache.lock().bytes.len() <= READ_CACHE_BYTES);
		assert_eq!(
			file.read_from_file(32767, 4).unwrap_err().kind(),
			ErrorKind::UnexpectedEof
		);
	}

	/// Host-only microbenchmark; includes the same durable flush as production.
	/// This does not predict iPhone NAND latency or end-to-end block throughput.
	#[test]
	#[ignore]
	fn positional_durable_append_benchmark() {
		for round in 0..3 {
			let dir = mwc_crates::tempfile::tempdir().unwrap();
			let mut file = AppendOnlyFile::<TestElem>::open(
				dir.path().join("bench.bin"), SizeInfo::FixedSize(4),
				ProtocolVersion(1), 0, VariableSizeMetadataValidation::Full,
			).unwrap();
			file.positional_io = true;
			file.append(&mut vec![0; READ_CACHE_BYTES]).unwrap();
			file.flush().unwrap();
			let start = std::time::Instant::now();
			for _ in 0..250 {
				file.read_from_file(0, 4).unwrap();
				file.append(&mut [1; 32]).unwrap();
				file.flush().unwrap();
			}
			eprintln!("positional durable append round={} iterations=250 elapsed_ms={:.3}",
				round, start.elapsed().as_secs_f64() * 1000.0);
			assert_eq!(file.size().unwrap(), READ_CACHE_BYTES as u64 + 250 * 32);
		}
	}

	#[test]
	fn positional_flush_retry_truncates_partially_written_tail() {
		let dir = mwc_crates::tempfile::tempdir().unwrap();
		let path = dir.path().join("retry.bin");
		let mut file = AppendOnlyFile::<TestElem>::open(
			&path, SizeInfo::FixedSize(4), ProtocolVersion(1), 0,
			VariableSizeMetadataValidation::Full,
		).unwrap();
		file.positional_io = true;
		file.append(&mut [1; 4]).unwrap();
		file.flush().unwrap();
		file.append(&mut [2; 4]).unwrap();
		// Model write_all succeeding partially before a flush returns an error.
		// The logical buffer and start position remain unchanged on failure.
		file.file = None;
		let mut disk = OpenOptions::new().append(true).open(&path).unwrap();
		disk.write_all(&[9; 12]).unwrap();
		drop(disk);
		file.flush().unwrap();
		assert_eq!(std::fs::read(&path).unwrap(), vec![1, 1, 1, 1, 2, 2, 2, 2]);
		assert_eq!(file.size_in_elmts().unwrap(), 2);
	}
}
