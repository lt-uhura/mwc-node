//! Bounded, process-wide timing diagnostics. Durations overlap across threads
//! and nested operations; they are not additive wall-clock time.
use std::sync::Mutex;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use std::cell::Cell;

thread_local! { static HEADER_WAIT: Cell<Duration> = const { Cell::new(Duration::ZERO) }; }
/// Per-thread header-lock wait, used as a delta around synchronous chain calls.
pub fn header_wait_total() -> Duration { HEADER_WAIT.with(Cell::get) }
/// This measures only the robust header read lock, not every chain lock.
pub fn record_header_wait(elapsed: Duration) {
	HEADER_WAIT.with(|v| v.set(v.get().saturating_add(elapsed)));
}

/// Bounded request provenance. Unknown means no retained successful send, NOT
/// proof that a response was unsolicited. Entries expire after two minutes.
struct Sent { hash: [u8; 32], peer: String, retry: bool, at: Instant }
fn retain_send(sent: &mut VecDeque<Sent>, value: Sent) {
	while sent.front().map_or(false, |v| value.at.duration_since(v.at) > Duration::from_secs(120)) { sent.pop_front(); }
	if sent.len() >= 2048 { sent.pop_front(); }
	sent.push_back(value);
}
fn classify_origin(sent: &VecDeque<Sent>, hash: &[u8], peer: &str, now: Instant) -> usize {
	let mut kinds = 0;
	for v in sent.iter().rev() {
		if now.duration_since(v.at) > Duration::from_secs(120) { break; }
		if v.hash.as_slice() == hash && v.peer == peer { kinds |= if v.retry { 2 } else { 1 }; }
	}
	match kinds { 1 => 0, 2 => 1, 3 => 2, _ => 3 }
}
/// Remember a successful enqueue, not a guarantee of network delivery.
pub fn record_body_send(hash: &[u8], peer: String, retry: bool) {
	if hash.len() != 32 { return; }
	if let Ok(mut s) = STATE.lock() {
		let now = Instant::now();
		let mut key = [0; 32]; key.copy_from_slice(hash);
		retain_send(&mut s.sent, Sent { hash: key, peer, retry, at: now });
	}
}
/// 0 original, 1 retry, 2 ambiguous (both kinds), 3 no retained send.
pub fn body_origin(hash: &[u8], peer: &str) -> usize {
	if let Ok(s) = STATE.lock() {
		return classify_origin(&s.sent, hash, peer, Instant::now());
	}
	3
}
/// Arrival at the last observed missing head from a retained retry peer. This
/// is evidence of rescue delivery, not proof of validation/HEAD advancement.
pub fn observe_retry_arrival(height: u64, origin: usize) {
	if origin != 1 { return; }
	if let Ok(mut s) = STATE.lock() {
		if s.head.as_ref().map_or(false, |(h, missing, _, at)| *missing && h.checked_add(1) == Some(height) && at.elapsed() <= Duration::from_secs(1)) {
			s.head_retry_arrivals += 1;
		}
	}
}
/// Known outcome cost by request provenance; remaining time includes all other
/// locks and I/O and must not be interpreted as CPU time.
pub fn record_known_cost(origin: usize, elapsed: Duration, header_wait: Duration) {
	if let Ok(mut s) = STATE.lock() {
		s.known_cost[origin.min(3)].record(elapsed, true);
		s.known_header_wait.record(header_wait, true);
	}
}

/// Fixed diagnostic categories; never consulted by synchronization policy.
pub fn record_batch_reason(reason: usize) {
	if let Ok(mut s) = STATE.lock() { if let Some(v) = s.batch_reasons.get_mut(reason) { *v += 1; } }
}
fn missing_interval(old: u64, current: u64, was_missing: bool, missing: bool, dt: Duration) -> bool {
	dt <= Duration::from_secs(1) && old == current && was_missing && missing
}

/// Sampled occupancy between consecutive observations of the SAME missing
/// head. Gaps >1s are omitted (suspension/slow loop), not charged to a peer.
pub fn observe_head(height: u64, missing: bool, peer: Option<String>) {
	if let Ok(mut s) = STATE.lock() {
		let now = Instant::now();
		if let Some((old_height, old_missing, old_peer, at)) = s.head.take() {
			let dt = now.duration_since(at);
			if missing_interval(old_height, height, old_missing, missing, dt) {
				s.head_wait.record(dt, true);
				let owner = old_peer.unwrap_or_else(|| "untracked".into());
				if let Some((_, us)) = s.head_peers.iter_mut().find(|(p, _)| p == &owner) { *us += dt.as_micros(); }
				else if s.head_peers.len() < 16 { s.head_peers.push((owner, dt.as_micros())); }
			}
		}
		s.head = Some((height, missing, peer, now));
	}
}

#[derive(Clone, Copy, Default)]
struct Counter {
	cpu: crate::thread_cpu::Counter,
	count: u64,
	micros: u128,
	max_micros: u128,
	errors: u64,
}
impl Counter {
	const ZERO: Self = Self { cpu: crate::thread_cpu::Counter::ZERO, count: 0, micros: 0, max_micros: 0, errors: 0 };
	fn record(&mut self, duration: Duration, success: bool) {
		self.count += 1;
		self.micros += duration.as_micros();
		self.max_micros = self.max_micros.max(duration.as_micros());
		self.errors += u64::from(!success);
	}
}
#[derive(Default)]
struct BatchCounter {
	attempts: u64,
	initial: u64,
	added: u64,
	committed_calls: u64,
	committed_blocks: u64,
	sizes: [u64; 4],
}
impl BatchCounter {
	fn record(&mut self, initial: usize, added: usize, committed: bool) {
		let total = initial.saturating_add(added);
		self.attempts += 1;
		self.initial += initial as u64;
		self.added += added as u64;
		self.sizes[match total { 0..=1 => 0, 2..=4 => 1, 5..=8 => 2, _ => 3 }] += 1;
		if committed {
			self.committed_calls += 1;
			self.committed_blocks += total as u64;
		}
	}
}

/// Completed live batch attempts; committed block count is not net HEAD advancement.
pub fn record_live_batch(initial: usize, added: usize, committed: bool) {
	if let Ok(mut state) = STATE.lock() {
		state.since.get_or_insert_with(Instant::now);
		state.batches.record(initial, added, committed);
	}
}

#[derive(Default)]
struct State {
	sent: VecDeque<Sent>,
	known_cost: [Counter; 4],
	known_header_wait: Counter,
	batch_reasons: [u64; 17],
	head: Option<(u64, bool, Option<String>, Instant)>,
	head_wait: Counter,
	head_peers: Vec<(String, u128)>,
	head_retry_arrivals: u64,
	since: Option<Instant>,
	counters: [Counter; 30],
	batches: BatchCounter,
	limits_at: Option<Instant>,
	outcomes: [Counter; 5],
	arrivals: [u64; 3],
	recent_headers: VecDeque<[u8; 32]>,
}
static STATE: Mutex<State> = Mutex::new(State {
	sent: VecDeque::new(),
	known_cost: [Counter::ZERO; 4],
	known_header_wait: Counter::ZERO,
	batch_reasons: [0; 17],
	head: None,
	head_wait: Counter::ZERO,
	head_peers: Vec::new(),
	head_retry_arrivals: 0,
	since: None,
	counters: [Counter::ZERO; 30],
	batches: BatchCounter { attempts: 0, initial: 0, added: 0, committed_calls: 0, committed_blocks: 0, sizes: [0; 4] },
	limits_at: None,
	outcomes: [Counter::ZERO; 5],
	arrivals: [0; 3],
	recent_headers: VecDeque::new(),
});

/// Begin a diagnostic window after the previous mobile node has fully stopped.
/// Caller must serialize node lifetimes; these counters are process-wide.
/// Thread-local header wait remains cumulative because callers use deltas.
pub fn begin_session() {
	if let Ok(mut state) = STATE.lock() {
		state.begin_session(Instant::now());
	}
}
impl State {
	fn begin_session(&mut self, now: Instant) {
		*self = Self::default();
		self.since = Some(now);
	}
}

/// Result of the chain processing call, before adapter response bookkeeping.
#[derive(Clone, Copy)]
pub enum BlockOutcome {
	/// Chain processing succeeded; not necessarily main-chain height advancement.
	Accepted,
	/// Exact known-block classification from the chain, not a header-only shortcut.
	Known,
	/// Orphan or missing dependency, requiring further processing.
	Pending,
	/// Invalid block classification.
	BadData,
	/// Other chain processing error.
	Error,
}
impl BlockOutcome {
	/// Record inclusive chain-call elapsed time in its outcome bucket.
	pub fn record(self, elapsed: Duration) {
		if let Ok(mut state) = STATE.lock() {
			state.since.get_or_insert_with(Instant::now);
			state.outcomes[self as usize].record(elapsed, true);
		}
	}
}

fn remember_header(recent: &mut VecDeque<[u8; 32]>, hash: [u8; 32]) -> bool {
	if recent.contains(&hash) { return true; }
	if recent.len() == 256 { recent.pop_front(); }
	recent.push_back(hash);
	false
}

/// Header repeats are diagnostic only: equal headers do NOT prove equal bodies.
/// Remembers at most 256 distinct inserted hashes across reporting windows.
pub fn record_block_arrival(header: &[u8], matched_request: bool) {
	if header.len() != 32 { return; }
	let mut hash = [0; 32];
	hash.copy_from_slice(header);
	if let Ok(mut state) = STATE.lock() {
		state.since.get_or_insert_with(Instant::now);
		state.arrivals[0] += 1;
		state.arrivals[1] += u64::from(matched_request);
		if remember_header(&mut state.recent_headers, hash) { state.arrivals[2] += 1; }
	}
}

/// Fixed buckets, with no per-block allocation or log messages.
#[derive(Clone, Copy)]
pub enum Metric {
	/// Request registration to the decoded block adapter, including decoding/hash.
	RequestToAdapter,
	/// Adapter process_block, including locks, validation and response reporting.
	ProcessBlock,
	/// Append-only flush including nested size-file flushes.
	PmmrFlush,
	/// sync_all inside append-only flush (not every filesystem sync).
	PmmrFsync,
	/// LMDB batch commits, including child batches and non-chain databases.
	LmdbCommit,
	/// Stored-body HEAD reconciliation, including lock acquisition and reads.
	BodyReconcile,
	/// Time acquiring both PMMR write locks for stored-body reconciliation.
	BodyReconcileWait,
	/// Live batch time acquiring both PMMR writer locks.
	LiveBatchWait,
	/// Live batch writer critical section, including validation and persistence.
	LiveBatchHold,
	/// Receive-window preparation, without the sender lock.
	ReceiveRefillPrepare,
	/// Compare/publish critical section; unsuccessful means stale snapshot.
	ReceiveRefillPublish,
	/// Series PoW/header processing, per block, under writer locks.
	SeriesHeader,
	/// Series internal body validation, per block, under writer locks.
	SeriesBody,
	/// Series UTXO extension including nested PMMR flushes, per batch.
	SeriesExtension,
	/// Series body/index persistence and HEAD update, excluding outer commit.
	SeriesStore,
	/// Series fork preparation, including any replayed fork blocks.
	ExtensionFork,
	/// Series replay, maturity, and UTXO checks, per incoming block.
	ExtensionChecks,
	/// Series cryptographic block sums, per incoming block.
	ExtensionSums,
	/// Series PMMR application and root/size checks, excluding outer record collection.
	ExtensionApply,
	/// Three body backend sync calls, including nested flush/fsync; all extensions.
	ExtensionSync,
	/// Backend hash-file flush, all backend sync callers.
	BackendHash,
	/// Backend data flush, including nested variable-size metadata flush.
	BackendData,
	/// Backend leaf-set flush, including clean/nonprunable no-ops.
	BackendLeaf,
	/// Backend prune-list flush, including clean no-ops.
	BackendPrune,
	/// Bitmap replacement preparation, write and file sync; nested in leaf/prune.
	BitmapFile,
	/// Bitmap rename and parent-directory sync; nested in leaf/prune.
	BitmapPublish,
	/// Transaction-body structural checks, all full-validation callers.
	ValidationStructure,
	/// Proof collection and verification (including cache lookup), all full bodies.
	ValidationProofs,
	/// Kernel signature batch verification, all full bodies.
	ValidationSignatures,
	/// Block contextual kernel checks, coinbase and commitment sums.
	ValidationBlockRest,
}
impl Metric {
	/// Record a completed operation; false counts unsuccessful results.
	pub fn record(self, duration: Duration, success: bool) {
		if let Ok(mut state) = STATE.lock() {
			state.since.get_or_insert_with(Instant::now);
			state.counters[self as usize].record(duration, success);
		}
	}
	/// Start a failure-by-default scope timer.
	pub fn start(self) -> Timer {
		Timer {
			cpu_start: if self.measures_cpu() { crate::thread_cpu::now() } else { None },
			_same_thread: std::marker::PhantomData,
			metric: self,
			start: Instant::now(),
			success: false,
		}
	}
	fn measures_cpu(self) -> bool {
		matches!(self, Self::ProcessBlock | Self::BodyReconcile | Self::LiveBatchHold
			| Self::SeriesBody | Self::SeriesExtension | Self::ExtensionSync | Self::LmdbCommit
			| Self::ValidationStructure | Self::ValidationProofs | Self::ValidationSignatures | Self::ValidationBlockRest)
	}
}
/// Records failures, including early returns, without changing error propagation.
pub struct Timer {
	cpu_start: Option<Duration>,
	// Thread CPU clocks cannot be paired across threads, even if a caller moves a timer.
	_same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
	metric: Metric,
	start: Instant,
	success: bool,
}
impl Timer {
	/// Mark the operation successful before the scope ends.
	pub fn success(&mut self) {
		self.success = true;
	}
}
impl Drop for Timer {
	fn drop(&mut self) {
		let wall = self.start.elapsed();
		let cpu_end = if self.metric.measures_cpu() { crate::thread_cpu::now() } else { None };
		if let Ok(mut state) = STATE.lock() {
			state.since.get_or_insert_with(Instant::now);
			let counter = &mut state.counters[self.metric as usize];
			counter.record(wall, self.success);
			if self.metric.measures_cpu() { counter.cpu.record(wall, self.cpu_start, cpu_end); }
		}
	}
}

/// Called by the sync loop; completion-based windows include all node instances.
pub fn summary() -> Option<Vec<String>> {
	let (elapsed, counters, outcomes, arrivals, batches, known, known_wait, reasons, head_wait, head_peers, head_retry_arrivals) = {
		let mut state = STATE.lock().ok()?;
		let now = Instant::now();
		let elapsed = now.duration_since(*state.since.get_or_insert(now));
		if elapsed < Duration::from_secs(15) {
			return None;
		}
		state.since = Some(now);
		(elapsed, std::mem::take(&mut state.counters), std::mem::take(&mut state.outcomes), std::mem::take(&mut state.arrivals), std::mem::take(&mut state.batches), std::mem::take(&mut state.known_cost), std::mem::take(&mut state.known_header_wait), std::mem::take(&mut state.batch_reasons), std::mem::take(&mut state.head_wait), std::mem::take(&mut state.head_peers), std::mem::take(&mut state.head_retry_arrivals))
	};
	let mut line = format!(
		"body sync timing window_s={:.1} [n/avg_ms/max_ms/errors]",
		elapsed.as_secs_f64()
	);
	for (name, c) in [
		"request_to_adapter",
		"process",
		"pmmr_flush",
		"pmmr_fsync",
		"lmdb_commit",
		"reconcile",
		"reconcile_wait",
	]
	.iter()
	.zip(counters.iter())
	{
		line.push_str(&format!(
			" {}={}/{:.2}/{:.2}/{}",
			name,
			c.count,
			c.micros as f64 / c.count.max(1) as f64 / 1000.0,
			c.max_micros as f64 / 1000.0,
			c.errors
		));
	}
	let mut blocks = format!("body sync outcomes window_s={:.1} arrivals={} matched={} unmatched={} recent_header_repeat={} chain[n/total_ms/max_ms]", elapsed.as_secs_f64(), arrivals[0], arrivals[1], arrivals[0].saturating_sub(arrivals[1]), arrivals[2]);
	for (name, c) in ["accepted", "known", "pending", "bad", "error"].iter().zip(outcomes.iter()) {
		blocks.push_str(&format!(" {}={}/{:.2}/{:.2}", name, c.count, c.micros as f64 / 1000.0, c.max_micros as f64 / 1000.0));
	}
	let mut batching = format!("body sync batching window_s={:.1} attempts={} initial={} added={} committed_calls={} committed_blocks={} sizes[1/2-4/5-8/9+]={}/{}/{}/{}", elapsed.as_secs_f64(), batches.attempts, batches.initial, batches.added, batches.committed_calls, batches.committed_blocks, batches.sizes[0], batches.sizes[1], batches.sizes[2], batches.sizes[3]);
	for (name, metric) in [("wait", Metric::LiveBatchWait), ("hold", Metric::LiveBatchHold)] {
		let c = counters[metric as usize];
		batching.push_str(&format!(" {}[n/avg_ms/max_ms/errors]={}/{:.2}/{:.2}/{}", name, c.count, c.micros as f64 / c.count.max(1) as f64 / 1000.0, c.max_micros as f64 / 1000.0, c.errors));
	}
	let mut scheduling = format!("body sync scheduling window_s={:.1} receive_refill={} [n/avg_ms/max_ms/unsuccessful]", elapsed.as_secs_f64(), cfg!(target_os = "ios") && option_env!("MWC_RECEIVE_REFILL") != Some("0"));
	scheduling.push_str(&format!(" stage_orphans={}", cfg!(target_os = "ios") && option_env!("MWC_STAGE_SYNC_ORPHANS") != Some("0")));
	for (name, metric) in [("prepare", Metric::ReceiveRefillPrepare), ("publish", Metric::ReceiveRefillPublish)] {
		let c = counters[metric as usize];
		scheduling.push_str(&format!(" {}={}/{:.2}/{:.2}/{}", name, c.count, c.micros as f64 / c.count.max(1) as f64 / 1000.0, c.max_micros as f64 / 1000.0, c.errors));
	}
	let mut stages = format!("body sync stages window_s={:.1} [n/total_ms/max_ms/errors]", elapsed.as_secs_f64());
	for (name, metric) in [("header", Metric::SeriesHeader), ("body", Metric::SeriesBody), ("extension", Metric::SeriesExtension), ("store", Metric::SeriesStore)] {
		let c = counters[metric as usize];
		stages.push_str(&format!(" {}={}/{:.2}/{:.2}/{}", name, c.count, c.micros as f64 / 1000.0, c.max_micros as f64 / 1000.0, c.errors));
	}
	let mut extension = format!("body sync extension window_s={:.1} [n/total_ms/max_ms/errors]", elapsed.as_secs_f64());
	for (name, metric) in [("fork", Metric::ExtensionFork), ("checks", Metric::ExtensionChecks), ("sums", Metric::ExtensionSums), ("apply", Metric::ExtensionApply), ("sync", Metric::ExtensionSync)] {
		let c = counters[metric as usize];
		extension.push_str(&format!(" {}={}/{:.2}/{:.2}/{}", name, c.count, c.micros as f64 / 1000.0, c.max_micros as f64 / 1000.0, c.errors));
	}
	let mut sync_io = format!("body sync sync_io window_s={:.1} [n/total_ms/max_ms/errors]", elapsed.as_secs_f64());
	for (name, metric) in [("hash", Metric::BackendHash), ("data", Metric::BackendData), ("leaf", Metric::BackendLeaf), ("prune", Metric::BackendPrune), ("bitmap_file", Metric::BitmapFile), ("bitmap_publish", Metric::BitmapPublish)] {
		let c = counters[metric as usize];
		sync_io.push_str(&format!(" {}={}/{:.2}/{:.2}/{}", name, c.count, c.micros as f64 / 1000.0, c.max_micros as f64 / 1000.0, c.errors));
	}
	let mut duplicates = format!("body sync duplicates window_s={:.1} known[n/total_ms]", elapsed.as_secs_f64());
	for (name, c) in ["original", "retry", "ambiguous", "unattributed"].iter().zip(known.iter()) {
		duplicates.push_str(&format!(" {}={}/{:.2}", name, c.count, c.micros as f64 / 1000.0));
	}
	duplicates.push_str(&format!(" header_read_wait_ms={:.2} remaining_ms={:.2}", known_wait.micros as f64 / 1000.0, known.iter().map(|c| c.micros).sum::<u128>().saturating_sub(known_wait.micros) as f64 / 1000.0));
	let batch_detail = format!("body sync batch_detail window_s={:.1} late_end[cap/empty/depth_or_branch/overflow/depth/branch/missing_orphan/header_mismatch]={:?} attempt_exit[prepare/series/commit/recovery/complete]={:?} failure[known/dependency/bad_data/other]={:?}", elapsed.as_secs_f64(), &reasons[..8], &reasons[8..13], &reasons[13..]);
	let head_wait = format!("body sync head_wait window_s={:.1} sampled_missing_ms={:.2} same_head_intervals={} retry_arrivals_at_sampled_head={} owner_us={:?}", elapsed.as_secs_f64(), head_wait.micros as f64 / 1000.0, head_wait.count, head_retry_arrivals, head_peers);
	let mut cpu = format!("body sync cpu window_s={:.1} [n/wall_ms/cpu_ms/off_cpu_ms/unavailable]", elapsed.as_secs_f64());
	for (name, metric) in [("process", Metric::ProcessBlock), ("reconcile", Metric::BodyReconcile), ("batch_hold", Metric::LiveBatchHold)] {
		let c = counters[metric as usize].cpu;
		cpu.push_str(&format!(" {}={}/{:.2}/{:.2}/{:.2}/{}", name, c.samples, c.wall as f64 / 1000.0, c.cpu as f64 / 1000.0, c.off_cpu as f64 / 1000.0, c.unavailable));
	}
	let cpu_stages = format_cpu_stages(elapsed, &counters);
	let validation = format_cpu_validation(elapsed, &counters);
	Some(vec![line, blocks, batching, scheduling, stages, extension, sync_io, duplicates, batch_detail, head_wait, cpu, cpu_stages, validation])
}

// Separate line keeps both summaries within the mobile log category size bound.
fn format_cpu_stages(elapsed: Duration, counters: &[Counter; 30]) -> String {
	let mut line = format!("body sync cpu_stages window_s={:.1} [n/wall_ms/cpu_ms/off_cpu_ms/unavailable]", elapsed.as_secs_f64());
	for (name, metric) in [("body", Metric::SeriesBody), ("extension", Metric::SeriesExtension), ("sync", Metric::ExtensionSync), ("commit", Metric::LmdbCommit)] {
		let c = counters[metric as usize].cpu;
		line.push_str(&format!(" {}={}/{:.2}/{:.2}/{:.2}/{}", name, c.samples, c.wall as f64 / 1000.0, c.cpu as f64 / 1000.0, c.off_cpu as f64 / 1000.0, c.unavailable));
	}
	line
}

// Full-validation callers include transactions and non-series blocks; these
// counters must not be subtracted directly from SeriesBody totals.
fn format_cpu_validation(elapsed: Duration, counters: &[Counter; 30]) -> String {
	let mut line = format!("body sync cpu_validation window_s={:.1} [n/wall_ms/cpu_ms/off_cpu_ms/unavailable]", elapsed.as_secs_f64());
	for (name, metric) in [("structure", Metric::ValidationStructure), ("proofs", Metric::ValidationProofs), ("signatures", Metric::ValidationSignatures), ("block_rest", Metric::ValidationBlockRest)] {
		let c = counters[metric as usize].cpu;
		line.push_str(&format!(" {}={}/{:.2}/{:.2}/{:.2}/{}", name, c.samples, c.wall as f64 / 1000.0, c.cpu as f64 / 1000.0, c.off_cpu as f64 / 1000.0, c.unavailable));
	}
	line
}

/// Rate limit only the diagnostic, never the scheduling calculation itself.
pub fn log_limits_now() -> bool {
	if let Ok(mut state) = STATE.lock() {
		let now = Instant::now();
		if state
			.limits_at
			.map_or(true, |t| now.duration_since(t) >= Duration::from_secs(15))
		{
			state.limits_at = Some(now);
			return true;
		}
	}
	false
}

#[cfg(test)]
mod tests {
	#[test]
	fn validation_cpu_summary_keeps_distinct_metrics() {
		use super::*;
		let mut counters = [Counter::ZERO; 30];
		for (i, metric) in [Metric::ValidationStructure, Metric::ValidationProofs, Metric::ValidationSignatures, Metric::ValidationBlockRest].into_iter().enumerate() {
			assert!(metric.measures_cpu());
			counters[metric as usize].cpu.record(Duration::from_millis(100 + i as u64), Some(Duration::ZERO), Some(Duration::from_millis(30)));
		}
		let line = format_cpu_validation(Duration::from_secs(15), &counters);
		for (i, name) in ["structure", "proofs", "signatures", "block_rest"].into_iter().enumerate() {
			assert!(line.contains(&format!(" {}=1/{}.00/30.00/{}.00/0", name, 100 + i, 70 + i)));
		}
		assert!(line.len() + 100 < 600);
	}

	#[test]
	fn cpu_stage_summary_keeps_distinct_metrics_and_fits_mobile_log() {
		use super::*;
		let mut counters = [Counter::ZERO; 30];
		for (i, metric) in [Metric::SeriesBody, Metric::SeriesExtension, Metric::ExtensionSync, Metric::LmdbCommit].into_iter().enumerate() {
			assert!(metric.measures_cpu());
			counters[metric as usize].cpu.record(Duration::from_millis(100 + i as u64), Some(Duration::ZERO), Some(Duration::from_millis(30)));
		}
		let line = format_cpu_stages(Duration::from_secs(15), &counters);
		for (i, name) in ["body", "extension", "sync", "commit"].into_iter().enumerate() {
			assert!(line.contains(&format!(" {}=1/{}.00/30.00/{}.00/0", name, 100 + i, 70 + i)));
		}
		assert!(line.len() + 100 < 600); // room for native timestamp/log prefix
	}

	use super::*;
	#[test]
	fn provenance_is_bounded_expires_and_preserves_ambiguity() {
		let mut sent = VecDeque::new();
		let now = Instant::now();
		let entry = |retry, at| Sent { hash: [7; 32], peer: "peer".into(), retry, at };
		assert_eq!(classify_origin(&sent, &[7; 32], "peer", now), 3);
		retain_send(&mut sent, entry(false, now));
		assert_eq!(classify_origin(&sent, &[7; 32], "peer", now), 0);
		assert_eq!(classify_origin(&sent, &[7; 32], "other", now), 3);
		retain_send(&mut sent, entry(true, now));
		assert_eq!(classify_origin(&sent, &[7; 32], "peer", now), 2);
		for _ in 0..2048 { retain_send(&mut sent, entry(true, now)); }
		assert_eq!(sent.len(), 2048);
		assert_eq!(classify_origin(&sent, &[7; 32], "peer", now), 1);
		let later = now + Duration::from_secs(121);
		assert_eq!(classify_origin(&sent, &[7; 32], "peer", later), 3);
		retain_send(&mut sent, entry(false, later));
		assert_eq!(sent.len(), 1);
	}
	#[test]
	fn head_sampling_excludes_progress_unknown_and_suspension() {
		let dt = Duration::from_millis(200);
		assert!(missing_interval(10, 10, true, true, dt));
		assert!(!missing_interval(10, 11, true, true, dt));
		assert!(!missing_interval(10, 9, true, true, dt));
		assert!(!missing_interval(10, 10, true, false, dt));
		assert!(!missing_interval(10, 10, false, true, dt));
		assert!(!missing_interval(10, 10, true, true, Duration::from_secs(2)));
	}
	#[test]
	fn header_wait_delta_is_thread_local() {
		let before = header_wait_total();
		record_header_wait(Duration::from_millis(3));
		assert_eq!(header_wait_total() - before, Duration::from_millis(3));
		assert_eq!(std::thread::spawn(header_wait_total).join().unwrap(), Duration::ZERO);
	}
	#[test]
	fn live_batch_counts_distinguish_attempts_from_commits() {
		let mut b = BatchCounter::default();
		b.record(1, 0, true);
		b.record(2, 2, false);
		b.record(3, 5, true);
		b.record(9, 0, true);
		assert_eq!((b.attempts, b.initial, b.added), (4, 15, 7));
		assert_eq!((b.committed_calls, b.committed_blocks), (3, 18));
		assert_eq!(b.sizes, [1, 1, 1, 1]);
		let _ = std::mem::take(&mut b);
		assert_eq!((b.attempts, b.committed_blocks, b.sizes), (0, 0, [0; 4]));
	}
	#[test]
	fn recent_headers_detect_repeats_with_bounded_history() {
		let mut recent = VecDeque::new();
		assert!(!remember_header(&mut recent, [0; 32]));
		assert!(remember_header(&mut recent, [0; 32]));
		for n in 1u16..=256 {
			let mut hash = [0; 32];
			hash[..2].copy_from_slice(&n.to_le_bytes());
			assert!(!remember_header(&mut recent, hash));
		}
		assert_eq!(recent.len(), 256);
		assert!(!remember_header(&mut recent, [0; 32]));
		assert_eq!(recent.len(), 256);
	}
	#[test]
	fn aggregates_success_errors_and_resets() {
		let mut c = Counter::default();
		c.record(Duration::from_millis(2), true);
		c.record(Duration::from_millis(4), false);
		assert_eq!(
			(c.count, c.micros, c.max_micros, c.errors),
			(2, 6000, 4000, 1)
		);
		let old = std::mem::take(&mut c);
		assert_eq!(old.count, 2);
		assert_eq!((c.count, c.micros, c.max_micros, c.errors), (0, 0, 0, 0));
	}
	#[test]
	fn session_boundary_discards_old_counters_and_histories() {
		let now = Instant::now();
		let mut state = State::default();
		state.batches.record(4, 1, true);
		state.counters[0].record(Duration::from_secs(1), true);
		state.counters[0].cpu.record(Duration::from_secs(1), Some(Duration::ZERO), Some(Duration::from_millis(20)));
		state.outcomes[0].record(Duration::from_secs(1), true);
		state.known_cost[1].record(Duration::from_secs(1), true);
		state.sent.push_back(Sent { hash: [1; 32], peer: "old".into(), retry: true, at: now });
		state.recent_headers.push_back([1; 32]);
		state.head = Some((100, true, Some("old".into()), now));
		state.limits_at = Some(now);
		state.begin_session(now);
		assert_eq!(state.since, Some(now));
		assert_eq!(state.batches.attempts, 0);
		assert_eq!(state.counters[0].count, 0);
		assert_eq!(state.counters[0].cpu.samples, 0);
		assert_eq!(state.outcomes[0].count, 0);
		assert_eq!(state.known_cost[1].count, 0);
		assert!(state.sent.is_empty() && state.recent_headers.is_empty());
		assert!(state.head.is_none() && state.limits_at.is_none());
	}
}
