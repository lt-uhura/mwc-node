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

use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils;
use crate::mwc::sync::sync_utils::{RequestTracker, SyncRequestResponses, SyncResponse};
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::{self, SyncState, SyncStatus};
use mwc_chain::{pibd_params, Chain};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_crates::log::{debug, info, warn};
use mwc_crates::parking_lot::{Mutex, MutexGuard, RwLock};
use mwc_crates::rand;
use mwc_crates::rand::prelude::*;
use mwc_crates::secp::Secp256k1;
use mwc_p2p::Capabilities;
use mwc_p2p::{Peer, PeerAddr, Peers};
use std::cmp;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Most recent GetBlock send attempt. The 10s heartbeat prints this so the
/// Node tab can see why bodies are or are not moving, even when new_requests
/// is empty and send_requests itself stays silent.
struct LastSendStats {
	sent_heights: Vec<u64>,
	peers_before_filter: usize,
	peers_after_filter: usize,
	new_requests: usize,
	note: String,
}

/// Handshake / ping height is often 0 until the first Ping/Pong. Do not drop
/// those peers when requesting the first bodies (heights 1..=8).
fn peer_can_serve_body_height(live_height: u64, request_height: u64) -> bool {
	if live_height >= request_height {
		return true;
	}
	live_height == 0 && request_height >= 1 && request_height <= 8
}

const BODY_SYNC_PEER_LOG_SECS: u64 = 30;

// Leave room in the 15-entry mobile orphan pool without increasing concurrent
// requests or the durable batch cap. Preserve the special genesis window.
fn body_height_window(mobile: bool, fork_height: u64, orphan_limit: usize) -> u64 {
	if mobile {
		if fork_height == 0 { 8 } else { 12 }
	} else {
		(orphan_limit / 2).max(1) as u64
	}
}

// Descending height order. An entry at/below HEAD means committed progress
// has freed height-window capacity. Empty lists are initialized by the loop,
// which also owns fork/replay readiness checks.
fn series_needs_refill(series: &[(Hash, u64)], head: u64) -> bool {
	series.last().map_or(false, |(_, height)| *height <= head)
}

fn publish_series_if_unchanged(series: &mut Vec<(Hash, u64)>, previous: &[(Hash, u64)], next: Vec<(Hash, u64)>) -> bool {
	if series.as_slice() != previous { return false; }
	*series = next;
	true
}

// At most two unresolved rescue sends, not an expanded unique-block window.
// Keep the original tracked request and timeout intact so either peer can win.
#[derive(Default)]
struct HeadRetry {
	pending: Option<(Hash, Instant)>,
	last_attempt: Option<Instant>,
	// Retain timed-out short leases until the normal timeout: expiring a lease
	// does not cancel the network request or make its duplicate budget free.
	sent: Vec<(Hash, PeerAddr, Instant)>,
}

impl HeadRetry {
	fn available(&mut self, now: Instant, resolved: bool, lease: Duration) -> bool {
		self.sent.retain(|(_, _, sent)| now.saturating_duration_since(*sent) < Duration::from_secs(30));
		if self.pending.map_or(false, |(_, sent)| resolved || now.saturating_duration_since(sent) >= lease) {
			self.pending = None;
		}
		// Permit the next blocking hash to be rescued promptly after resolution,
		// but cap this path at two attempts/second even when sends fail.
		self.sent.len() < 2 && self.pending.is_none() && self.last_attempt.map_or(true, |t| now.saturating_duration_since(t) >= Duration::from_millis(500))
	}

	fn peer_eligible(&self, hash: Hash, peer: &PeerAddr, original: &PeerAddr) -> bool {
		peer != original && !self.sent.iter().any(|(h, p, _)| *h == hash && p == peer)
	}
}

fn head_retry_lease(latency: Option<u32>) -> Duration {
	Duration::from_millis(latency.map_or(5000, |ms| u64::from(ms).saturating_mul(4).clamp(2000, 5000)))
}

fn head_retry_delay(latency: Option<u32>) -> Duration {
	// This applies only to the canonical next missing block. Without samples,
	// retain the conservative two-second startup delay.
	Duration::from_millis(latency.map_or(2000, |ms| u64::from(ms).saturating_mul(3).clamp(500, 2000)))
}

// Experimental age gate for spare-capacity retries only. Gap recovery and
// canonical-head rescue retain their existing policies.
fn spare_retry_due(age: Option<Duration>, latency: Option<u32>, mobile: bool) -> bool {
	!mobile || age.map_or(false, |age| age >= head_retry_delay(latency))
}

// Body-only, bounded history. Modest 4:1 maximum preference keeps slower and
// unknown peers in circulation rather than trusting one fast peer exclusively.
#[derive(Default)]
struct BodyPeerPerformance {
	samples: Vec<(PeerAddr, u64, Instant)>,
	// Delivery debt only, never peer bans or shared request latency. Expiry
	// restores exploration; matched deliveries pay down debt two at a time.
	alternate_debt: Vec<(PeerAddr, u8, Instant)>,
	// Fresh-selection leases only. Retries and single-source fallback are unchanged.
	probe_leases: Vec<(PeerAddr, Instant)>,
	// Separate history so latency exploration does not alter debt probation.
	fresh_leases: Vec<(PeerAddr, Instant)>,
	// Interval diagnostics only; never consulted by scheduling.
	counters: Vec<(PeerAddr, [u64; 5])>,
	// Adapter-entry delivery timing only; never feeds scheduling weights.
	delivery_counters: Vec<(PeerAddr, [u64; 3])>,
}

impl BodyPeerPerformance {
	fn record_delivery(&mut self, peer: &PeerAddr, age: Duration) {
		let ms = age.as_millis().min(u64::MAX as u128) as u64;
		if let Some((_, values)) = self.delivery_counters.iter_mut().find(|(p, _)| p == peer) {
			values[0] = values[0].saturating_add(1);
			values[1] = values[1].saturating_add(ms);
			values[2] = values[2].max(ms);
		} else if self.delivery_counters.len() < 64 {
			self.delivery_counters.push((peer.clone(), [1, ms, ms]));
		}
	}
	fn recent_latency(&self, peer: &PeerAddr, now: Instant) -> Option<u64> {
		self.samples.iter().find(|(p, _, at)| p == peer && now.saturating_duration_since(*at) < Duration::from_secs(300)).map(|(_, ms, _)| *ms)
	}

	// Limit exploration only when a measured, healthy alternative is much
	// faster. Unknown/stale peers and single-source fallback keep their normal
	// weights. This changes fresh requests only, never validation or rescue.
	fn fresh_weights(&self, peers: &[PeerAddr], now: Instant, mobile: bool) -> Vec<u64> {
		let healthy = peers.iter().any(|p| !self.on_probation(p, now));
		let fastest = peers.iter().filter(|p| !self.on_probation(p, now))
			.filter_map(|p| self.recent_latency(p, now)).min();
		peers.iter().map(|peer| {
			let slow = mobile && fastest.zip(self.recent_latency(peer, now)).map_or(false, |(best, ms)| ms >= 250 && ms >= best.saturating_mul(4));
			if slow && self.fresh_leases.iter().any(|(p, at)| p == peer && now.saturating_duration_since(*at) < Duration::from_secs(10)) {
				0
			} else {
				self.fresh_weight(peer, now, healthy)
			}
		}).collect()
	}

	fn on_probation(&self, peer: &PeerAddr, now: Instant) -> bool {
		self.alternate_debt.iter().any(|(p, debt, at)| p == peer && *debt >= 3 && now.saturating_duration_since(*at) < Duration::from_secs(60))
	}

	fn fresh_weight(&self, peer: &PeerAddr, now: Instant, healthy_alternative: bool) -> u64 {
		if healthy_alternative && self.on_probation(peer, now) && self.probe_leases.iter().any(|(p, at)| p == peer && now.saturating_duration_since(*at) < Duration::from_secs(10)) {
			0
		} else {
			self.weight(peer, now)
		}
	}

	fn selected_fresh(&mut self, peer: &PeerAddr, now: Instant) {
		self.fresh_leases.retain(|(_, at)| now.saturating_duration_since(*at) < Duration::from_secs(10));
		if let Some((_, at)) = self.fresh_leases.iter_mut().find(|(p, _)| p == peer) {
			*at = now;
		} else {
			if self.fresh_leases.len() >= 64 { self.fresh_leases.remove(0); }
			self.fresh_leases.push((peer.clone(), now));
		}
		self.probe_leases.retain(|(_, at)| now.saturating_duration_since(*at) < Duration::from_secs(10));
		if self.on_probation(peer, now) {
			if let Some((_, at)) = self.probe_leases.iter_mut().find(|(p, _)| p == peer) {
				*at = now;
			} else {
				if self.probe_leases.len() >= 64 { self.probe_leases.remove(0); }
				self.probe_leases.push((peer.clone(), now));
			}
		}
	}

	fn score(&self, peer: &PeerAddr, now: Instant) -> (Option<u64>, u64, &'static str) {
		let ewma = self.samples.iter().find(|(p, _, at)| p == peer && now.saturating_duration_since(*at) < Duration::from_secs(300)).map(|(_, ms, _)| *ms);
		(ewma, self.weight(peer, now), if self.on_probation(peer, now) { "delivery_debt" } else if ewma.is_some() { "post_process_ewma" } else { "unknown_or_expired" })
	}
	fn alternate_resolved(&mut self, peer: &PeerAddr, age: Duration, now: Instant) {
		if age < Duration::from_millis(500) { return; }
		self.alternate_debt.retain(|(_, _, at)| now.saturating_duration_since(*at) < Duration::from_secs(60));
		if let Some((_, debt, at)) = self.alternate_debt.iter_mut().find(|(p, _, _)| p == peer) {
			*debt = debt.saturating_add(1).min(6);
			*at = now;
		} else {
			if self.alternate_debt.len() >= 64 {
				if let Some((idx, _)) = self.alternate_debt.iter().enumerate().min_by_key(|(_, (_, _, at))| *at) {
					self.alternate_debt.swap_remove(idx);
				}
			}
			self.alternate_debt.push((peer.clone(), 1, now));
		}
	}

	fn count(&mut self, peer: &PeerAddr, event: usize, value: u64) {
		if let Some((_, counts)) = self.counters.iter_mut().find(|(p, _)| p == peer) {
			counts[event] = counts[event].saturating_add(value);
		} else if self.counters.len() < 64 {
			let mut counts = [0; 5];
			counts[event] = value;
			self.counters.push((peer.clone(), counts));
		}
	}

	fn matched_delivery(&mut self, peer: &PeerAddr) {
		if let Some((_, debt, _)) = self.alternate_debt.iter_mut().find(|(p, _, _)| p == peer) {
			*debt = debt.saturating_sub(2);
		}
	}

	fn observe(&mut self, peer: &PeerAddr, elapsed: Duration, now: Instant) {
		self.samples.retain(|(_, _, updated)| now.saturating_duration_since(*updated) < Duration::from_secs(300));
		let ms = elapsed.as_millis().clamp(1, 30_000) as u64;
		if let Some((_, average, updated)) = self.samples.iter_mut().find(|(p, _, _)| p == peer) {
			*average = (*average * 3 + ms) / 4;
			*updated = now;
		} else {
			if self.samples.len() >= 64 {
				if let Some((idx, _)) = self.samples.iter().enumerate().min_by_key(|(_, (_, _, t))| *t) {
					self.samples.swap_remove(idx);
				}
			}
			self.samples.push((peer.clone(), ms, now));
		}
	}

	fn weight(&self, peer: &PeerAddr, now: Instant) -> u64 {
		if self.alternate_debt.iter().any(|(p, debt, at)| p == peer && *debt >= 3 && now.saturating_duration_since(*at) < Duration::from_secs(60)) {
			return 1;
		}
		self.samples.iter().find(|(p, _, updated)| p == peer && now.saturating_duration_since(*updated) < Duration::from_secs(300))
			.map_or(2, |(_, ms, _)| (400 / (*ms).max(1)).clamp(1, 4))
	}
}

fn reserve_retry_budget(available: usize, reservations: usize) -> usize {
	available.saturating_sub(reservations)
}

fn gap_retry_delta(series_len: usize, mobile: bool) -> u64 {
	let small_window = if mobile { 12 } else { 8 };
	if series_len <= small_window { 1 } else { cmp::max(7, series_len as u64 / 5) }
}

fn eligible_received_run(first: u64, last: u64, delta: u64) -> bool {
	first > 0 && last.saturating_sub(first) > delta
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetryReservation {
	sent: Instant,
	expires: Instant,
	startup: bool,
}

fn expire_retry_slots(slots: &mut VecDeque<RetryReservation>, now: Instant, latency: Option<Duration>) -> usize {
	if let Some(latency) = latency {
		for slot in slots.iter_mut().filter(|slot| slot.startup) {
			// Replace the no-sample fallback once, using the original send time.
			// Never extend a reservation or reprice normal measured reservations.
			if let Some(measured_expiry) = slot.sent.checked_add(latency) {
				slot.expires = slot.expires.min(measured_expiry);
				slot.startup = false;
			}
		}
	}
	slots.retain(|slot| slot.expires > now);
	slots.len()
}

fn stale_now(secs: u64) -> Instant {
	Instant::now()
		.checked_sub(Duration::from_secs(secs))
		.unwrap_or_else(Instant::now)
}

fn take_rate_limit(last: &RwLock<Instant>, secs: u64) -> bool {
	let now = Instant::now();
	let mut slot = last.write();
	if now.saturating_duration_since(*slot) >= Duration::from_secs(secs) {
		*slot = now;
		true
	} else {
		false
	}
}

pub struct BodySync {
	last_peer_diagnostics: RwLock<Instant>,
	peer_performance: RwLock<BodyPeerPerformance>,
	chain: Arc<Chain>,
	required_capabilities: RwLock<Capabilities>,
	request_tracker: RequestTracker<Hash>,
	// Serialize budget calculation through all routine sends, not just series
	// traversal. Always try_lock: receive callbacks must never wait for a sender.
	request_dispatch: Mutex<()>,
	request_series: RwLock<Vec<(Hash, u64)>>, // Hash, height
	pibd_params: Arc<PibdParams>,
	last_retry_height: RwLock<u64>,
	retry_expiration_times: RwLock<VecDeque<RetryReservation>>,
	excluded_peers: RwLock<HashSet<PeerAddr>>,
	last_apply_log: RwLock<(Instant, u64)>,
	last_highest_height: RwLock<u64>,
	last_send_stats: RwLock<LastSendStats>,
	last_timeouts: RwLock<usize>,
	last_fallback_log: RwLock<Instant>,
	last_empty_getblock_log: RwLock<Instant>,
	last_stored_replay_err: RwLock<Instant>,
	last_gap_log: RwLock<Instant>,
	last_retry_log: RwLock<Instant>,
	last_head_retry_log: RwLock<Instant>,
	last_stored_request_cleanup: RwLock<Instant>,
	head_retry: RwLock<HeadRetry>,
}

// The pool is lazy and thread-local, and leases a distinct context for nested
// calls. Keep the operation result nested: context creation errors previously
// returned immediately, while replay/orphan errors follow their existing handlers.
fn with_body_sync_context<T>(
	f: impl FnOnce(&mut Secp256k1) -> T,
) -> Result<T, mwc_chain::Error> {
	mwc_util::secp_static::with_commit_mut(mwc_chain::Error::from, |secp| Ok(f(secp)))
}

#[cfg(test)]
mod context_tests {
	use super::*;
	use mwc_crates::secp::ContextFlag;

	#[test]
	fn mobile_lookahead_is_bounded_and_preserves_genesis_and_desktop() {
		assert_eq!(body_height_window(true, 0, 15), 8);
		assert_eq!(body_height_window(true, 1, 15), 12);
		assert_eq!(body_height_window(true, u64::MAX, 15), 12);
		assert!(body_height_window(true, 100, 15) < 15);
		assert_eq!(body_height_window(false, 100, 15), 7);
		assert_eq!(body_height_window(false, 100, 250), 125);
		assert_eq!(body_height_window(false, 0, 0), 1);
	}

	#[test]
	fn receive_refill_requires_committed_window_progress() {
		let series: Vec<_> = (101..=108).rev().map(|h| (Hash::default(), h)).collect();
		assert!(!series_needs_refill(&[], 100));
		assert!(!series_needs_refill(&series, 100)); // received orphans alone do not advance the window
		assert!(!series_needs_refill(&series, 99)); // rollback belongs to loop
		assert!(series_needs_refill(&series, 101));
		assert!(series_needs_refill(&series, 108));
		let refilled: Vec<_> = (102..=109).rev().map(|h| (Hash::default(), h)).collect();
		assert!(!series_needs_refill(&refilled, 101)); // no repeated rebuild without progress
		assert!(series_needs_refill(&refilled, 102));
	}

	#[test]
	fn refill_publication_does_not_overwrite_concurrent_refresh_or_invalidation() {
		let original = vec![(Hash::default(), 8)];
		let next = vec![(Hash::default(), 9)];
		let mut current = original.clone();
		assert!(publish_series_if_unchanged(&mut current, &original, next.clone()));
		assert!(!publish_series_if_unchanged(&mut current, &original, vec![]));
		assert_eq!(current, next);
		current.clear();
		assert!(!publish_series_if_unchanged(&mut current, &original, next));
		assert!(current.is_empty());
		// Same heights on another branch must also invalidate the snapshot.
		current = vec![(Hash::from_vec(&[1; 32]), 8)];
		assert!(!publish_series_if_unchanged(&mut current, &original, vec![]));
		assert_eq!(current.len(), 1);
	}

	#[cfg(feature = "test-support")]
	#[test]
	fn receive_refill_leaves_near_tip_and_busy_sender_to_loop() {
		use mwc_chain::types::NoopAdapter;
		use mwc_core::{genesis, global, pow};
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let dir = std::env::temp_dir().join(format!("mwc_receive_refill_{}_{}",
			std::process::id(), std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
		let chain = Arc::new(Chain::init(&secp, 0, dir.to_string_lossy().into_owned(),
			Arc::new(NoopAdapter {}), genesis::genesis_floo(&secp, 0), pow::verify_size,
			false, HashSet::new(), None, None, false).unwrap());
		let sync = BodySync::new(chain.clone());
		let original = vec![(chain.genesis().hash(0).unwrap(), 0)];
		*sync.request_series.write() = original.clone();
		{
			let guard = sync.request_series.write();
			sync.refill_request_series_after_progress().unwrap();
			assert_eq!(*guard, original);
		}
		sync.refill_request_series_after_progress().unwrap();
		assert_eq!(*sync.request_series.read(), original);
		// Missing future headers and exhausted ranges do not invent requests.
		assert!(sync.build_request_series(0, 0).unwrap().is_empty());
		assert!(matches!(sync.build_request_series(0, 8), Err(mwc_chain::Error::InvalidHeaderHeight(8))));
		assert_eq!(*sync.request_series.read(), original);
		// Both sends in one loop cycle share the already-reserved budget.
		let now = Instant::now();
		for _ in 0..2 {
			sync.retry_expiration_times.write().push_back(RetryReservation {
				sent: now, expires: now + Duration::from_secs(30), startup: false,
			});
		}
		let mut budget = reserve_retry_budget(7, sync.calc_retry_running_requests());
		assert_eq!(budget, 5);
		let dispatch = sync.request_dispatch.try_lock().unwrap();
		for _ in 0..2 {
			sync.send_requests(&dispatch, &mut budget, &vec![], &SyncPeers::new(), 0, 0).unwrap();
			assert_eq!(budget, 5);
		}
		// A receive refill cannot enter between the loop's two passes or its
		// spare-budget retries. This is nonblocking even from another thread.
		std::thread::scope(|scope| {
			scope.spawn(|| assert!(sync.request_dispatch.try_lock().is_none())).join().unwrap();
		});
		drop(dispatch);
		assert!(sync.request_dispatch.try_lock().is_some());
		drop(sync);
		drop(chain);
		std::fs::remove_dir_all(dir).unwrap();
	}

	#[test]
	fn dispatch_budget_observes_previous_sender_and_releases_after_failure() {
		let dispatch = Mutex::new(());
		let tracker = RequestTracker::<u64>::new();
		let peer = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let capacity = || tracker.calculate_needed_requests(3, 0, 0, 3, 7);
		let reservations = RwLock::new(0usize);
		{
			let _guard = dispatch.try_lock().unwrap();
			assert_eq!(capacity(), 7);
			// Model four original requests and two routine duplicate reservations.
			for key in 0..4 { tracker.register_request(key, peer.clone(), String::new()); }
			*reservations.write() = 2;
			std::thread::scope(|scope| {
				scope.spawn(|| assert!(dispatch.try_lock().is_none())).join().unwrap();
			});
		}
		{
			let _guard = dispatch.try_lock().unwrap();
			// The next sender gets one slot, not the pre-send snapshot of seven.
			assert_eq!(reserve_retry_budget(capacity(), *reservations.read()), 1);
			let token = tracker.register_request(4, peer.clone(), String::new());
			assert_eq!(reserve_retry_budget(capacity(), *reservations.read()), 0);
			tracker.rollback_request(&4, &token);
		}
		let _guard = dispatch.try_lock().unwrap();
		assert_eq!(reserve_retry_budget(capacity(), *reservations.read()), 1);
		tracker.remove_request(&0, &peer);
		assert_eq!(reserve_retry_budget(capacity(), *reservations.read()), 2);
	}

	#[test]
	fn probation_probes_are_bounded_and_preserve_fallback() {
		let now = Instant::now();
		let peer = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let mut performance = BodyPeerPerformance::default();
		performance.observe(&peer, Duration::from_millis(50), now);
		assert_eq!(performance.score(&peer, now), (Some(50), 4, "post_process_ewma"));
		for _ in 0..3 { performance.alternate_resolved(&peer, Duration::from_secs(1), now); }
		assert_eq!(performance.score(&peer, now), (Some(50), 1, "delivery_debt"));
		assert_eq!(performance.fresh_weight(&peer, now, true), 1);
		performance.selected_fresh(&peer, now);
		assert_eq!(performance.fresh_weight(&peer, now, true), 0);
		assert_eq!(performance.fresh_weight(&peer, now, false), 1);
		assert_eq!(performance.fresh_weight(&peer, now + Duration::from_secs(9), true), 0);
		assert_eq!(performance.fresh_weight(&peer, now + Duration::from_secs(10), true), 1);
		performance.matched_delivery(&peer);
		assert_eq!(performance.fresh_weight(&peer, now, true), 4);
		for _ in 0..5 { performance.alternate_resolved(&peer, Duration::from_secs(1), now); }
		assert_eq!(performance.fresh_weight(&peer, now, true), 0);
		assert_eq!(performance.fresh_weight(&peer, now + Duration::from_secs(60), true), 4);
		assert_eq!(performance.score(&peer, now + Duration::from_secs(300)), (None, 2, "unknown_or_expired"));
	}

	#[test]
	fn slow_peer_probes_preserve_fallback_expiry_and_desktop_weights() {
		let now = Instant::now();
		let fast = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let slow = PeerAddr::Ip("127.0.0.2:3414".parse().unwrap());
		let unknown = PeerAddr::Ip("127.0.0.3:3414".parse().unwrap());
		let peers = vec![fast.clone(), slow.clone(), unknown];
		let mut performance = BodyPeerPerformance::default();
		performance.observe(&fast, Duration::from_millis(50), now);
		performance.observe(&slow, Duration::from_millis(300), now);
		assert_eq!(performance.fresh_weights(&peers, now, true), vec![4, 1, 2]);
		performance.selected_fresh(&slow, now);
		assert_eq!(performance.fresh_weights(&peers, now, true), vec![4, 0, 2]);
		assert_eq!(performance.fresh_weights(&peers, now, false), vec![4, 1, 2]);
		assert_eq!(performance.fresh_weights(&[slow.clone()], now, true), vec![1]);
		assert_eq!(performance.fresh_weights(&peers, now + Duration::from_secs(9), true), vec![4, 0, 2]);
		assert_eq!(performance.fresh_weights(&peers, now + Duration::from_secs(10), true), vec![4, 1, 2]);
		assert_eq!(performance.fresh_weights(&peers, now + Duration::from_secs(300), true), vec![2, 2, 2]);
		// A fast but indebted peer is not a healthy alternative.
		for _ in 0..3 { performance.alternate_resolved(&fast, Duration::from_secs(1), now); }
		assert_eq!(performance.fresh_weights(&peers, now, true), vec![1, 1, 2]);
	}

	#[test]
	fn slow_peer_probes_require_both_absolute_and_relative_latency() {
		let now = Instant::now();
		let fast = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let slow = PeerAddr::Ip("127.0.0.2:3414".parse().unwrap());
		let peers = vec![fast.clone(), slow.clone()];
		for (best, other, expected) in [(50, 249, 1), (50, 250, 0), (100, 399, 1), (100, 400, 0), (300, 400, 1)] {
			let mut performance = BodyPeerPerformance::default();
			performance.observe(&fast, Duration::from_millis(best), now);
			performance.observe(&slow, Duration::from_millis(other), now);
			performance.selected_fresh(&slow, now);
			assert_eq!(performance.fresh_weights(&peers, now, true)[1], expected);
			// Fresh evidence of recovery restores normal selection immediately.
			performance.samples.clear();
			performance.observe(&fast, Duration::from_millis(50), now);
			performance.observe(&slow, Duration::from_millis(50), now);
			assert_eq!(performance.fresh_weights(&peers, now, true), vec![4, 4]);
		}
	}

	#[test]
	fn probation_probe_history_is_bounded() {
		let now = Instant::now();
		let mut performance = BodyPeerPerformance::default();
		for n in 1..100 {
			let peer = PeerAddr::Ip(format!("127.0.0.{}:3414", n).parse().unwrap());
			for _ in 0..3 { performance.alternate_resolved(&peer, Duration::from_secs(1), now); }
			performance.selected_fresh(&peer, now);
			assert!(performance.probe_leases.len() <= 64);
			assert!(performance.fresh_leases.len() <= 64);
		}
		let peer = PeerAddr::Ip("127.0.0.99:3414".parse().unwrap());
		performance.selected_fresh(&peer, now + Duration::from_secs(10));
		assert_eq!(performance.probe_leases.len(), 1);
		assert_eq!(performance.fresh_leases.len(), 1);
	}

	#[test]
	fn peer_diagnostics_are_bounded_and_do_not_change_weights() {
		let now = Instant::now();
		let peer = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let mut performance = BodyPeerPerformance::default();
		performance.count(&peer, 0, 2);
		performance.count(&peer, 1, 1);
		performance.count(&peer, 2, 120);
		assert_eq!(performance.counters[0].1, [2, 1, 120, 0, 0]);
		assert_eq!(performance.weight(&peer, now), 2);
		for n in 2..=100 {
			let other = PeerAddr::Ip(format!("127.0.0.{}:3414", n).parse().unwrap());
			performance.count(&other, 3, 1);
		}
		assert_eq!(performance.counters.len(), 64);
		assert_eq!(std::mem::take(&mut performance.counters).len(), 64);
		assert!(performance.counters.is_empty());
		assert_eq!(performance.weight(&peer, now), 2);
	}

	#[test]
	fn delivery_diagnostics_are_separate_bounded_and_resettable() {
		let now = Instant::now();
		let peer = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let mut performance = BodyPeerPerformance::default();
		performance.observe(&peer, Duration::from_millis(400), now);
		performance.record_delivery(&peer, Duration::from_millis(20));
		performance.record_delivery(&peer, Duration::from_millis(40));
		assert_eq!(performance.delivery_counters[0].1, [2, 60, 40]);
		assert_eq!(performance.recent_latency(&peer, now), Some(400));
		assert!(performance.counters.is_empty());
		for n in 2..100 {
			performance.record_delivery(&PeerAddr::Ip(format!("127.0.0.{}:3414", n).parse().unwrap()), Duration::from_millis(10));
		}
		assert_eq!(performance.delivery_counters.len(), 64);
		let window = std::mem::take(&mut performance.delivery_counters);
		assert_eq!(window[0].1, [2, 60, 40]);
		performance.record_delivery(&peer, Duration::from_millis(5));
		assert_eq!(performance.delivery_counters[0].1, [1, 5, 5]);
	}

	#[test]
	fn alternate_delivery_penalty_requires_repetition_and_recovers() {
		let now = Instant::now();
		let peer = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let mut performance = BodyPeerPerformance::default();
		for _ in 0..10 { performance.alternate_resolved(&peer, Duration::from_millis(499), now); }
		assert!(performance.alternate_debt.is_empty());
		for _ in 0..2 { performance.alternate_resolved(&peer, Duration::from_millis(500), now); }
		assert_eq!(performance.weight(&peer, now), 2);
		performance.alternate_resolved(&peer, Duration::from_millis(500), now);
		assert_eq!(performance.weight(&peer, now), 1);
		performance.matched_delivery(&peer);
		performance.observe(&peer, Duration::from_millis(50), now);
		assert_eq!(performance.weight(&peer, now), 4);
		for _ in 0..20 { performance.alternate_resolved(&peer, Duration::from_secs(1), now); }
		assert_eq!(performance.alternate_debt[0].1, 6);
		assert_eq!(performance.weight(&peer, now), 1);
		assert_eq!(performance.weight(&peer, now + Duration::from_secs(60)), 4);
		performance.matched_delivery(&peer);
		assert_eq!(performance.weight(&peer, now), 1);
		performance.matched_delivery(&peer);
		assert_eq!(performance.weight(&peer, now), 4);
	}

	#[test]
	fn alternate_delivery_history_is_bounded_and_timeout_is_not_recovery() {
		let now = Instant::now();
		let mut performance = BodyPeerPerformance::default();
		for n in 1..=100 {
			let peer = PeerAddr::Ip(format!("127.0.0.{}:3414", n).parse().unwrap());
			performance.alternate_resolved(&peer, Duration::from_secs(1), now + Duration::from_millis(n));
			assert!(performance.alternate_debt.len() <= 64);
		}
		let peer = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let later = now + Duration::from_secs(61);
		for _ in 0..3 { performance.alternate_resolved(&peer, Duration::from_secs(1), later); }
		assert_eq!(performance.alternate_debt.len(), 1);
		performance.observe(&peer, Duration::from_secs(30), later);
		assert_eq!(performance.alternate_debt[0].1, 3);
		assert_eq!(performance.weight(&peer, later), 1);
	}

	#[test]
	fn body_peer_preference_is_bounded_expires_and_recovers() {
		let now = Instant::now();
		let peer = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let mut performance = BodyPeerPerformance::default();
		assert_eq!(performance.weight(&peer, now), 2);
		performance.observe(&peer, Duration::from_millis(50), now);
		assert_eq!(performance.weight(&peer, now), 4);
		performance.observe(&peer, Duration::from_secs(30), now);
		assert_eq!(performance.weight(&peer, now), 1);
		for _ in 0..32 {
			performance.observe(&peer, Duration::from_millis(50), now);
		}
		assert_eq!(performance.weight(&peer, now), 4);
		assert_eq!(performance.weight(&peer, now + Duration::from_secs(300)), 2);
		for n in 2..=100 {
			let other = PeerAddr::Ip(format!("127.0.0.{}:3414", n).parse().unwrap());
			performance.observe(&other, Duration::ZERO, now + Duration::from_millis(n));
			assert!(performance.samples.len() <= 64);
		}
		performance.observe(&peer, Duration::from_secs(1), now + Duration::from_secs(301));
		assert_eq!(performance.samples.len(), 1);
	}

	#[test]
	fn blocking_retry_delay_is_adaptive_and_bounded() {
		assert_eq!(head_retry_delay(None), Duration::from_secs(2));
		assert_eq!(head_retry_delay(Some(0)), Duration::from_millis(500));
		assert_eq!(head_retry_delay(Some(100)), Duration::from_millis(500));
		assert_eq!(head_retry_delay(Some(200)), Duration::from_millis(600));
		assert_eq!(head_retry_delay(Some(1000)), Duration::from_secs(2));
		assert_eq!(head_retry_delay(Some(u32::MAX)), Duration::from_secs(2));
	}

	#[test]
	fn spare_retry_age_gate_preserves_desktop_and_handles_boundaries() {
		assert!(spare_retry_due(None, None, false));
		assert!(!spare_retry_due(None, Some(100), true));
		assert!(!spare_retry_due(Some(Duration::from_millis(499)), Some(100), true));
		assert!(spare_retry_due(Some(Duration::from_millis(500)), Some(100), true));
		assert!(!spare_retry_due(Some(Duration::from_millis(1999)), None, true));
		assert!(spare_retry_due(Some(Duration::from_secs(2)), None, true));
		assert!(!spare_retry_due(Some(Duration::from_millis(599)), Some(200), true));
		assert!(spare_retry_due(Some(Duration::from_millis(600)), Some(200), true));
	}

	#[test]
	fn blocking_retry_lease_limits_duplicates_until_resolution_or_timeout() {
		let now = Instant::now();
		let mut retry = HeadRetry::default();
		let lease = head_retry_lease(Some(100));
		assert_eq!(lease, Duration::from_secs(2));
		assert_eq!(head_retry_lease(None), Duration::from_secs(5));
		assert_eq!(head_retry_lease(Some(u32::MAX)), Duration::from_secs(5));
		assert!(retry.available(now, false, lease));
		retry.last_attempt = Some(now);
		retry.pending = Some((Hash::default(), now));
		let original = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let first = PeerAddr::Ip("127.0.0.2:3414".parse().unwrap());
		let second = PeerAddr::Ip("127.0.0.3:3414".parse().unwrap());
		retry.sent.push((Hash::default(), first.clone(), now));
		assert!(!retry.available(now + Duration::from_millis(1999), false, lease));
		assert!(retry.available(now + Duration::from_secs(2), false, lease));
		assert!(!retry.peer_eligible(Hash::default(), &original, &original));
		assert!(!retry.peer_eligible(Hash::default(), &first, &original));
		assert!(retry.peer_eligible(Hash::default(), &second, &original));
		retry.sent.push((Hash::default(), second, now + Duration::from_secs(2)));
		// Short lease expiry must not allow unlimited unresolved duplicates.
		assert!(!retry.available(now + Duration::from_secs(10), false, lease));
		assert!(!retry.available(now + Duration::from_secs(29), false, lease));
		assert!(retry.available(now + Duration::from_secs(30), false, lease));
		assert_eq!(retry.sent.len(), 1);
		assert!(retry.pending.is_none());
	}

	#[test]
	fn blocking_retry_resolution_and_send_failures_respect_cooldown() {
		let now = Instant::now();
		let mut retry = HeadRetry { pending: Some((Hash::default(), now)), last_attempt: Some(now), ..HeadRetry::default() };
		let lease = head_retry_lease(Some(100));
		assert!(!retry.available(now + Duration::from_millis(100), true, lease));
		assert!(retry.pending.is_none());
		assert!(!retry.available(now + Duration::from_millis(499), false, lease));
		assert!(retry.available(now + Duration::from_millis(500), false, lease));
		// Failed send records an attempt, but does not create a pending lease.
		retry.last_attempt = Some(now + Duration::from_secs(2));
		assert!(!retry.available(now + Duration::from_millis(2499), false, lease));
		assert!(retry.available(now + Duration::from_millis(2500), false, lease));
	}

	#[test]
	fn small_window_can_retry_gap_with_three_received_successors() {
		for mobile in [false, true] {
			assert!(eligible_received_run(102, 104, gap_retry_delta(8, mobile)));
			assert!(!eligible_received_run(102, 103, gap_retry_delta(8, mobile)));
			assert!(!eligible_received_run(0, 0, gap_retry_delta(8, mobile)));
			assert!(!eligible_received_run(104, 102, gap_retry_delta(8, mobile)));
			assert_eq!(gap_retry_delta(40, mobile), 8);
		}
		for size in 9..=12 {
			assert_eq!(gap_retry_delta(size, true), 1);
			assert_eq!(gap_retry_delta(size, false), 7);
		}
		assert_eq!(gap_retry_delta(13, true), 7);
	}

	#[test]
	fn retry_expiration_removes_expired_tail_and_exact_boundary() {
		let now = Instant::now();
		let future = now + Duration::from_secs(10);
		let slot = |expires| RetryReservation { sent: now, expires, startup: false };
		let mut slots = VecDeque::from(vec![slot(future), slot(now - Duration::from_secs(1)), slot(now)]);
		assert_eq!(expire_retry_slots(&mut slots, now, None), 1);
		assert_eq!(slots, VecDeque::from(vec![slot(future)]));
		assert_eq!(expire_retry_slots(&mut slots, future, None), 0);
	}

	#[test]
	fn startup_retry_reservations_release_budget_when_samples_arrive() {
		let sent = Instant::now();
		let mut slots = VecDeque::from(vec![RetryReservation {
			sent, expires: sent + Duration::from_secs(30), startup: true,
		}; 6]);
		let now = sent + Duration::from_secs(5);
		assert_eq!(expire_retry_slots(&mut slots, now, None), 6);
		// Reproduce six reservations with 25 seconds left and 292 ms latency.
		assert_eq!(expire_retry_slots(&mut slots, now, Some(Duration::from_millis(292))), 0);
		assert_eq!(7usize.saturating_sub(slots.len()), 7);
	}

	#[test]
	fn startup_retry_repricing_preserves_young_and_measured_reservations() {
		let sent = Instant::now();
		let mut slots = VecDeque::from(vec![
			RetryReservation { sent, expires: sent + Duration::from_secs(30), startup: true },
			RetryReservation { sent, expires: sent + Duration::from_secs(3), startup: false },
		]);
		assert_eq!(expire_retry_slots(&mut slots, sent + Duration::from_millis(100), Some(Duration::from_millis(292))), 2);
		assert_eq!(slots[0].expires, sent + Duration::from_millis(292));
		assert!(!slots[0].startup);
		// Later lower latency must not repeatedly shrink ordinary reservations.
		assert_eq!(expire_retry_slots(&mut slots, sent + Duration::from_millis(200), Some(Duration::from_millis(1))), 2);
		assert_eq!(expire_retry_slots(&mut slots, sent + Duration::from_millis(292), None), 1);
		assert_eq!(slots[0].expires, sent + Duration::from_secs(3));
	}

	#[test]
	fn startup_retry_repricing_never_extends_timeout() {
		let sent = Instant::now();
		let mut slots = VecDeque::from(vec![RetryReservation {
			sent, expires: sent + Duration::from_secs(30), startup: true,
		}]);
		assert_eq!(expire_retry_slots(&mut slots, sent, Some(Duration::from_secs(60))), 1);
		assert_eq!(slots[0].expires, sent + Duration::from_secs(30));
		assert_eq!(expire_retry_slots(&mut slots, sent + Duration::from_secs(30), None), 0);
	}

	#[test]
	fn repeated_sync_work_reuses_context_and_matches_fresh_commitments() {
		std::thread::spawn(|| {
			let fresh = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
			let mut first: *const Secp256k1 = std::ptr::null();
			for value in 0..32 {
				with_body_sync_context(|secp| {
					let address = secp as *const Secp256k1;
					if first.is_null() { first = address; }
					assert_eq!(first, address);
					// Compare failures too: zero with zero blinding is not a valid commitment.
					assert_eq!(secp.commit_value(value), fresh.commit_value(value));
				}).unwrap();
			}
		}).join().unwrap();
	}

	#[test]
	fn operation_failure_is_preserved_and_context_remains_reusable() {
		std::thread::spawn(|| {
			let mut first = std::ptr::null();
			let result: Result<(), mwc_chain::Error> = with_body_sync_context(|secp| {
				first = secp as *const Secp256k1;
				Err(mwc_chain::Error::Other("body sync regression sentinel".into()))
			}).unwrap();
			assert!(matches!(result, Err(mwc_chain::Error::Other(ref message))
				if message == "body sync regression sentinel"));
			with_body_sync_context(|secp| {
				assert_eq!(first, secp as *const Secp256k1);
				secp.commit_value(7).unwrap();
			}).unwrap();
		}).join().unwrap();
	}

	#[test]
	fn nested_sync_work_does_not_alias_mutable_contexts() {
		std::thread::spawn(|| {
			with_body_sync_context(|outer| {
				with_body_sync_context(|inner| {
					assert!(!std::ptr::eq(outer, inner));
					assert_eq!(outer.commit_value(7).unwrap(), inner.commit_value(7).unwrap());
				}).unwrap();
			}).unwrap();
		}).join().unwrap();
	}
}

impl BodySync {
	pub fn new(chain: Arc<Chain>) -> BodySync {
		BodySync {
			last_peer_diagnostics: RwLock::new(Instant::now()),
			peer_performance: RwLock::new(BodyPeerPerformance::default()),
			pibd_params: chain.get_pibd_params().clone(),
			chain,
			required_capabilities: RwLock::new(Capabilities::UNKNOWN),
			request_tracker: RequestTracker::new(),
			request_dispatch: Mutex::new(()),
			request_series: RwLock::new(Vec::new()),
			last_retry_height: RwLock::new(0),
			retry_expiration_times: RwLock::new(VecDeque::new()),
			excluded_peers: RwLock::new(HashSet::new()),
			last_apply_log: RwLock::new((
				Instant::now()
					.checked_sub(Duration::from_secs(10))
					.unwrap_or_else(Instant::now),
				0,
			)),
			last_highest_height: RwLock::new(0),
			last_send_stats: RwLock::new(LastSendStats {
				sent_heights: Vec::new(),
				peers_before_filter: 0,
				peers_after_filter: 0,
				new_requests: 0,
				note: "no send_requests yet".into(),
			}),
			last_timeouts: RwLock::new(0),
			last_fallback_log: RwLock::new(stale_now(BODY_SYNC_PEER_LOG_SECS)),
			last_empty_getblock_log: RwLock::new(stale_now(BODY_SYNC_PEER_LOG_SECS)),
			last_stored_replay_err: RwLock::new(stale_now(BODY_SYNC_PEER_LOG_SECS)),
			last_gap_log: RwLock::new(stale_now(15)),
			last_retry_log: RwLock::new(stale_now(15)),
			last_head_retry_log: RwLock::new(stale_now(15)),
			last_stored_request_cleanup: RwLock::new(stale_now(1)),
			head_retry: RwLock::new(HeadRetry::default()),
		}
	}

	fn log_empty_getblock_once(&self, why: &str, series_len: Option<usize>) {
		if !take_rate_limit(&self.last_empty_getblock_log, BODY_SYNC_PEER_LOG_SECS) {
			return;
		}
		let series = series_len.unwrap_or_else(|| self.request_series.read_recursive().len());
		info!(
			"body sync GetBlock not sent: {} (series={}, in_flight={})",
			why,
			series,
			self.request_tracker.get_requests_num()
		);
	}

	pub fn get_peer_capabilities(&self) -> Capabilities {
		self.required_capabilities.read_recursive().clone()
	}

	// Expected that it is called ONLY when state_sync is done
	pub fn request(
		&self,
		in_peers: &Arc<Peers>,
		sync_state: &SyncState,
		sync_peers: &SyncPeers,
		best_height: u64,
	) -> Result<SyncResponse, mwc_chain::Error> {
		if let Some(lines) = mwc_util::sync_diagnostics::summary() { for line in lines { info!("{}", line); } }
		// Do not gate block requests on spent-commitment index readiness. PIBD
		// intentionally starts with an empty retained-body index, and the blocks
		// requested here populate it one by one. The same readiness state can also
		// occur temporarily during reorg or recovery, so treating it as BadState
		// could reset an otherwise valid chain.
		// check if we need something
		let mut head = self.chain.head()?;
		self.log_request_gap(head.height);
		// 32 was the original stored-body replay size (~orphan window).
		// process_block_multiple / leftover-prune still cap the commit unit
		// (1 on iOS). Do not raise this to 128: a shutdown rolls back the
		// in-flight uncommitted chunk only, but 128 held HEAD too long.
		const STORED_REPLAY_BATCH: u64 = 32;
		const STORED_REPLAY_ERR_BACKOFF: Duration = Duration::from_secs(2);
		let mut replayed_stored = 0u64;
		if self.chain.archive_mode() {
			if let Some(resumed) = self.chain.resume_body_head_from_stored_blocks()? {
				head = resumed;
			}
			// Fallback only: the dedicated stored-body-replay thread is the engine.
			// Keep a small replay here if that thread is not running.
			let replay_backoff = Instant::now()
				.saturating_duration_since(*self.last_stored_replay_err.read_recursive())
				< STORED_REPLAY_ERR_BACKOFF;
			if replay_backoff {
				head = self.chain.head()?;
				if self.chain.has_stored_body_after_head()? {
					sync_state.update(SyncStatus::BodySync {
						archive_height: 0,
						current_height: head.height,
						highest_height: best_height,
					});
					return Ok(SyncResponse::new(
						SyncRequestResponses::Syncing,
						self.get_peer_capabilities(),
						format!(
							"stored body replay backing off, head.height={}",
							head.height
						),
					));
				}
			} else if self.chain.is_stop_requested() {
				head = self.chain.head()?;
				warn!(
					"stored-body replay aborted by shutdown at height {}, HEAD remains {}",
					head.height.saturating_add(1),
					head.height
				);
				sync_state.update(SyncStatus::BodySync {
					archive_height: 0,
					current_height: head.height,
					highest_height: best_height,
				});
				return Ok(SyncResponse::new(
					SyncRequestResponses::Syncing,
					self.get_peer_capabilities(),
					format!(
						"stored body replay aborted by shutdown, head.height={}",
						head.height
					),
				));
			} else {
				match with_body_sync_context(|secp| {
					// Reconciliation above stays outside retryable replay handling:
					// its errors must still propagate without being reclassified.
					self.chain.replay_stored_bodies_after_reconcile(secp, STORED_REPLAY_BATCH)
				})? {
					Ok(n) => {
						replayed_stored = n;
						// HEAD was already reconciled under the PMMR locks. Refresh
						// even when no bodies were applied: reconciliation or a concurrent
						// receiver may have changed HEAD. Do not reconcile twice per loop.
						head = self.chain.head()?;
					}
					Err(e) if e.is_stored_body_replay_retryable() => {
						*self.last_stored_replay_err.write() = Instant::now();
						if take_rate_limit(&self.last_empty_getblock_log, BODY_SYNC_PEER_LOG_SECS) {
							if e.is_pmmr_rewind_forward() {
								warn!(
									"stored-body-replay: cannot rewind PMMR forward; backing off: {}",
									e
								);
							} else {
								warn!(
									"stored body replay error at head {}, backing off: {}",
									head.height, e
								);
							}
						}
						head = self.chain.head().unwrap_or(head);
						sync_state.update(SyncStatus::BodySync {
							archive_height: 0,
							current_height: head.height,
							highest_height: best_height,
						});
						return Ok(SyncResponse::new(
							SyncRequestResponses::Syncing,
							self.get_peer_capabilities(),
							format!("stored body replay error, head.height={}", head.height),
						));
					}
					Err(e) => return Err(e),
				}
			}
		}
		let header_head = self.chain.header_head()?;

		// Do not GetBlock until HEAD has caught the contiguous stored tip.
		if self.chain.archive_mode()
			&& (replayed_stored == STORED_REPLAY_BATCH
				|| self.chain.has_stored_body_after_head()?)
		{
			head = self.chain.head()?;
			sync_state.update(SyncStatus::BodySync {
				archive_height: 0,
				current_height: head.height,
				highest_height: best_height,
			});
			return Ok(SyncResponse::new(
				SyncRequestResponses::Syncing,
				self.get_peer_capabilities(),
				format!("replaying stored bodies, head.height={}", head.height),
			));
		}

		let max_avail_height = cmp::min(best_height, header_head.height);
		self.invalidate_stale_request_series(max_avail_height)?;

		// BodySync is only the bulk height catch-up path. Once the body head is
		// within the normal near-tip window, readiness is intentionally based on
		// height rather than fork_point. Normal block handling owns branch
		// reconciliation: orphan tracking requests missing ancestors and
		// Chain::process_block fully validates and applies the branch when it
		// connects. Reorgs beyond the configured cut-through horizon are
		// deliberately outside the automatic-rewind policy.
		if head.height > max_avail_height.saturating_sub(7) {
			// Expected by QT wallet
			info!(
				"synchronized at {} @ {} [{}]",
				head.total_difficulty.to_num(),
				head.height,
				head.last_block_h
			);

			// sync is done, we are ready.
			return Ok(SyncResponse::new(
				SyncRequestResponses::BodyReady,
				Capabilities::UNKNOWN,
				format!(
					"head.height={} vs max_avail_height={}",
					head.height, max_avail_height
				),
			));
		}

		let archive_height =
			Chain::height_2_archive_height(self.chain.get_context_id(), best_height);

		let head = self.chain.head()?;
		let mut fork_point = self.chain.fork_point()?;

		if !self.chain.archive_mode() {
			if fork_point.height < archive_height {
				warn!(
					"body_sync: cannot sync full blocks earlier than horizon. will request txhashset"
				);
				return Ok(SyncResponse::new(
					SyncRequestResponses::BadState,
					self.get_peer_capabilities(),
					format!(
						"fork_point.height={} < archive_height={}",
						fork_point.height, archive_height
					),
				));
			}
		}

		// Historical-block capability is selected from the body head, not the fork
		// point, for the same reason: this path prefers BLOCK_HIST for bulk
		// catch-up from an old body height. Near-tip competing branches are left to
		// the regular orphan/reorg flow described above.
		//
		// Almost no public peers advertise BLOCK_HIST. If we require it exclusively
		// while the body head is still at (or below) the archive horizon, get_sync_peers
		// returns empty and archive catch-up stalls at height 0 forever. Fall back to
		// any sync peer and GetBlock the next heights; early-chain blocks are often
		// still available.
		let archive_catchup = self.chain.archive_mode() && head.height <= archive_height;

		// requested_blocks, check for expiration. Force-expire anything that
		// has sat more than 30s with no body; Instant::elapsed() previously
		// left in_flight stuck at 1 with timed_out=0.
		self.clear_stored_requests()?;
		let expired_excluded = self
			.request_tracker
			.retain_expired(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS, sync_peers);
		*self.last_timeouts.write() = expired_excluded.len();
		{
			let now = Instant::now();
			let mut performance = self.peer_performance.write();
			for peer in &expired_excluded {
				performance.count(peer, 4, 1);
				performance.observe(peer, Duration::from_secs(30), now);
			}
		}
		*self.excluded_peers.write() = expired_excluded;
		*self.last_highest_height.write() = best_height;

		// HeaderSync can return HeadersPibdReady (and BodySync then runs in
		// parallel) before height 1 is on the local header chain. Without
		// header 1, refresh_request_series cannot build heights 1..=8 and
		// GetBlock never fires. Stay on HeaderSync instead of pretending to
		// apply height 0.
		if fork_point.height == 0 {
			match self.chain.get_header_by_height(1) {
				Ok(_) => {}
				Err(e) if e.is_not_found() => {
					sync_state.update(SyncStatus::HeaderSync {
						current_height: header_head.height.min(archive_height),
						archive_height,
					});
					self.record_send_stats(Vec::new(), 0, 0, 0, "blocked: header 1 missing");
					self.log_empty_getblock_once("header 1 missing", None);
					self.maybe_log_apply_progress(
						fork_point.height,
						best_height,
						header_head.height,
					);
					return Ok(SyncResponse::new(
						SyncRequestResponses::Syncing,
						self.get_peer_capabilities(),
						format!(
							"body blocked on missing header 1 (header_head={})",
							header_head.height
						),
					));
				}
				Err(e) => return Err(e),
			}
		}

		let (peers, excluded_requests, excluded_peers, any_peer_count, hist_peer_count) =
			self.select_body_sync_peers(in_peers, archive_catchup, head.height);

		sync_state.update(SyncStatus::BodySync {
			archive_height: if self.chain.archive_mode() {
				0
			} else {
				archive_height
			},
			current_height: fork_point.height,
			highest_height: best_height,
		});

		if peers.is_empty() {
			self.record_send_stats(Vec::new(), 0, 0, 0, "no eligible peers");
			self.maybe_log_apply_progress(fork_point.height, best_height, header_head.height);
			let waiting_reason = if archive_catchup && hist_peer_count == 0 {
				"no peers advertise BLOCK_HIST; archive catch-up cannot request historical bodies"
			} else if excluded_peers > 0 {
				"eligible peers are at request capacity or excluded"
			} else {
				"no connected peers currently eligible for body requests"
			};
			info!(
				"body_sync: waiting for peers (connected={}, block_hist={}, excluded={}, head.height={}, reason={})",
				any_peer_count, hist_peer_count, excluded_peers, head.height, waiting_reason
			);
			if excluded_peers == 0 {
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					self.get_peer_capabilities(),
					format!(
						"No available peers (total={}, BLOCK_HIST={}), waiting Q size: {}",
						any_peer_count,
						hist_peer_count,
						self.request_tracker.get_requests_num()
					),
				));
			} else {
				return Ok(SyncResponse::new(
					SyncRequestResponses::Syncing,
					self.get_peer_capabilities(),
					format!(
						"Peers: {}  BLOCK_HIST: {}  Waiting Q size: {}",
						any_peer_count,
						hist_peer_count,
						self.request_tracker.get_requests_num()
					),
				));
			}
		}

		// Check for stuck orphan
		let next_height = fork_point.height.checked_add(1).ok_or_else(|| {
			mwc_chain::Error::DataOverflow(format!(
				"BodySync::request, fork_point.height={}",
				fork_point.height
			))
		})?;
		let next_block = match self.chain.get_header_by_height(next_height) {
			Ok(next_block) => Some(next_block),
			Err(e) if e.is_not_found() => None,
			Err(e) => return Err(e),
		};
		if let Some(next_block) = next_block {
			let next_block_hash = next_block.hash(self.chain.get_context_id())?;
			self.retry_blocking_request(next_block_hash, next_block.height, &peers)?;
			// Kick the stuck orphan
			match self.chain.get_orphan(&next_block_hash) {
				Some(orph) => {
					debug!("There is stuck orphan is found, let's kick it...");
					match with_body_sync_context(|secp| {
						self.chain.process_block(secp, orph.block, orph.opts, orph.source_peers)
					})? {
						Ok(_) => {
							let _ = self
								.chain
								.remove_orphan(next_block.height, &next_block_hash);
							self.log_applied_height(next_block.height);
							debug!(
								"push stuck orphan was successful. Should be able continue to go forward now"
							);
							fork_point = self.chain.fork_point()?;
						}
						Err(e) if e.is_known_block() => {
							// Another in-flight response can commit this block after
							// it was selected from the orphan pool. It is terminal for
							// this orphan entry, but it is not a body-sync failure.
							debug!(
								"Removing already-known stuck orphan {} at {}: {}",
								next_block_hash, next_block.height, e
							);
							let _ = self
								.chain
								.remove_orphan(next_block.height, &next_block_hash);
							self.request_series.write().clear();
						}
						Err(e) if e.is_bad_data() => {
							warn!(
								"Removing bad stuck orphan {} at {}. Error: {}",
								next_block_hash, next_block.height, e
							);
							let _ = self
								.chain
								.remove_orphan(next_block.height, &next_block_hash);
							self.request_series.write().clear();
						}
						Err(e) => return Err(e),
					}
				}
				None => {}
			}
		}

		// if we have 5 peers to sync from then ask for 50 blocks total (peer_count *
		// 10) max will be 80 if all 8 peers are advertising more work
		// also if the chain is already saturated with orphans, throttle

		let dispatch = match self.request_dispatch.try_lock() {
			Some(guard) => guard,
			None => {
				self.log_retry_decision("dispatch_busy", None, 0, 0);
				return Ok(SyncResponse::new(
					SyncRequestResponses::Syncing,
					self.get_peer_capabilities(),
					"Body request dispatch already active".to_string(),
				));
			}
		};
		let average_latency_ms = self.request_tracker.get_average_latency_ms();
		let request_limit = self.pibd_params.get_blocks_request_limit(average_latency_ms);
		let mut need_request = self.request_tracker.calculate_needed_requests(
			peers.len(),
			excluded_requests,
			excluded_peers,
			self.pibd_params.get_blocks_request_per_peer(),
			request_limit,
		);
		// Charge reservations once for this entire dispatch cycle, not once per
		// send_requests call (the loop may refill and call it a second time).
		let raw_capacity = need_request;
		let retry_slots = self.calc_retry_running_requests();
		need_request = reserve_retry_budget(raw_capacity, retry_slots);
		if mwc_util::sync_diagnostics::log_limits_now() {
			info!("body sync limits source=loop limit={} latency_ms={:?} peers={} excluded_peers={} excluded_requests={} in_flight={} needed={} raw_capacity={} retry_reservations={} peer_preference={}", request_limit, average_latency_ms, peers.len(), excluded_peers, excluded_requests, self.request_tracker.get_requests_num(), need_request, raw_capacity, retry_slots, option_env!("MWC_BODY_PEER_PREFERENCE") != Some("0"));
		}

		if need_request == 0 {
			let why = if raw_capacity > 0 { "retry reservations exhausted budget" } else { "request capacity exhausted" };
			self.log_retry_decision(if raw_capacity > 0 { "duplicate_throttle" } else { "request_budget_full" }, None, raw_capacity, retry_slots);
			self.record_send_stats(
				Vec::new(),
				peers.len(),
				peers.len(),
				0,
				why,
			);
			self.log_empty_getblock_once(why, None);
		}

		if need_request > 0 {
			// Always rebuild an empty series before the first send. An empty last()
			// used to leave send_requests with nothing to queue, so height 1 was
			// skipped when fork_point is 0.
			if self.request_series.read_recursive().is_empty() {
				self.refresh_request_series(fork_point.height, max_avail_height)?;
			}

			let mut waiting_requests = self.send_requests(
				&dispatch,
				&mut need_request,
				&peers,
				sync_peers,
				any_peer_count,
				hist_peer_count,
			)?;

			// We can send more requests, let's check if we need to update request_series
			if need_request > 0 {
				let mut need_refresh_request_series = false;

				// If request_series last (lowest height) is missing, rebuild.
				// last() == None (empty series) must still refresh so height 1 is requested.
				let last_request_series = self.request_series.read_recursive().last().cloned();
				if let Some((hash, height)) = last_request_series {
					debug!("Updating body request series for {} / {}", hash, height);
					if self.chain.block_exists(&hash)? {
						// The tail is updated, so we can request more
						need_refresh_request_series = true;
					}
				} else {
					need_refresh_request_series = true;
				}

				if need_refresh_request_series {
					self.refresh_request_series(fork_point.height, max_avail_height)?;
				}

				// Now we can try to submit more requests...
				waiting_requests = self.send_requests(
					&dispatch,
					&mut need_request,
					&peers,
					sync_peers,
					any_peer_count,
					hist_peer_count,
				)?;
			}

			if need_request > 0 && !waiting_requests.is_empty() {
				self.send_waiting_requests(&dispatch, waiting_requests, need_request, &peers, sync_peers)?;
			}
		}

		self.maybe_log_apply_progress(fork_point.height, best_height, header_head.height);

		return Ok(SyncResponse::new(
			SyncRequestResponses::Syncing,
			self.get_peer_capabilities(),
			format!(
				"Peers: {}  Waiting Q size: {}",
				peers.len() + excluded_peers,
				self.request_tracker.get_requests_num()
			),
		));
	}

	pub fn clear_request(&self, block_hash: &Hash, peer: &PeerAddr) {
		self.request_tracker.remove_request_by_key(block_hash, peer);
	}

	pub fn request_age_at(&self, hash: &Hash, peer: &PeerAddr, arrived: Instant) -> Option<Duration> {
		self.request_tracker.request_age_at(hash, peer, arrived)
	}

	pub fn record_delivery(&self, peer: &PeerAddr, age: Duration) {
		self.peer_performance.write().record_delivery(peer, age);
	}

	pub fn recieve_block_reporting(
		&self,
		valid_block: Option<bool>, // Some accepted/rejected, None means pending validation.
		block_hash: &Hash,
		peer: &PeerAddr,
		peers: &Arc<Peers>,
		sync_peers: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		let accepted_block = valid_block == Some(true);
		// Only the exact registered peer has a meaningful request timestamp.
		// Pending validation is delivery, not a claim of consensus validity.
		if valid_block != Some(false) {
			let now = Instant::now();
			let age = self.request_tracker.request_age_at(block_hash, peer, now);
			let mut performance = self.peer_performance.write();
			if let Some(age) = age {
				performance.matched_delivery(peer);
				performance.observe(peer, age, now);
				performance.count(peer, 1, 1);
				performance.count(peer, 2, age.as_millis().min(u64::MAX as u128) as u64);
			} else {
				performance.count(peer, 3, 1);
			}
		}
		let registered_peer = if accepted_block {
			self.request_tracker.remove_request_by_key_with_age(block_hash, peer).map(|(owner, age)| {
				if owner != *peer {
					self.peer_performance.write().alternate_resolved(&owner, age, Instant::now());
				}
				owner
			})
		} else {
			self.request_tracker.remove_request(block_hash, peer)
		};
		let matched_request = registered_peer
			.as_ref()
			.map_or(false, |registered_peer| registered_peer == peer);
		let resolved_request = registered_peer.is_some() && (accepted_block || matched_request);

		if resolved_request {
			if matched_request {
				match valid_block {
					Some(true) => sync_peers.report_ok_response(peer),
					Some(false) => {
						sync_peers.report_error_response(
							peer,
							format!("Get bad block {} for peer {}", block_hash, peer),
						);
					}
					None => {
						debug!(
							"Received pending-validation block {} from peer {}",
							block_hash, peer
						);
					}
				}
			}

			// let's request next package since we get this one...
			if self.request_tracker.get_update_requests_to_next_ask() == 0 {
				let head = self.chain.head()?;
				let required = *self.required_capabilities.read_recursive();
				let archive_catchup = required.contains(Capabilities::BLOCK_HIST);
				let (peers, excluded_requests, excluded_peers, any_peer_count, hist_peer_count) =
					self.select_body_sync_peers(peers, archive_catchup, head.height);
				if !peers.is_empty() {
					let Some(dispatch) = self.request_dispatch.try_lock() else {
						self.log_retry_decision("dispatch_busy", None, 0, 0);
						return Ok(());
					};
					// requested_blocks, check for expiration
					let average_latency_ms = self.request_tracker.get_average_latency_ms();
					let request_limit = self.pibd_params.get_blocks_request_limit(average_latency_ms);
					let mut need_request = self.request_tracker.calculate_needed_requests(
						peers.len(),
						excluded_requests,
						excluded_peers,
						self.pibd_params.get_blocks_request_per_peer(),
						request_limit,
					);
					need_request = reserve_retry_budget(need_request, self.calc_retry_running_requests());
					if mwc_util::sync_diagnostics::log_limits_now() {
						info!("body sync limits source=receive limit={} latency_ms={:?} peers={} excluded_peers={} excluded_requests={} in_flight={} needed={}", request_limit, average_latency_ms, peers.len(), excluded_peers, excluded_requests, self.request_tracker.get_requests_num(), need_request);
					}
					if need_request > 0 {
						// Refill the bounded window as committed HEAD advances rather
						// than waiting for the periodic loop to replace an exhausted list.
						self.refill_request_series_after_progress()?;
						self.send_requests(
							&dispatch,
							&mut need_request,
							&peers,
							sync_peers,
							any_peer_count,
							hist_peer_count,
						)?;
					}
				}
			}
		}
		Ok(())
	}

	fn select_body_sync_peers(
		&self,
		in_peers: &Arc<Peers>,
		archive_catchup: bool,
		min_height: u64,
	) -> (Vec<Arc<Peer>>, usize, usize, usize, usize) {
		let per_peer = self.pibd_params.get_blocks_request_per_peer();
		let excluded = self.excluded_peers.read_recursive();

		// Handshake/ping height is often 0. Keep those peers eligible while
		// requesting the first bodies (heights 1..=8).
		let peer_min_height = if min_height < 8 { 0 } else { min_height };

		let (hist_peers, hist_ex_req, hist_ex_peers) = sync_utils::get_sync_peers(
			in_peers,
			per_peer,
			Capabilities::BLOCK_HIST,
			peer_min_height,
			None,
			&self.request_tracker,
			&*excluded,
		);
		let hist_count = hist_peers.len() + hist_ex_peers;

		let (any_peers, any_ex_req, any_ex_peers) = sync_utils::get_sync_peers(
			in_peers,
			per_peer,
			Capabilities::UNKNOWN,
			peer_min_height,
			None,
			&self.request_tracker,
			&*excluded,
		);
		let any_count = any_peers.len() + any_ex_peers;
		if take_rate_limit(&self.last_peer_diagnostics, 30) {
			let selected = if archive_catchup && !hist_peers.is_empty() { &hist_peers } else { &any_peers };
			let now = Instant::now();
			let mut performance = self.peer_performance.write();
			let weights: Vec<_> = selected.iter().take(16).map(|p| (p.info.addr.clone(), performance.weight(&p.info.addr, now))).collect();
			let scores: Vec<_> = selected.iter().take(16).map(|p| (p.info.addr.clone(), performance.score(&p.info.addr, now))).collect();
			let addresses: Vec<_> = selected.iter().map(|p| p.info.addr.clone()).collect();
			let mobile_probes = cfg!(target_os = "ios") && option_env!("MWC_BODY_SLOW_PEER_PROBES") == Some("1");
			let fresh_weights: Vec<_> = addresses.iter().cloned().zip(if option_env!("MWC_BODY_PEER_PREFERENCE") == Some("0") { vec![1; addresses.len()] } else { performance.fresh_weights(&addresses, now, mobile_probes) }).take(16).collect();
			let counters = std::mem::take(&mut performance.counters);
			let delivery = std::mem::take(&mut performance.delivery_counters);
			let debt: Vec<_> = performance.alternate_debt.iter().filter(|(_, _, at)| now.saturating_duration_since(*at) < Duration::from_secs(60)).take(16).map(|(p, n, _)| (p.clone(), *n)).collect();
			drop(performance);
			info!("body sync delivery window_min_s=30 [matched_arrivals/arrival_total_ms/arrival_max_ms]={:?}; peer_stats age_total_ms includes local processing; interval counts may differ", delivery);
			info!("body sync peer_stats window_min_s=30 [fresh_selected/matched/age_total_ms/unmatched/timeout_peer_events]={:?} eligible_weights={:?} alternate_debt={:?} scores[ewma_ms/weight/reason]={:?} fresh_weights_snapshot={:?} probation_probe_s=10 preference_enabled={} slow_peer_probes={}", counters, weights, debt, scores, fresh_weights, option_env!("MWC_BODY_PEER_PREFERENCE") != Some("0"), mobile_probes && option_env!("MWC_BODY_PEER_PREFERENCE") != Some("0"));
			info!("body sync eligibility connected={} outbound={} inbound={} min_height={} archive={} any_candidates={} hist_candidates={} usable={} excluded={}",
				in_peers.iter().connected().count(), in_peers.iter().connected().outbound().count(), in_peers.iter().connected().inbound().count(),
				peer_min_height, archive_catchup, any_count, hist_count, selected.len(), excluded.len());
		}

		if archive_catchup && !hist_peers.is_empty() {
			*self.required_capabilities.write() =
				Capabilities::BLOCK_HIST | Capabilities::HEADER_HIST;
			(
				hist_peers,
				hist_ex_req,
				hist_ex_peers,
				any_count,
				hist_count,
			)
		} else {
			if archive_catchup && hist_peers.is_empty() {
				if take_rate_limit(&self.last_fallback_log, BODY_SYNC_PEER_LOG_SECS) {
					info!(
						"body sync BLOCK_HIST count={} yielded 0 usable peers; falling back to any sync peers (count={})",
						hist_count, any_count
					);
					info!(
						"body sync using N non-archive peers for GetBlock ({})",
						any_peers.len()
					);
				}
				// UNKNOWN so follow-up GetBlock and seed boost are not stuck
				// hunting BLOCK_HIST-only peers that do not exist.
				*self.required_capabilities.write() = Capabilities::UNKNOWN;
			} else {
				*self.required_capabilities.write() = Capabilities::HEADER_HIST;
			}
			(any_peers, any_ex_req, any_ex_peers, any_count, hist_count)
		}
	}

	fn record_send_stats(
		&self,
		sent_heights: Vec<u64>,
		peers_before_filter: usize,
		peers_after_filter: usize,
		new_requests: usize,
		note: &str,
	) {
		*self.last_send_stats.write() = LastSendStats {
			sent_heights,
			peers_before_filter,
			peers_after_filter,
			new_requests,
			note: note.to_string(),
		};
	}

	fn log_applied_height(&self, height: u64) {
		let highest = *self.last_highest_height.read_recursive();
		info!("body sync applied height {} / {}", height, highest);
		*self.last_apply_log.write() = (Instant::now(), height);
	}

	fn maybe_log_apply_progress(&self, current_height: u64, highest_height: u64, header_head: u64) {
		const APPLY_LOG_INTERVAL: u64 = 50;
		const APPLY_LOG_SECS: u64 = 10;
		let now = Instant::now();
		let mut last = self.last_apply_log.write();
		let (last_at, last_height) = *last;
		let elapsed = now.saturating_duration_since(last_at);
		if current_height.saturating_sub(last_height) >= APPLY_LOG_INTERVAL
			|| elapsed >= Duration::from_secs(APPLY_LOG_SECS)
		{
			let in_flight = self.request_tracker.get_requests_num();
			let series = self.request_series.read_recursive().len();
			let stats = self.last_send_stats.read_recursive();
			// This timer is NOT an applied block. process_block success logs
			// "body sync applied height" separately.
			if stats.note.contains("header 1 missing") {
				info!(
					"body sync blocked: header 1 is missing (header_head={})",
					header_head
				);
			}
			info!(
				"body sync still at height {} / {} (in_flight={}, series={}, header_head={})",
				current_height, highest_height, in_flight, series, header_head
			);
			let timeouts = *self.last_timeouts.read_recursive();
			if stats.sent_heights.is_empty() {
				info!(
					"body sync GetBlock: none ({}) new_requests={} peers_after_filter={}/{} timed_out={}",
					stats.note,
					stats.new_requests,
					stats.peers_after_filter,
					stats.peers_before_filter,
					timeouts
				);
			} else {
				info!(
					"body sync GetBlock: sent heights {:?} peers_after_filter={}/{} timed_out={} ({})",
					stats.sent_heights,
					stats.peers_after_filter,
					stats.peers_before_filter,
					timeouts,
					stats.note
				);
			}
			*last = (now, current_height);
		}
	}

	fn refresh_request_series(
		&self,
		fork_point_height: u64,
		max_avail_height: u64,
	) -> Result<(), mwc_chain::Error> {
		let previous = self.request_series.read_recursive().clone();
		let next = self.build_request_series(fork_point_height, max_avail_height)?;
		let mut series = self.request_series.write();
		publish_series_if_unchanged(&mut series, &previous, next);
		Ok(())
	}

	fn refill_request_series_after_progress(&self) -> Result<(), mwc_chain::Error> {
		if !cfg!(any(target_os = "ios", test)) || option_env!("MWC_RECEIVE_REFILL") == Some("0") {
			return Ok(());
		}
		// A sender already owns this lock? Let it finish; never queue receivers
		// behind one another just to refill. Keep the existing height/request caps.
		let previous = match self.request_series.try_read() {
			Some(series) => series.clone(),
			None => return Ok(()),
		};
		let head = self.chain.head()?;
		if !series_needs_refill(&previous, head.height) {
			return Ok(());
		}
		let header_head = self.chain.header_head()?;
		// Near-tip and fork recovery remain owned by the normal loop. Only
		// extend from a body HEAD authenticated on the current header branch.
		if head.height >= header_head.height.saturating_sub(100) {
			return Ok(());
		}
		let mut preparation = mwc_util::sync_diagnostics::Metric::ReceiveRefillPrepare.start();
		let canonical = match self.chain.get_header_by_height(head.height) {
			Ok(header) => header,
			Err(e) if e.is_not_found() => return Ok(()),
			Err(e) => return Err(e),
		};
		if canonical.hash(self.chain.get_context_id())? != head.last_block_h {
			return Ok(());
		}
		let next = self.build_request_series(head.height, header_head.height)?;
		preparation.success();
		drop(preparation);
		// Never hold the sender lock across chain reads. Discard stale work if
		// another builder/invalidator changed the snapshot while we prepared it.
		let Some(mut series) = self.request_series.try_write() else { return Ok(()); };
		let mut publication = mwc_util::sync_diagnostics::Metric::ReceiveRefillPublish.start();
		if publish_series_if_unchanged(&mut series, &previous, next) {
			publication.success();
		}
		Ok(())
	}

	fn build_request_series(
		&self,
		fork_point_height: u64,
		max_avail_height: u64,
	) -> Result<Vec<(Hash, u64)>, mwc_chain::Error> {
		let mut new_request_series: Vec<(Hash, u64)> = Vec::new();

		let request_height_window = body_height_window(
			cfg!(target_os = "ios"),
			fork_point_height,
			self.pibd_params.get_orphans_num_limit(),
		);
		let max_request_height = match fork_point_height.checked_add(request_height_window) {
			Some(max_request_height) => max_request_height,
			None => {
				let msg = format!(
					"BodySync::request, fork_point.height={}, request_height_window={}",
					fork_point_height, request_height_window
				);
				return Err(mwc_chain::Error::DataOverflow(msg));
			}
		};
		let max_height = cmp::min(max_request_height, max_avail_height);
		if max_height <= fork_point_height {
			info!(
				"body sync request series empty: max_height={} <= fork_point={} (header_head/max_avail={})",
				max_height, fork_point_height, max_avail_height
			);
			return Ok(new_request_series);
		}
		// Local headers can be gappy while HeaderSync is still applying 512-
		// header batches. Walk down from the window top until a stored header
		// exists instead of failing the whole BodySync request.
		let mut start_height = max_height;
		let mut current = loop {
			match self.chain.get_header_by_height(start_height) {
				Ok(header) => break header,
				Err(e) if e.is_not_found() => {
					if start_height <= fork_point_height.saturating_add(1) {
						info!(
							"body sync request series blocked: header {} missing (fork_point={}, max_height={})",
							start_height, fork_point_height, max_height
						);
						return Ok(new_request_series);
					}
					start_height = start_height.saturating_sub(1);
				}
				Err(e) => return Err(e),
			}
		};
		if start_height != max_height {
			info!(
				"body sync request series starting at height {} (wanted {})",
				start_height, max_height
			);
		}

		while current.height > fork_point_height {
			let hash = current.hash(self.chain.get_context_id())?;
			if !self.chain.is_orphan(&hash) {
				new_request_series.push((hash, current.height));
			}
			match self.chain.get_previous_header(&current) {
				Ok(prev) => current = prev,
				Err(e) if e.is_not_found() => {
					info!(
						"body sync request series walk stopped at height {} (missing parent)",
						current.height
					);
					break;
				}
				Err(e) => return Err(e),
			}
		}

		if let Some((hash, height)) = new_request_series.last() {
			debug!(
				"New body request series starting from {} / {}",
				hash, height
			);
		} else {
			info!(
				"body sync request series empty after refresh (fork_point={}, max_height={})",
				fork_point_height, max_height
			);
		}
		Ok(new_request_series)
	}

	fn is_block_recieved(&self, hash: &Hash) -> Result<bool, mwc_chain::Error> {
		Ok(self.chain.is_orphan(&hash) || self.chain.block_exists(&hash)?)
	}

	/// A request series is derived from one canonical header branch. Validate its
	/// highest retained entry before using it again so a header reorg or a lower
	/// sync target cannot leave body sync retrying hashes from an obsolete branch.
	fn invalidate_stale_request_series(
		&self,
		max_avail_height: u64,
	) -> Result<(), mwc_chain::Error> {
		// Keep the request-series lock while authenticating the anchor. send_requests
		// takes the same lock before reading or sending entries, so no stale entry can
		// be queued between validation and invalidation.
		let mut request_series = self.request_series.write();
		let Some((anchor_hash, anchor_height)) = request_series.first().cloned() else {
			return Ok(());
		};

		let stale_reason = if anchor_height > max_avail_height {
			Some(format!(
				"anchor height {} exceeds available height {}",
				anchor_height, max_avail_height
			))
		} else {
			match self.chain.get_header_by_height(anchor_height) {
				Ok(header) => {
					let canonical_hash = header.hash(self.chain.get_context_id())?;
					if canonical_hash == anchor_hash {
						None
					} else {
						Some(format!(
							"anchor {} at {} is no longer canonical (current {})",
							anchor_hash, anchor_height, canonical_hash
						))
					}
				}
				Err(e) if e.is_not_found() => Some(format!(
					"anchor header {} at {} is no longer available",
					anchor_hash, anchor_height
				)),
				Err(e) => return Err(e),
			}
		};

		if let Some(stale_reason) = stale_reason {
			let cancelled_requests = self
				.request_tracker
				.cancel_requests(request_series.iter().map(|(hash, _)| hash));
			request_series.clear();
			*self.last_retry_height.write() = 0;
			self.retry_expiration_times.write().clear();
			debug!(
				"Invalidated stale body request series ({}); cancelled {} tracked requests",
				stale_reason, cancelled_requests
			);
		}

		Ok(())
	}

	// Diagnostic locks are taken separately and released before logging or I/O.
	// Snapshots may race processing; missing series entries are unknown, not absent blocks.
	fn log_request_gap(&self, body: u64) {
		let now = Instant::now();
		let series = self.request_series.read_recursive().clone();
		let requests = self.request_tracker.diagnostic_requests(now);
		let next = body.checked_add(1);
		let next_hash = series.iter().find(|(_, h)| Some(*h) == next).map(|(hash, _)| hash);
		let next_request = next_hash.and_then(|hash| requests.iter().find(|(key, _, _)| key == hash));
		let describe = |req: Option<&(Hash, PeerAddr, Duration)>| -> String {
			match req {
				Some((hash, peer, age)) => format!("height:{:?} peer:{} age_ms:{}",
					series.iter().find(|(key, _)| key == hash).map(|(_, h)| h), peer, age.as_millis()),
				None => "untracked".to_string(),
			}
		};
		let received = match next_hash.map(|hash| self.is_block_recieved(hash)) {
			Some(Ok(true)) => "stored_or_orphan",
			Some(Ok(false)) => "not_received",
			Some(Err(_)) => "lookup_error",
			None => "unknown",
		};
		mwc_util::sync_diagnostics::observe_head(body, received == "not_received",
			next_request.map(|(_, peer, _)| peer.to_string()));
		if !take_rate_limit(&self.last_gap_log, 15) { return; }
		let (retry_slots, expired_slots, front_wait_ms) = {
			let expirations = self.retry_expiration_times.read_recursive();
			(expirations.len(), expirations.iter().filter(|t| t.expires < now).count(),
			 expirations.front().map(|t| t.expires.saturating_duration_since(now).as_millis()))
		};
		let last_retry = *self.last_retry_height.read_recursive();
		info!("body sync gap body={} next={:?} in_series={} received={:?} next_request=[{}] oldest=[{}] timeout_s={} retry_slots={} expired_slots={} front_wait_ms={:?} last_retry_height={}",
			body, next, next_hash.is_some(), received, describe(next_request),
			describe(requests.iter().max_by_key(|(_, _, age)| *age)),
			pibd_params::PIBD_REQUESTS_TIMEOUT_SECS, retry_slots, expired_slots, front_wait_ms, last_retry);
	}

	fn log_retry_decision(&self, reason: &str, height: Option<u64>, budget: usize, detail: usize) {
		if take_rate_limit(&self.last_retry_log, 15) {
			info!("body sync retry reason={} height={:?} budget={} detail={}", reason, height, budget, detail);
		}
	}

	// Replay and orphan processing can commit other blocks without adapter receipt
	// reporting. Cancel only hashes actually stored, never merely out-of-series ones.
	fn clear_stored_requests(&self) -> Result<(), mwc_chain::Error> {
		if !take_rate_limit(&self.last_stored_request_cleanup, 1) { return Ok(()); }
		let cleared = self.request_tracker.cancel_satisfied_requests(|hash| self.chain.block_exists(hash))?;
		if cleared > 0 { self.log_retry_decision("stored_requests_cleared", None, 0, cleared); }
		Ok(())
	}

	fn retry_blocking_request(&self, hash: Hash, height: u64, peers: &[Arc<Peer>]) -> Result<(), mwc_chain::Error> {
		let now = Instant::now();
		let Some(mut retry) = self.head_retry.try_write() else {
			self.log_head_retry("lock_busy", height, None, None);
			return Ok(());
		};
		let resolved = match retry.pending {
			Some((pending, _)) => self.is_block_recieved(&pending)?,
			None => false,
		};
		// Completed hashes release their budget even if a newer hash owns the lease.
		let mut outstanding = Vec::new();
		for (h, peer, sent) in &retry.sent {
			if !self.is_block_recieved(h)? { outstanding.push((*h, peer.clone(), *sent)); }
		}
		retry.sent = outstanding;
		if !retry.available(now, resolved, head_retry_lease(self.request_tracker.get_average_latency_ms())) {
			self.log_head_retry(if retry.sent.len() >= 2 { "rescue_budget_full" } else if retry.pending.is_some() { "pending_lease" } else { "cooldown" }, height, retry.pending, None);
			return Ok(());
		}
		if self.is_block_recieved(&hash)? {
			self.log_head_retry("already_received", height, retry.pending, None);
			return Ok(());
		}
		let Some(original) = self.request_tracker.get_expected_peer(&hash) else {
			self.log_head_retry("untracked", height, retry.pending, None);
			return Ok(());
		};
		let Some(age) = self.request_tracker.request_age_at(&hash, &original, now) else {
			self.log_head_retry("request_changed", height, retry.pending, None);
			return Ok(());
		};
		if age < head_retry_delay(self.request_tracker.get_average_latency_ms()) {
			self.log_head_retry("not_due", height, retry.pending, Some(age));
			return Ok(());
		}
		let mut rng = rand::rng();
		let alternate = peers.iter().filter(|p| retry.peer_eligible(hash, &p.info.addr, &original) && peer_can_serve_body_height(p.info.live_info.read_recursive().height, height)).choose(&mut rng);
		if let Some(peer) = alternate {
			retry.last_attempt = Some(now);
			match peer.send_block_request(hash, mwc_chain::Options::SYNC) {
				Ok(()) => {
					mwc_util::sync_diagnostics::record_body_send(hash.as_bytes(), peer.info.addr.to_string(), true);
					retry.sent.push((hash, peer.info.addr.clone(), now));
					retry.pending = Some((hash, now));
					self.log_head_retry("sent", height, retry.pending, Some(age));
					self.log_retry_decision("blocking_retry_sent", Some(height), 1, age.as_millis().min(usize::MAX as u128) as usize);
				}
				Err(e) => {
					self.log_head_retry("send_failed", height, retry.pending, Some(age));
					debug!("Blocking block retry send failed for {}: {}", peer.info.addr, e);
				}
			}
		} else {
			self.log_head_retry("no_alternate", height, retry.pending, Some(age));
		}
		Ok(())
	}

	fn log_head_retry(&self, reason: &str, height: u64, pending: Option<(Hash, Instant)>, age: Option<Duration>) {
		// Separate category/rate limit: routine request-budget messages must not
		// hide rescue lease or duplicate-budget decisions.
		if take_rate_limit(&self.last_head_retry_log, 5) {
			info!("body sync rescue reason={} height={} request_age_ms={:?} pending_hash={:?} pending_age_ms={:?}",
				reason, height, age.map(|a| a.as_millis()), pending.map(|p| p.0),
				pending.map(|p| p.1.elapsed().as_millis()));
		}
	}

	fn push_retry_expiration(&self, now: Instant) -> Result<(), mwc_chain::Error> {
		let measured_latency = self.request_tracker.get_average_latency();
		let retry_latency = measured_latency.unwrap_or_else(|| Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64));
		let retry_expiration = now.checked_add(retry_latency).ok_or_else(|| {
			mwc_chain::Error::DataOverflow(format!(
				"BodySync retry latency exceeds representable Instant range: {:?}",
				retry_latency
			))
		})?;

		self.retry_expiration_times
			.write()
			.push_back(RetryReservation { sent: now, expires: retry_expiration, startup: measured_latency.is_none() });
		Ok(())
	}

	fn duplicate_candidate(&self, hash: &Hash) -> Result<bool, mwc_chain::Error> {
		// Routine retries have no minimum age; their existing budget, alternate-
		// peer selection and duplicate throttle still apply.
		// A concurrent response may already have stored or orphaned this block.
		Ok(!self.is_block_recieved(hash)?)
	}

	fn calc_retry_running_requests(&self) -> usize {
		let now = Instant::now();
		let latency = self.request_tracker.get_average_latency();
		let mut retry_expiration_times = self.retry_expiration_times.write();
		// Moving latency estimates make expiration order non-monotonic.
		expire_retry_slots(&mut retry_expiration_times, now, latency)
	}

	// return waiting requests
	fn send_requests(
		&self,
		_dispatch: &MutexGuard<'_, ()>,
		need_request: &mut usize,
		peers: &Vec<Arc<Peer>>,
		sync_peers: &SyncPeers,
		any_peer_count: usize,
		hist_peer_count: usize,
	) -> Result<Vec<(u64, Hash)>, mwc_chain::Error> {
		// request_series naturally from head to tail, but requesting better to send from tail to the head....
		let mut peers = peers.clone();
		let peers_before_filter = peers.len();
		let mut waiting_heights: Vec<(u64, Hash)> = Vec::new();
		let mut empty_getblock_why: Option<(&'static str, usize)> = None;
		// Requests wuth try write because otherwise somebody else is sending, it is mean we are good...
		if let Some(request_series) = self.request_series.try_write() {
			if *need_request == 0 {
				self.record_send_stats(
					Vec::new(),
					peers_before_filter,
					peers_before_filter,
					0,
					"need_request=0 after retry throttle",
				);
				empty_getblock_why =
					Some(("need_request=0 after retry throttle", request_series.len()));
			} else {
				let mut rng = rand::rng();
				let now = Instant::now();

				let mut new_requests: Vec<(u64, Hash)> = Vec::new();

				let mut first_in_cache: u64 = 0;
				let mut last_in_cache: u64 = 0;
				let mut has10_idx: u64 = 0;
				let retry_delta = gap_retry_delta(request_series.len(), cfg!(target_os = "ios"));

				let mut skipped_received: Vec<u64> = Vec::new();
				for (hash, height) in request_series.iter().rev() {
					if self.is_block_recieved(&hash)? {
						skipped_received.push(*height);
						if last_in_cache.checked_add(1) == Some(*height) {
							last_in_cache = *height;
						} else {
							first_in_cache = *height;
							last_in_cache = *height;
						}
						continue;
					}

					if last_in_cache > 0 {
						if eligible_received_run(first_in_cache, last_in_cache, retry_delta) {
							has10_idx = first_in_cache;
						}
						first_in_cache = 0;
						last_in_cache = 0;
					}

					if self.request_tracker.has_request(&hash) {
						waiting_heights.push((height.clone(), hash.clone()));
					} else {
						new_requests.push((height.clone(), hash.clone()));
						if new_requests.len() >= *need_request {
							break;
						}
					}
				}

				// A received run at the end of the series has no following missing
				// entry to trigger the in-loop check above.
				if eligible_received_run(first_in_cache, last_in_cache, retry_delta) { has10_idx = first_in_cache; }
				let mut retry_requests: Vec<(u64, Hash)> = Vec::new();
				if has10_idx == 0 && !waiting_heights.is_empty() {
					self.log_retry_decision("gap_run_not_eligible", waiting_heights.first().map(|(h, _)| *h), *need_request, retry_delta as usize);
				}
				if has10_idx > 0 {
					for (height, req) in &waiting_heights {
						if *height >= has10_idx {
							break;
						}
						retry_requests.push((height.clone(), req.clone()));
					}
				}

				// Now let's try to send retry requests first
				if let Some(mut last_retry_height) = self.last_retry_height.try_write() {
					for (height, hash) in retry_requests {
						if height <= *last_retry_height {
							self.log_retry_decision("height_already_retried", Some(height), *need_request, 0);
							continue;
						}

						if *need_request == 0 {
							break;
						}

						// We don't want to send retry to the peer whom we already send the data
						if let Some(requested_peer) = self.request_tracker.get_expected_peer(&hash)
						{
							if !self.duplicate_candidate(&hash)? {
								self.log_retry_decision("duplicate_already_received", Some(height), *need_request, 0);
								continue;
							}
							let duplicate_request_count = cmp::min(*need_request, 2);
							let dup_peers: Vec<Arc<Peer>> = peers
								.iter()
								.filter(|p| {
									p.info.addr != requested_peer
										&& peer_can_serve_body_height(
											p.info.live_info.read_recursive().height,
											height,
										)
								})
								.cloned()
								.sample(&mut rng, duplicate_request_count);

							if dup_peers.is_empty() {
								self.log_retry_decision("no_alternate_peer", Some(height), *need_request, 0);
								break;
							}

							// we can do retry now
							let mut retry_sent = false;
							for p in dup_peers {
								if *need_request == 0 {
									break;
								}

								debug!(
									"Processing duplicated request for the block {} at {}, peer {:?}",
									hash, height, p.info.addr
								);
								match p.send_block_request(hash, mwc_chain::Options::SYNC) {
									Ok(_) => {
										mwc_util::sync_diagnostics::record_body_send(hash.as_bytes(), p.info.addr.to_string(), true);
										*need_request -= 1;
										retry_sent = true;
										self.push_retry_expiration(now)?;
									}
									Err(e) => {
										let msg = format!(
											"Failed to send duplicate block request to peer {}, {}",
											p.info.addr, e
										);
										warn!("{}", msg);
										sync_peers.report_no_response(&p.info.addr, msg);
										break;
									}
								}
							}

							if retry_sent {
								self.log_retry_decision("gap_retry_sent", Some(height), *need_request, 0);
								*last_retry_height = height;
							}
						}
					}
				}

				// Now sending normal requests, no retry for now
				if new_requests.is_empty() {
					let note = if request_series.is_empty() {
						"series empty"
					} else if !waiting_heights.is_empty() {
						"window exhausted: remaining bodies already requested"
					} else if !skipped_received.is_empty() {
						"all series heights already received"
					} else {
						"new_requests empty"
					};
					self.record_send_stats(
						Vec::new(),
						peers_before_filter,
						peers_before_filter,
						0,
						note,
					);
					empty_getblock_why = Some((note, request_series.len()));
				}
				if let Some((from_height, _)) =
					new_requests.iter().min_by_key(|(height, _)| *height)
				{
					info!(
						"body sync requesting blocks from height {} (peer count={}, BLOCK_HIST count={})",
						from_height, any_peer_count, hist_peer_count
					);
				}
				let mut sent_heights: Vec<u64> = Vec::new();
				let new_request_count = new_requests.len();
				for (height, hash) in new_requests {
					if *need_request == 0 {
						break;
					}
					// Safe: need_request == 0 is handled above.
					*need_request -= 1;

					peers.retain(|p| {
						peer_can_serve_body_height(p.info.live_info.read_recursive().height, height)
					});

					// Select and lease atomically across loop/receive refill callers.
					let now = Instant::now();
					let mut performance = self.peer_performance.write();
					let preference = option_env!("MWC_BODY_PEER_PREFERENCE") != Some("0");
					let addresses: Vec<_> = peers.iter().map(|p| p.info.addr.clone()).collect();
					let weights = if preference {
						performance.fresh_weights(&addresses, now, cfg!(target_os = "ios") && option_env!("MWC_BODY_SLOW_PEER_PROBES") == Some("1"))
					} else { vec![1; peers.len()] };
					let total: u64 = weights.iter().sum();
					let selected = if total == 0 { None } else {
						let mut ticket = rng.random_range(0..total);
						weights.iter().position(|weight| {
							if ticket < *weight { true } else { ticket -= *weight; false }
						}).and_then(|idx| peers.get(idx))
					};
					if let Some(peer) = selected {
						if preference { performance.selected_fresh(&peer.info.addr, now); }
					}
					drop(performance);
					let peer = match selected {
						Some(p) => p,
						None => {
							info!(
								"body sync GetBlock dropped all peers at height {} (before_filter={})",
								height, peers_before_filter
							);
							self.record_send_stats(
								sent_heights,
								peers_before_filter,
								0,
								new_request_count,
								"all peers dropped by live-height filter",
							);
							*need_request = 0;
							return Ok(waiting_heights);
						}
					};

					debug!(
						"Processing request for the block {} at {}, peer {:?}",
						hash, height, peer.info.addr
					);
					self.peer_performance.write().count(&peer.info.addr, 0, 1);
					let request_token = self.request_tracker.register_request(
						hash.clone(),
						peer.info.addr.clone(),
						format!("Block {}, {}", hash, height),
					);
					if let Err(e) = peer.send_block_request(hash.clone(), mwc_chain::Options::SYNC)
					{
						self.request_tracker.rollback_request(&hash, &request_token);
						let msg = format!(
							"Failed to send block request to peer {}, {}",
							peer.info.addr, e
						);
						warn!("{}", msg);
						sync_peers.report_no_response(&peer.info.addr, msg);
					} else {
						sent_heights.push(height);
						mwc_util::sync_diagnostics::record_body_send(hash.as_bytes(), peer.info.addr.to_string(), false);
					}
				}
				if new_request_count > 0 {
					self.record_send_stats(
						sent_heights,
						peers_before_filter,
						peers.len(),
						new_request_count,
						"sent",
					);
				}
			} // else need_request > 0 after retry throttle
		} else {
			self.record_send_stats(
				Vec::new(),
				peers_before_filter,
				peers_before_filter,
				0,
				"request_series lock busy",
			);
			self.log_retry_decision("series_lock_busy", None, *need_request, 0);
			empty_getblock_why = Some(("request_series lock busy", 0));
		}
		if let Some((why, series_len)) = empty_getblock_why {
			self.log_empty_getblock_once(why, Some(series_len));
		}
		Ok(waiting_heights)
	}

	fn send_waiting_requests(
		&self,
		_dispatch: &MutexGuard<'_, ()>,
		waiting_heights: Vec<(u64, Hash)>,
		need_request: usize,
		peers: &Vec<Arc<Peer>>,
		sync_peers: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		debug_assert!(need_request > 0);

		let mut rng = rand::rng();
		let now = Instant::now();

		// Do not spend spare mobile capacity duplicating healthy young requests.
		let mut eligible = Vec::new();
		for (height, hash) in waiting_heights {
			if let Some(peer) = self.request_tracker.get_expected_peer(&hash) {
				if !spare_retry_due(self.request_tracker.request_age_at(&hash, &peer, now), self.request_tracker.get_average_latency_ms(), cfg!(target_os = "ios")) { continue; }
				if self.duplicate_candidate(&hash)? { eligible.push((height, hash)); }
			}
		}
		let duplicate_reqs: Vec<(u64, Hash)> = eligible.into_iter().sample(&mut rng, need_request);

		for (height, hash) in duplicate_reqs {
			// We don't want to send retry to the peer whom we already send the data
			if let Some(requested_peer) = self.request_tracker.get_expected_peer(&hash) {
				// Recheck in case the tracked request was replaced during selection.
				if !spare_retry_due(self.request_tracker.request_age_at(&hash, &requested_peer, Instant::now()), self.request_tracker.get_average_latency_ms(), cfg!(target_os = "ios")) {
					self.log_retry_decision("spare_retry_too_young", Some(height), need_request, 0);
					continue;
				}
				if !self.duplicate_candidate(&hash)? { continue; }
				let dup_peer = peers
					.iter()
					.filter(|p| {
						p.info.addr != requested_peer
							&& peer_can_serve_body_height(
								p.info.live_info.read_recursive().height,
								height,
							)
					})
					.choose(&mut rng);

				match dup_peer {
					Some(dup_peer) => {
						debug!(
							"Processing duplicated request for the block {} at {}, peer {:?}",
							hash, height, dup_peer.info.addr
						);
						match dup_peer.send_block_request(hash, mwc_chain::Options::SYNC) {
							Ok(_) => {
								mwc_util::sync_diagnostics::record_body_send(hash.as_bytes(), dup_peer.info.addr.to_string(), true);
								self.push_retry_expiration(now)?;
								self.log_retry_decision("spare_budget_retry_sent", Some(height), need_request, 0);
							},
							Err(e) => {
								let msg = format!(
									"Failed to send duplicate block request to peer {}, {}",
									dup_peer.info.addr, e
								);
								warn!("{}", msg);
								sync_peers.report_no_response(&dup_peer.info.addr, msg);
								break;
							}
						}
					}
					None => {
						self.log_retry_decision("spare_budget_no_alternate_peer", Some(height), need_request, 0);
						break;
					},
				}
			}
		}
		Ok(())
	}
}
