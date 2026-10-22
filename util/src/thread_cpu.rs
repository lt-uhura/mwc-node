//! Paired wall/thread CPU measurements; never used for synchronization decisions.
use std::time::Duration;

/// CPU consumed by the calling thread, or unavailable on unsupported platforms.
pub(crate) fn now() -> Option<Duration> {
	#[cfg(any(target_os = "ios", all(test, target_vendor = "apple")))]
	{
		use mwc_crates::libc;
		let mut value = libc::timespec {
			tv_sec: 0,
			tv_nsec: 0,
		};
		// SAFETY: valid writable timespec; this clock reads only the current thread.
		let result = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut value) };
		if result != 0 || value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
			return None;
		}
		Some(Duration::new(value.tv_sec as u64, value.tv_nsec as u32))
	}
	#[cfg(not(any(target_os = "ios", all(test, target_vendor = "apple"))))]
	{
		None
	}
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Counter {
	pub samples: u64,
	pub wall: u128,
	pub cpu: u128,
	pub off_cpu: u128,
	pub unavailable: u64,
}
impl Counter {
	pub const ZERO: Self = Self {
		samples: 0,
		wall: 0,
		cpu: 0,
		off_cpu: 0,
		unavailable: 0,
	};
	pub fn record(&mut self, wall: Duration, start: Option<Duration>, end: Option<Duration>) {
		let Some(cpu) = start.zip(end).and_then(|(s, e)| e.checked_sub(s)) else {
			self.unavailable += 1;
			return;
		};
		self.samples += 1;
		self.wall += wall.as_micros();
		self.cpu += cpu.as_micros();
		// Separate clock reads can slightly disagree for very short scopes.
		self.off_cpu += wall.saturating_sub(cpu).as_micros();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn paired_totals_exclude_unavailable_and_backwards_clocks() {
		let mut c = Counter::ZERO;
		let ms = Duration::from_millis;
		c.record(ms(10), Some(ms(2)), Some(ms(5)));
		c.record(ms(20), None, Some(ms(8)));
		c.record(ms(20), Some(ms(8)), None);
		c.record(ms(20), Some(ms(8)), Some(ms(7)));
		assert_eq!(
			(c.samples, c.wall, c.cpu, c.off_cpu, c.unavailable),
			(1, 10000, 3000, 7000, 3)
		);
		let old = std::mem::take(&mut c);
		assert_eq!(old.samples, 1);
		assert_eq!(
			(c.samples, c.wall, c.cpu, c.off_cpu, c.unavailable),
			(0, 0, 0, 0, 0)
		);
	}
	#[test]
	fn clock_skew_does_not_underflow() {
		let mut c = Counter::ZERO;
		c.record(
			Duration::from_nanos(10),
			Some(Duration::ZERO),
			Some(Duration::from_nanos(20)),
		);
		assert_eq!(c.off_cpu, 0);
	}
	#[cfg(target_vendor = "apple")]
	#[test]
	fn apple_thread_clock_is_readable_and_monotonic() {
		std::thread::spawn(|| {
			let start = now().expect("thread CPU clock available");
			for n in 0..10000 {
				std::hint::black_box(n);
			}
			assert!(now().unwrap() >= start);
		})
		.join()
		.unwrap();
	}
}
