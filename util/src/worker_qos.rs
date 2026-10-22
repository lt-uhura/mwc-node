//! Scheduling for native iOS workers participating in visible, long-running sync.
//!
//! This is a scheduling hint, not a background execution entitlement. Call only
//! from dedicated native workers, never from a dispatch-managed thread.

/// Give an iOS sync worker a utility QoS floor without lowering an existing QoS.
/// Other platforms retain their current scheduling. Failure is nonfatal.
pub fn configure_sync_worker(role: &str) {
	#[cfg(target_os = "ios")]
	{
		match apple::configure() {
			Ok((before, after)) => mwc_crates::log::info!(
				"body sync worker_qos role={} before={} after={} policy=utility_floor",
				role,
				before,
				after
			),
			Err(code) => mwc_crates::log::warn!(
				"body sync worker_qos role={} error={} policy=utility_floor; continuing",
				role,
				code
			),
		}
	}
	#[cfg(not(target_os = "ios"))]
	let _ = role;
}

#[cfg(any(target_os = "ios", all(test, target_vendor = "apple")))]
mod apple {
	use mwc_crates::libc::{self, qos_class_t};
	use qos_class_t::*;

	fn needs_utility(class: qos_class_t) -> bool {
		matches!(class, QOS_CLASS_UNSPECIFIED | QOS_CLASS_BACKGROUND)
	}

	fn current() -> Result<qos_class_t, i32> {
		let mut class = QOS_CLASS_UNSPECIFIED;
		let mut relative = 0;
		// SAFETY: both out-pointers are valid and pthread_self is the live caller.
		let result = unsafe {
			libc::pthread_get_qos_class_np(libc::pthread_self(), &mut class, &mut relative)
		};
		if result == 0 { Ok(class) } else { Err(result) }
	}

	pub(super) fn configure() -> Result<(u32, u32), i32> {
		let before = current()?;
		if needs_utility(before) {
			// SAFETY: utility with relative priority zero is a supported Darwin QoS.
			// This affects only the dedicated native thread making this call.
			let result = unsafe { libc::pthread_set_qos_class_self_np(QOS_CLASS_UTILITY, 0) };
			if result != 0 {
				return Err(result);
			}
		}
		Ok((before as u32, current()? as u32))
	}

	#[cfg(test)]
	mod tests {
		use super::*;

		#[test]
		fn policy_preserves_utility_and_higher_classes() {
			assert!(needs_utility(QOS_CLASS_UNSPECIFIED));
			assert!(needs_utility(QOS_CLASS_BACKGROUND));
			for class in [
				QOS_CLASS_UTILITY,
				QOS_CLASS_DEFAULT,
				QOS_CLASS_USER_INITIATED,
				QOS_CLASS_USER_INTERACTIVE,
			] {
				assert!(!needs_utility(class));
			}
		}

		#[test]
		fn native_worker_promotes_background_and_is_idempotent() {
			std::thread::spawn(|| {
				assert_eq!(
					unsafe { libc::pthread_set_qos_class_self_np(QOS_CLASS_BACKGROUND, 0) },
					0
				);
				assert_eq!(
					configure().unwrap(),
					(QOS_CLASS_BACKGROUND as u32, QOS_CLASS_UTILITY as u32)
				);
				assert_eq!(
					configure().unwrap(),
					(QOS_CLASS_UTILITY as u32, QOS_CLASS_UTILITY as u32)
				);
			})
			.join()
			.unwrap();
		}

		#[test]
		fn native_worker_does_not_lower_default() {
			std::thread::spawn(|| {
				assert_eq!(
					unsafe { libc::pthread_set_qos_class_self_np(QOS_CLASS_DEFAULT, 0) },
					0
				);
				assert_eq!(
					configure().unwrap(),
					(QOS_CLASS_DEFAULT as u32, QOS_CLASS_DEFAULT as u32)
				);
			})
			.join()
			.unwrap();
		}
	}
}
