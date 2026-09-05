//! A clock behind a trait, so expiry arithmetic can be tested without waiting.

use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock {
    /// Seconds since the Unix epoch.
    fn now(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A clock frozen at a chosen instant. For tests.
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_a_plausible_epoch() {
        // 2026-01-01T00:00:00Z. If this fails, the machine clock is wrong.
        assert!(SystemClock.now() > 1_767_225_600);
    }

    #[test]
    fn fixed_clock_returns_what_it_was_given() {
        assert_eq!(FixedClock(1_757_000_000).now(), 1_757_000_000);
    }
}
