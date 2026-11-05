//! Deadline and cancellation checks shared by normalized TCP connectors.
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Check cancellation first, then return the time left for the connection.
pub(crate) fn remaining(
    started: Instant,
    timeout: Duration,
    stopped: Option<&AtomicBool>,
) -> io::Result<Duration> {
    if stopped.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "connection cancelled",
        ));
    }
    timeout
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "outer socket connection timed out"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_checks_cancellation_and_expiry() {
        let started = Instant::now();
        let stopped = AtomicBool::new(false);
        assert!(remaining(started, Duration::from_secs(1), Some(&stopped)).is_ok());
        stopped.store(true, Ordering::Release);
        assert_eq!(
            remaining(started, Duration::from_secs(1), Some(&stopped))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(
            remaining(started, Duration::ZERO, Some(&stopped))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );
        stopped.store(false, Ordering::Release);
        assert_eq!(
            remaining(started, Duration::ZERO, Some(&stopped))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        let expired = Instant::now() - Duration::from_secs(2);
        assert_eq!(
            remaining(expired, Duration::from_secs(1), None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
