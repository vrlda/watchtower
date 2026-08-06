//! Supervision for background tasks: restart on panic (exponential backoff,
//! 30s cap) and on clean exit (small pause). A task that dies silently was
//! the M5 handoff's supervision gap — this closes it.

use std::time::Duration;

/// Exponential backoff, capped.
#[derive(Default)]
pub struct Backoff {
    delay_secs: u64,
}

impl Backoff {
    #[allow(clippy::should_implement_trait)] // `next` is the plan-spec'd API, not Iterator
    pub fn next(&mut self) -> Duration {
        let d = if self.delay_secs == 0 {
            1
        } else {
            self.delay_secs
        };
        self.delay_secs = (d * 2).clamp(1, 30);
        Duration::from_secs(d)
    }

    pub fn reset(&mut self) {
        self.delay_secs = 0;
    }
}

/// Run `f` forever, restarting on panic (backoff) and on clean exit (1s pause).
pub async fn spawn_supervised<F, Fut>(name: &'static str, f: F)
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut backoff = Backoff::default();
    loop {
        let result = tokio::spawn(f()).await;
        match result {
            Ok(()) => {
                eprintln!("[supervise] {} exited cleanly — restarting", name);
                backoff.reset();
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                let d = backoff.next();
                let kind = if e.is_panic() { "panicked" } else { "failed" };
                eprintln!(
                    "[supervise] {} {} — restarting in {}s",
                    name,
                    kind,
                    d.as_secs()
                );
                tokio::time::sleep(d).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn backoff_sequence_caps() {
        let mut d = Backoff::default();
        assert_eq!(d.next().as_secs(), 1);
        assert_eq!(d.next().as_secs(), 2);
        assert_eq!(d.next().as_secs(), 4);
        assert_eq!(d.next().as_secs(), 8);
        assert_eq!(d.next().as_secs(), 16);
        assert_eq!(d.next().as_secs(), 30, "cap at 30s");
        assert_eq!(d.next().as_secs(), 30);
        d.reset();
        assert_eq!(d.next().as_secs(), 1);
    }

    #[tokio::test]
    async fn restarts_after_panic_with_backoff() {
        // abort() detaches the child task; runtime teardown kills it (test-only).
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let handle = tokio::spawn(async move {
            spawn_supervised("panic-task", move || {
                let c = count2.clone();
                async move {
                    if c.fetch_add(1, Ordering::SeqCst) == 0 {
                        panic!("boom");
                    }
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
            })
            .await;
        });
        // first run panics → 1s backoff → second run starts
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert!(
            count.load(Ordering::SeqCst) >= 2,
            "task restarted after panic"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn restarts_after_clean_exit() {
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let handle = tokio::spawn(async move {
            spawn_supervised("exit-task", move || {
                let c = count2.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            })
            .await;
        });
        // clean exit → 1s pause → restart; ~3 invocations in ~2.5s
        tokio::time::sleep(std::time::Duration::from_millis(2600)).await;
        assert!(
            count.load(Ordering::SeqCst) >= 3,
            "clean exit restarts (with a small pause)"
        );
        handle.abort();
    }
}
