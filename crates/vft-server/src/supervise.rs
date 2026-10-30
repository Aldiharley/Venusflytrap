//! Restart-with-backoff supervision of long-running tasks.

use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;

/// Run `make()` in a loop: on `Err`, panic or unexpected `Ok`, log, wait
/// (1 s doubling to 60 s; reset after an attempt that ran 60 s), restart.
/// Stops when `stop` becomes `true` (or its sender is dropped). Returns when stopped.
pub async fn supervise<F, Fut>(
    name: &'static str,
    mut stop: tokio::sync::watch::Receiver<bool>,
    mut make: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    const MIN_BACKOFF: Duration = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);
    let mut backoff = MIN_BACKOFF;
    loop {
        if stopped(&stop) {
            return;
        }
        let started = Instant::now();
        let mut handle = tokio::spawn(make());
        let outcome = tokio::select! {
            res = &mut handle => res,
            _ = wait_stopped(&mut stop) => {
                handle.abort();
                return;
            }
        };
        match outcome {
            Ok(Ok(())) => tracing::warn!(
                task = name,
                "supervised task exited unexpectedly; restarting"
            ),
            Ok(Err(e)) => {
                tracing::error!(task = name, error = %e, "supervised task failed; restarting")
            }
            Err(e) => {
                tracing::error!(task = name, error = %e, "supervised task panicked; restarting")
            }
        }
        if started.elapsed() >= MAX_BACKOFF {
            backoff = MIN_BACKOFF;
        }
        tracing::info!(
            task = name,
            wait_s = backoff.as_secs(),
            "restarting after backoff"
        );
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = wait_stopped(&mut stop) => return,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn stopped(stop: &tokio::sync::watch::Receiver<bool>) -> bool {
    *stop.borrow()
}

/// Resolves once the flag is `true` or the sender is gone (nobody can stop us any more).
async fn wait_stopped(stop: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = stop.wait_for(|v| *v).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;
    use tokio::time::{timeout, Duration, Instant};

    type Starts = Arc<Mutex<Vec<Instant>>>;

    #[tokio::test(start_paused = true)]
    async fn restarts_after_panics_with_doubling_backoff() {
        let (tx, rx) = watch::channel(false);
        let starts: Starts = Arc::new(Mutex::new(Vec::new()));
        let s2 = starts.clone();
        let handle = tokio::spawn(supervise("t", rx, move || {
            let s = s2.clone();
            async move {
                let n = {
                    let mut g = s.lock().unwrap();
                    g.push(Instant::now());
                    g.len()
                };
                if n <= 2 {
                    panic!("boom {n}");
                }
                std::future::pending::<()>().await;
                Ok(())
            }
        }));
        tokio::time::sleep(Duration::from_secs(10)).await;
        {
            let g = starts.lock().unwrap();
            assert_eq!(g.len(), 3, "panics twice, third attempt keeps running");
            assert_eq!(g[1] - g[0], Duration::from_secs(1));
            assert_eq!(g[2] - g[1], Duration::from_secs(2));
        }
        tx.send(true).unwrap();
        timeout(Duration::from_secs(1), handle)
            .await
            .expect("stops promptly")
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn errors_back_off_and_cap_at_sixty_seconds() {
        let (tx, rx) = watch::channel(false);
        let starts: Starts = Arc::new(Mutex::new(Vec::new()));
        let s2 = starts.clone();
        let handle = tokio::spawn(supervise("t", rx, move || {
            let s = s2.clone();
            async move {
                s.lock().unwrap().push(Instant::now());
                anyhow::bail!("always fails")
            }
        }));
        tokio::time::sleep(Duration::from_secs(400)).await;
        {
            let g = starts.lock().unwrap();
            let gaps: Vec<u64> = g.windows(2).map(|w| (w[1] - w[0]).as_secs()).collect();
            assert_eq!(&gaps[..8], &[1, 2, 4, 8, 16, 32, 60, 60]);
        }
        tx.send(true).unwrap();
        timeout(Duration::from_secs(1), handle)
            .await
            .expect("stops promptly")
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_resets_after_a_healthy_run() {
        let (tx, rx) = watch::channel(false);
        let starts: Starts = Arc::new(Mutex::new(Vec::new()));
        let s2 = starts.clone();
        let handle = tokio::spawn(supervise("t", rx, move || {
            let s = s2.clone();
            async move {
                let n = {
                    let mut g = s.lock().unwrap();
                    g.push(Instant::now());
                    g.len()
                };
                if n == 3 {
                    // healthy for 60 s, then fails
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                anyhow::bail!("fail {n}")
            }
        }));
        tokio::time::sleep(Duration::from_secs(120)).await;
        {
            let g = starts.lock().unwrap();
            assert_eq!(g[1] - g[0], Duration::from_secs(1));
            assert_eq!(g[2] - g[1], Duration::from_secs(2));
            // attempt 3 ran 60 s, so the wait before attempt 4 is back to 1 s
            assert_eq!(g[3] - g[2], Duration::from_secs(61));
        }
        tx.send(true).unwrap();
        timeout(Duration::from_secs(1), handle)
            .await
            .expect("stops promptly")
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn stop_interrupts_backoff_wait_and_running_task() {
        // during the backoff sleep
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(supervise("t", rx, || async { anyhow::bail!("x") }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        tx.send(true).unwrap();
        timeout(Duration::from_millis(50), handle)
            .await
            .expect("stops during backoff")
            .unwrap();

        // while the task is running
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(supervise("t", rx, || async {
            std::future::pending::<()>().await;
            Ok(())
        }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        tx.send(true).unwrap();
        timeout(Duration::from_millis(50), handle)
            .await
            .expect("stops while running")
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn already_stopped_never_runs_the_task() {
        let (_tx, rx) = watch::channel(true);
        let ran = Arc::new(Mutex::new(false));
        let r2 = ran.clone();
        supervise("t", rx, move || {
            let r = r2.clone();
            async move {
                *r.lock().unwrap() = true;
                Ok(())
            }
        })
        .await;
        assert!(!*ran.lock().unwrap());
    }
}
