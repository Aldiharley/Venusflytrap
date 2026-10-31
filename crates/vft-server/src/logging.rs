//! Process-wide tracing setup.

/// Install a `tracing-subscriber` fmt layer writing to stderr, filtered by
/// `RUST_LOG` (default `info`). Safe to call more than once.
pub fn init() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // `try_init` fails if a global subscriber is already installed; that is the idempotent path.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        // Colour codes only on a terminal, never in a redirected log file.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .try_init();
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_is_idempotent() {
        super::init();
        super::init();
        tracing::info!("logging initialised");
    }
}
