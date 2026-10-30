//! # Venusflytrap core engine
//!
//! A semantic, taint-graph web-application-firewall engine with honeypot and
//! attack-chain inference — an open, measurable Rust engine that reasons about
//! what a payload can do rather than what it looks like (see `docs/RESEARCH.md`).
//!
//! Pipeline: **normalize → token-graph taint → detectors → four-valued lattice
//! → score/verdict**, with honeypot, file-backed threat intel, and a
//! cross-request kill-chain tracker layered on top.
//!
//! ```
//! use vft_core::{Shield, Config, Request, Verdict};
//! let shield = Shield::new(Config::default());
//! let mut req = Request::get("/items");
//! req.query.push(("id".into(), "1 union select password from users".into()));
//! assert_eq!(shield.inspect(&req).verdict, Verdict::Block);
//! ```
#![forbid(unsafe_code)]

pub mod attack;
pub mod body;
pub mod chain;
pub mod confidence;
pub mod config;
pub mod detect;
pub mod exceptions;
pub mod graph;
pub mod honeypot;
pub mod intel;
pub mod judgment;
pub mod lattice;
pub mod normalize;
pub mod options;
pub mod request;
pub mod score;
pub mod shield;

pub use attack::AttackTag;
pub use chain::{event_for, BanCause, BanRecord, ChainOutcome, ChainTracker, Event, SourceKey};
pub use config::{BanPolicy, Config};
pub use detect::{AiOracle, HeuristicOracle};
pub use exceptions::{ExceptionClock, Exceptions};
pub use judgment::{Cause, CauseKind, Contribution, Family, FieldRef, Judgment, Pattern, Stage, Verdict};
pub use lattice::FourValued;
pub use request::{Field, Location, Request};
pub use shield::Shield;
