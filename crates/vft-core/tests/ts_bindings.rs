//! The console's wire types in ui/src/gen must match the Rust types.
//! Check: cargo test -p vft-core --features ts --test ts_bindings
//! Bless: VFT_BLESS_TS=1 cargo test -p vft-core --features ts --test ts_bindings
#![cfg(feature = "ts")]

use std::path::PathBuf;
use ts_rs::{Config, TS};
use vft_core::chain::{BanCause, BanRecord, ChainOutcome};
use vft_core::options::{Apply, Expertise, OptionDescriptor, OptionKind, Source};
use vft_core::{Cause, CauseKind, Contribution, Family, FieldRef, FourValued, Judgment, Location, Stage, Verdict};

fn gen_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../ui/src/gen")
}

fn check<T: TS + 'static>(cfg: &Config, stale: &mut Vec<String>) {
    let rel = T::output_path().expect("derived types have an output path");
    let path = gen_dir().join(&rel);
    let want = T::export_to_string(cfg).expect("type renders");
    if std::env::var_os("VFT_BLESS_TS").is_some() {
        std::fs::create_dir_all(gen_dir()).expect("create ui/src/gen");
        std::fs::write(&path, &want).expect("write binding");
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(have) if have.replace("\r\n", "\n") == want => {}
        _ => stale.push(rel.display().to_string()),
    }
}

#[test]
fn generated_types_are_current() {
    let cfg = Config::new().with_large_int("number");
    let mut stale = Vec::new();
    check::<Judgment>(&cfg, &mut stale);
    check::<Cause>(&cfg, &mut stale);
    check::<CauseKind>(&cfg, &mut stale);
    check::<Contribution>(&cfg, &mut stale);
    check::<FieldRef>(&cfg, &mut stale);
    check::<Location>(&cfg, &mut stale);
    check::<FourValued>(&cfg, &mut stale);
    check::<Verdict>(&cfg, &mut stale);
    check::<Family>(&cfg, &mut stale);
    check::<Stage>(&cfg, &mut stale);
    check::<ChainOutcome>(&cfg, &mut stale);
    check::<BanRecord>(&cfg, &mut stale);
    check::<BanCause>(&cfg, &mut stale);
    check::<OptionDescriptor>(&cfg, &mut stale);
    check::<OptionKind>(&cfg, &mut stale);
    check::<Expertise>(&cfg, &mut stale);
    check::<Apply>(&cfg, &mut stale);
    check::<Source>(&cfg, &mut stale);
    assert!(stale.is_empty(), "stale bindings in ui/src/gen (re-run with VFT_BLESS_TS=1): {stale:?}");
}
