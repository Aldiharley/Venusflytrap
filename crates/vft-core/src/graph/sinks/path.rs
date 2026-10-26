//! Path traversal sinks.

use super::{ConstructInfo, ConstructKind, Hits, SinkCtx};
use crate::judgment::Family;

pub static DIRECTORY_TRAVERSAL: ConstructInfo = ConstructInfo { id: "path.directory-traversal", family: Some(Family::PathTraversal), kind: ConstructKind::Sink, summary: "two or more ../ segments, or one with a sensitive target" };
pub static DOTDOT_SEGMENT: ConstructInfo = ConstructInfo { id: "path.dotdot-segment", family: Some(Family::PathTraversal), kind: ConstructKind::Latent, summary: "a single ../ with no sensitive target" };

pub fn detect(cx: &SinkCtx, hits: &mut Hits) {
    let text = cx.text;
    let dots = text.matches("../").count() + text.matches("..\\").count();
    if dots >= 1 {
        // sensitive target raises to reachable
        let sensitive = ["etc/passwd", "etc/shadow", "win.ini", "boot.ini", "/proc/"]
            .iter()
            .any(|s| text.contains(s));
        if dots >= 2 || sensitive {
            hits.reach(&DIRECTORY_TRAVERSAL);
        } else {
            hits.latent(&DOTDOT_SEGMENT);
        }
    }
}
