//! Cross-site scripting sinks.

use super::{has_quote, ConstructInfo, ConstructKind, Hits, SinkCtx};
use crate::graph::tokenize::TokenKind;
use crate::judgment::Family;

pub static SCRIPT_TAG: ConstructInfo = ConstructInfo { id: "xss.script-tag", family: Some(Family::Xss), kind: ConstructKind::Sink, summary: "`<script` tag" };
pub static EVENT_HANDLER: ConstructInfo = ConstructInfo { id: "xss.event-handler", family: Some(Family::Xss), kind: ConstructKind::Sink, summary: "on*= handler in a new tag or after an attribute breakout" };
pub static DANGEROUS_PROTO: ConstructInfo = ConstructInfo { id: "xss.dangerous-proto", family: Some(Family::Xss), kind: ConstructKind::Sink, summary: "`javascript:` or `data:text/html`" };
pub static TAG_WITH_HANDLER: ConstructInfo = ConstructInfo { id: "xss.tag-with-handler", family: Some(Family::Xss), kind: ConstructKind::Sink, summary: "svg/img/iframe/body/video tag with an event handler" };
pub static HTML_TAG: ConstructInfo = ConstructInfo { id: "xss.html-tag", family: Some(Family::Xss), kind: ConstructKind::Latent, summary: "an HTML tag with no XSS construct formed" };

pub fn detect(cx: &SinkCtx, hits: &mut Hits) {
    let (tokens, text) = (cx.tokens, cx.text);
    let has_tag_open = tokens.iter().any(|t| t.kind == TokenKind::TagOpen);
    let has_handler = tokens.iter().any(|t| t.kind == TokenKind::EventHandler);
    // <script>
    if text.contains("<script") {
        hits.reach(&SCRIPT_TAG);
    }
    // Event-handler attribute, either inside a new tag (`<svg onload=`) or an
    // attribute-breakout into an existing tag (`x" onmouseover=alert(1)`), which
    // has a quote but no new tag (M3).
    if has_handler && (has_tag_open || has_quote(tokens)) {
        hits.reach(&EVENT_HANDLER);
    }
    // javascript:/data: protocol
    if text.contains("javascript:") || text.contains("data:text/html") {
        hits.reach(&DANGEROUS_PROTO);
    }
    // svg/img/iframe with handler
    for tag in ["<svg", "<img", "<iframe", "<body", "<video"] {
        if text.contains(tag) && tokens.iter().any(|t| t.kind == TokenKind::EventHandler) {
            hits.reach(&TAG_WITH_HANDLER);
            break;
        }
    }
    if !hits.reached(Family::Xss) && has_tag_open {
        hits.latent(&HTML_TAG);
    }
}
