use vft_core::confidence::{confidence, TABLE};
use vft_core::graph::sinks::lookup;

#[test]
fn table_is_sorted_unique_in_range_and_registered() {
    for w in TABLE.windows(2) {
        assert!(w[0].0 < w[1].0, "not sorted/unique at {}", w[1].0);
    }
    for (id, v) in TABLE {
        assert!((1..=100).contains(v), "{id}: {v}");
        assert!(lookup(id).is_some(), "{id} is not a registered construct");
        assert_eq!(confidence(id), Some(*v));
    }
    assert_eq!(confidence("nope.nope"), None);
}
