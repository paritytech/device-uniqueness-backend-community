// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

pub fn batch_item_results<T>(
    events: impl IntoIterator<Item = T>,
    names: impl Fn(&T) -> (&str, &str),
) -> Vec<Result<(), T>> {
    events
        .into_iter()
        .filter_map(|event| {
            let completed = match names(&event) {
                ("Utility", "ItemCompleted") => true,
                ("Utility", "ItemFailed") => false,
                _ => return None,
            };
            Some(if completed { Ok(()) } else { Err(event) })
        })
        .collect()
}

pub fn settle_batch_size(current: u16, max: u16, succeeded: bool) -> u16 {
    if succeeded {
        current.saturating_add(1).min(max)
    } else {
        (current / 2).max(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Event = (&'static str, &'static str);

    fn names(event: &Event) -> (&str, &str) {
        (event.0, event.1)
    }

    #[test]
    fn batch_item_results_keep_order_and_ignore_foreign_events() {
        let events = [
            ("System", "ExtrinsicSuccess"),
            ("Utility", "ItemCompleted"),
            ("Game", "ItemCompleted"),
            ("Utility", "ItemFailed"),
            ("Utility", "BatchCompletedWithErrors"),
            ("Utility", "ItemCompleted"),
        ];
        assert_eq!(
            batch_item_results(events, names),
            vec![Ok(()), Err(("Utility", "ItemFailed")), Ok(())]
        );
        assert!(batch_item_results(Vec::<Event>::new(), names).is_empty());
    }

    #[test]
    fn only_failed_items_are_asked_for_a_reason() {
        let events = [
            ("System", "ExtrinsicSuccess"),
            ("Utility", "ItemCompleted"),
            ("Game", "ItemFailed"), // same name, wrong pallet
            ("Utility", "ItemFailed"),
            ("Utility", "ItemCompleted"),
        ];
        let mut decoded = 0;
        let reasons: Vec<Result<(), String>> = batch_item_results(events, names)
            .into_iter()
            .map(|item| {
                item.map_err(|(pallet, event)| {
                    decoded += 1;
                    format!("{pallet}::{event}")
                })
            })
            .collect();

        assert_eq!(
            reasons,
            vec![Ok(()), Err("Utility::ItemFailed".to_string()), Ok(())]
        );
        assert_eq!(decoded, 1, "a reason was decoded for a non-failed item");
    }

    #[test]
    fn batch_size_grows_by_one_and_halves_on_failure() {
        assert_eq!(settle_batch_size(50, 100, true), 51);
        assert_eq!(settle_batch_size(99, 100, true), 100);
        assert_eq!(settle_batch_size(100, 100, true), 100);

        assert_eq!(settle_batch_size(100, 100, false), 50);
        assert_eq!(settle_batch_size(3, 100, false), 1);
        assert_eq!(settle_batch_size(1, 100, false), 1);
        assert_eq!(settle_batch_size(u16::MAX, u16::MAX, true), u16::MAX);
    }
}
