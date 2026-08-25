// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::io::Read as _;
use std::time::Instant;

use serde::Deserialize;
use username_indexer::poc::solution::mine;
use username_indexer::poc::Solution;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuedPuzzle {
    session_id: uuid::Uuid,
    timestamp: i64,
    difficulty: u8,
    checksum: String,
}

fn main() -> anyhow::Result<()> {
    let mut body = String::new();
    std::io::stdin().read_to_string(&mut body)?;
    let puzzle: IssuedPuzzle = serde_json::from_str(body.trim())?;

    let started = Instant::now();
    let counter = mine(puzzle.session_id, puzzle.timestamp, puzzle.difficulty);
    let elapsed = started.elapsed();

    let solution = Solution::new(
        puzzle.session_id,
        puzzle.timestamp,
        puzzle.difficulty,
        counter,
        puzzle.checksum,
    );

    eprintln!(
        "mined {} bits in {:.3}s ({counter} hashes)",
        puzzle.difficulty,
        elapsed.as_secs_f64()
    );
    println!("{}", solution.to_header());
    Ok(())
}
