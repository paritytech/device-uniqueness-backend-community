// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};
use dub::routes::table;

/// The Caddy snippet body, between the markers inside `(routes) { … }`.
const CADDYFILE: &str = "gateway/Caddyfile";

fn main() -> anyhow::Result<()> {
    let root = repo_root()?;
    for (path, rendered, comment) in artifacts() {
        let file = root.join(path);
        let current = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        let updated = splice(&current, &rendered, comment)
            .with_context(|| format!("splicing the generated region into {path}"))?;
        if updated == current {
            println!("unchanged  {path}");
        } else {
            std::fs::write(&file, updated).with_context(|| format!("writing {path}"))?;
            println!("rewrote    {path}");
        }
    }
    Ok(())
}

/// The artifacts, their rendered bodies, and the comment marker each file's
/// syntax uses.
fn artifacts() -> Vec<(&'static str, String, &'static str)> {
    vec![(CADDYFILE, table::caddy_snippet(), "\t#")]
}

/// Replace the text between the begin and end markers, keeping the markers and
/// everything around them.
fn splice(current: &str, rendered: &str, comment: &str) -> anyhow::Result<String> {
    let begin = format!("{comment} {}", table::BEGIN);
    let end = format!("{comment} {}", table::END);
    let Some(start) = current.find(&begin) else {
        bail!("no `{begin}` marker — add one, or the generated region has been deleted");
    };
    let Some(stop) = current.find(&end) else {
        bail!("no `{end}` marker");
    };
    if stop < start {
        bail!("the `{end}` marker precedes `{begin}`");
    }
    let after_begin = start + begin.len();
    Ok(format!(
        "{}\n{}\n{}",
        &current[..after_begin],
        rendered,
        &current[stop..]
    ))
}

/// Walk up from the manifest directory to the workspace root, so the tool works
/// from anywhere.
fn repo_root() -> anyhow::Result<PathBuf> {
    let mut dir: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join("docker-bake.hcl").is_file() {
            return Ok(dir.to_path_buf());
        }
        dir = dir.parent().context("reached the filesystem root")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_artifacts_are_in_sync() {
        let root = repo_root().expect("workspace root");
        for (path, rendered, comment) in artifacts() {
            let file = root.join(path);
            let current = std::fs::read_to_string(&file).expect("reading the committed artifact");
            let expected = splice(&current, &rendered, comment).expect("splicing");
            assert_eq!(
                current, expected,
                "{path} is stale — run `just routes` (do not hand-edit the generated region)"
            );
        }
    }

    #[test]
    fn a_missing_marker_is_an_error() {
        assert!(splice("nothing here", "body", "  #").is_err());
        let only_begin = format!("  # {}", table::BEGIN);
        assert!(splice(&only_begin, "body", "  #").is_err());
    }
}
