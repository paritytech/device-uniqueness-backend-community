// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

use std::fs;

fn main() -> anyhow::Result<()> {
    let json = apidoc_gen::openapi_json();
    fs::write(apidoc_gen::openapi_json_path(), &json)?;
    println!("wrote {}", apidoc_gen::openapi_json_path());

    let html = apidoc_gen::index_html()?;
    fs::write(apidoc_gen::index_html_path(), &html)?;
    println!("wrote {}", apidoc_gen::index_html_path());

    Ok(())
}
