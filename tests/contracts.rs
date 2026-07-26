//! Contract artifact regression tests.

use std::{collections::BTreeSet, fs, path::Path};

use anyhow::{Context, Result, bail};
use serde_json::Value;

#[test]
fn json_contracts_are_valid_and_closed() -> Result<()> {
    for path in [
        "contracts/workload-claims.schema.json",
        "contracts/realm-desired.schema.json",
        "contracts/realm-observation.schema.json",
    ] {
        let document: Value = serde_json::from_str(
            &fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?,
        )
        .with_context(|| format!("{path} is not valid JSON"))?;
        if document.get("$schema").and_then(Value::as_str)
            != Some("https://json-schema.org/draft/2020-12/schema")
        {
            bail!("{path} does not declare JSON Schema 2020-12");
        }
        if document
            .get("additionalProperties")
            .and_then(Value::as_bool)
            != Some(false)
        {
            bail!("{path} must reject unknown top-level properties");
        }
    }
    Ok(())
}

#[test]
fn workload_claim_schema_matches_serialized_claim_keys() -> Result<()> {
    let schema: Value = serde_json::from_str(&fs::read_to_string(
        "contracts/workload-claims.schema.json",
    )?)?;
    let required = schema["required"]
        .as_array()
        .context("workload schema required must be an array")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .context("workload schema required entry must be a string")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    let expected = BTreeSet::from([
        "iss",
        "aud",
        "sub",
        "tenant",
        "persona",
        "workspace",
        "lease",
        "operation",
        "capability",
        "jti",
        "iat",
        "nbf",
        "exp",
    ]);
    assert_eq!(required, expected);
    Ok(())
}

#[test]
fn openapi_covers_only_the_runtime_probe_surface() -> Result<()> {
    let contract = fs::read_to_string("contracts/openapi.yaml")?;
    assert!(contract.starts_with("openapi: 3.1.0\n"));
    assert!(contract.contains("\n  /healthz:\n"));
    assert!(contract.contains("\n  /readyz:\n"));
    assert!(!contract.contains("Proxy-Authorization"));
    Ok(())
}

#[test]
fn public_sources_are_orchestrator_neutral() -> Result<()> {
    for root in [
        ".github",
        "src",
        "tests",
        "examples",
        "integration",
        "deploy",
        "docs",
        "contracts",
    ] {
        assert_tree_is_neutral(Path::new(root))?;
    }
    for path in ["README.md", "AGENTS.md", "CLAUDE.md"] {
        assert_file_is_neutral(Path::new(path))?;
    }
    Ok(())
}

fn assert_tree_is_neutral(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))? {
        let entry = entry?;
        let child = entry.path();
        if child.is_dir() {
            assert_tree_is_neutral(&child)?;
        } else {
            assert_file_is_neutral(&child)?;
        }
    }
    Ok(())
}

fn assert_file_is_neutral(path: &Path) -> Result<()> {
    let Ok(contents) = fs::read_to_string(path) else {
        return Ok(());
    };
    let lowercase = contents.to_ascii_lowercase();
    for forbidden in [
        ["bot", "yard"].concat(),
        ["tailnet", ".ak5", ".cc"].concat(),
        ["send", "grift"].concat(),
        ["ghcr.io/", "ak5", "/charon"].concat(),
    ] {
        if lowercase.contains(&forbidden) {
            bail!(
                "{} contains an operator-specific public value",
                path.display()
            );
        }
    }
    Ok(())
}
