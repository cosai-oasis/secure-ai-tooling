# Troubleshooting Validation Issues

This page covers common validation issues and how to resolve them.

## Debugging framework hooks

The repo uses the upstream `pre-commit` framework. Useful commands while debugging:

```bash
# Run all hooks against the current working tree (regenerates derivatives):
pre-commit run --all-files

# Run one hook by id, against all files or a specific file set:
pre-commit run validate-component-edges --all-files
pre-commit run check-jsonschema --files risk-map/yaml/components.yaml

# Validate content without regenerating graphs / tables / SVGs:
./scripts/tools/validate-all.sh
```

> **Note:** `pre-commit run --all-files` stages regenerated derivatives (SVGs,
> graphs, tables, issue templates) via the Mode B auto-stage pattern. See
> [scripts/docs/manual-validation.md](../../scripts/docs/manual-validation.md#recommended-unified-dev-helper)
> for the full caveat and how to unstage bycatch before an unrelated commit.

See also [scripts/docs/troubleshooting.md](../../scripts/docs/troubleshooting.md)
for installation, Chromium, and environment issues.

## Edge Validation Errors

If the pre-commit hook or manual validation fails with edge consistency errors:

### 1. Bidirectional Edge Mismatch

```
Component 'componentA': missing incoming edges for: componentB
```

**Fix**: Add `componentA` to `componentB`'s `edges.from` list

### 2. Isolated Component

```
Found 1 isolated components (no edges): componentX
```

**Fix**: Add appropriate `to` and/or `from` edges, or verify if isolation is intentional

## Graph Generation Issues

If you encounter issues with the automatic graph generation:

### 1. Component graph generation failed during pre-commit

```
❌ Graph generation failed
```

**Fix**: Check that `components.yaml` is valid and accessible. Test manually:

```bash
python scripts/hooks/validate_riskmap.py --to-graph ./test-graph.md --force
```

### 2. Generated graph not staged

```
⚠️ Warning: Could not stage generated graph
```

**Fix**: Check file permissions and git repository status. Ensure `./risk-map/diagrams/` is writable (graph wrapper output location).

### 3. Component layout seems suboptimal

**Fix**: Use debug mode to inspect graph structure:

```bash
python scripts/hooks/validate_riskmap.py --to-graph ./debug-graph.md --debug --force
```

## Framework Mapping Catalogue Errors

The catalogue-membership validator (`validate-mapping-catalogue`, ADR-027 D5 Tier 2, ADR-038) checks each pinned MITRE ATLAS value against the vendored catalogue of the edition its token names. To run it by hand:

```bash
python3 scripts/hooks/precommit/validate_mapping_catalogue.py --force --block
```

`--force` is required. Without it the validator reads nothing, prints `skipping validation: --force not given (nothing examined)` and exits 0, so a bare run is not a pass. The pre-commit hook, the CI job and `validate-all.sh` all pass `--force --block`.

### 1. Value not present in its pinned edition (exit 1)

```
invalid: risks.yaml: entity='<entity-id>' framework='mitre-atlas' value='<id>@<token>': '<id>@<token>': '<id>' is not in edition '<token>' (release <release>); present at <other-token>
```

The id is not in the edition the value is pinned to. The detail names each other registered edition whose catalogue contains the id (`present at <other-token>`), or reports `absent from every registered edition` when none does. **Fix**: if the detail names another edition (`present at <other-token>`), re-pin the value to that edition with `scripts/framework_mapping_maintainer.py`. If it reports `absent from every registered edition`, the id is wrong or belongs to an edition the registry does not yet carry; correct the id, or ask a maintainer whether the registry needs a bump.

### 2. Catalogue digest mismatch (exit 2)

```
error: digest mismatch: <repo-root>/scripts/framework_catalogues/mitre-atlas/<file>: recorded <digest>, actual <digest>
catalogue check not performed: read error (exit 2)
```

A vendored file under `scripts/framework_catalogues/` no longer matches its `SHA256SUMS` entry, usually because an editor, formatter or line-ending conversion changed it. No value was checked. **Fix**: restore the file from version control (`git checkout -- <file>`). The files are verbatim upstream copies and are only changed as part of a registry bump.

### 3. Other read errors (exit 2)

Every read error prints an `error:` line followed by `catalogue check not performed: read error (exit 2)`, and no value is checked. Some read errors come from the content being committed:

- **A content YAML that cannot be read or parsed**: `error: cannot read content file <path>: <reason>`. A content file that parses but is empty, not a mapping, or has no top-level list of entity mappings is also a read error. **Fix**: correct the YAML.
- **A registry edit** to `risk-map/yaml/frameworks.yaml` that leaves a registered edition unresolved in the vendored manifest, or its catalogue missing or not listed in `SHA256SUMS`:

  ```
  error: mitre-atlas: registered edition '<token>' is unresolved in <repo-root>/scripts/framework_catalogues/mitre-atlas/manifest.yaml (no unique manifest entry)
  error: mitre-atlas: catalogue ATLAS-<release>.yaml for registered edition '<token>' is not listed in <repo-root>/scripts/framework_catalogues/mitre-atlas/SHA256SUMS (file <present|absent>)
  ```

  The usual case is a registry bump that flips `version` without the catalogue refresh. **Fix**: perform the refresh in the same commit as the `version` flip or an earlier one; the procedure is the catalogue-refresh paragraph of [hook-validations.md §19](../../scripts/docs/hook-validations.md) and ADR-038 D7. A registry edit that removes or renames the `mitre-atlas` entry is also a read error (`adjudicated framework is absent from the registry`).

Other read errors (a required vendored file missing or unlisted, a malformed `SHA256SUMS` or manifest) are in the vendored catalogue inputs; the fix is the same refresh or a restore from version control.

## Bypassing Validation (Not Recommended)

If you need to commit without running the pre-commit hook (strongly discouraged):

```bash
git commit --no-verify -m "commit message"
```

However, your changes will still be validated during the PR review process.

---

**Related:**
- [Validation Tools](validation.md) - Manual validation commands
- [CI/CD Validation](ci-cd.md) - Handling CI validation failures
- [Best Practices](best-practices.md) - Avoiding common issues
