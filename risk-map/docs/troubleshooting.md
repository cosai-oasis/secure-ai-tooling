# Troubleshooting Validation Issues

This page covers common validation issues and how to resolve them.

## Debugging framework hooks

The repo uses the upstream `pre-commit` framework. Useful commands while debugging:

```bash
# Run all hooks against the current working tree (regenerates derivatives):
uv run --locked --no-sync pre-commit run --all-files

# Run one hook by id, against all files or a specific file set:
uv run --locked --no-sync pre-commit run validate-component-edges --all-files
uv run --locked --no-sync pre-commit run check-jsonschema --files risk-map/yaml/components.yaml

# Validate content without regenerating graphs / tables / SVGs:
./scripts/tools/validate-all.sh
```

> **Note:** `uv run --locked --no-sync pre-commit run --all-files` stages regenerated derivatives (SVGs,
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
uv run --locked --no-sync python scripts/hooks/validate_riskmap.py --to-graph ./test-graph.md --force
```

### 2. Control-to-component graph generation failed

```
❌ Control-to-component graph generation failed
```

**Fix**: Verify that both `controls.yaml` and `components.yaml` are accessible and properly formatted. Test manually:

```bash
uv run --locked --no-sync python scripts/hooks/validate_riskmap.py --to-controls-graph ./test-controls.md --force
```

### 3. Generated graph not staged

```
⚠️ Warning: Could not stage generated graph
```

**Fix**: Check file permissions and git repository status. Ensure `./risk-map/diagrams/` is writable (graph wrapper output location).

### 4. Component layout seems suboptimal

**Fix**: Use debug mode to inspect graph structure:

```bash
uv run --locked --no-sync python scripts/hooks/validate_riskmap.py --to-graph ./debug-graph.md --debug --force
```

### 5. Control graph looks cluttered or confusing

**Fix**: The control graph uses automatic optimization. If results seem wrong, verify:
- Control component references are accurate in `controls.yaml`
- Component categories are correctly assigned in `components.yaml`
- Test the graph generation manually to inspect the output

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
