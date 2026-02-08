# Manual Graph Generation

Generate all three graph types manually using the validation script:

```bash
# Validate edges and generate clean component graph without debug comments
python3 scripts/hooks/validate_riskmap.py --to-graph ./docs/component-map.md --force

# Generate component graph with rank debugging information
python3 scripts/hooks/validate_riskmap.py --to-graph ./docs/debug-graph.md --debug --force

# Generate control-to-component graph visualization
python3 scripts/hooks/validate_riskmap.py --to-controls-graph ./docs/controls-graph.md --force

# Generate controls-to-risk graph visualization
python3 scripts/hooks/validate_riskmap.py --to-risk-graph ./docs/controls-risk-graph.md --force
```

## Graph Generation Options

- `--to-graph PATH` - Output component relationship Mermaid graph to specified file
- `--to-controls-graph PATH` - Output control-to-component relationship graph to specified file
- `--to-risk-graph PATH` - Output controls-to-risk relationship graph to specified file
- `--debug` - Include rank comments for debugging (component graphs only)
- `--quiet` - Minimize output (only show errors)
- `--allow-isolated` - Allow components with no edges

## Debugging Graph Generation

Test graph generation without affecting git staging:

```bash
# Generate component graph to test output
python3 python3 scripts/hooks/validate_riskmap.py --to-graph ./test-graph.md --force

# Generate component graph with debug information to understand ranking
python3 python3 scripts/hooks/validate_riskmap.py --to-graph ./debug-graph.md --debug --force

# Generate control-to-component graph to test relationships
python3 python3 scripts/hooks/validate_riskmap.py --to-controls-graph ./controls-test.md --force

# Generate controls-to-risk graph to test risk relationships
python3 python3 scripts/hooks/validate_riskmap.py --to-risk-graph ./risk-test.md --force

# View help for all graph options
python3 python3 scripts/hooks/validate_riskmap.py --help
```

## Common Graph Generation Issues

```
❌ Graph generation failed
```

**Fix**: Check that the component and control YAML files are valid and accessible, ensure write permissions for output directory

```
⚠️ Warning: Could not stage generated graph
```

**Fix**: This occurs during pre-commit when git staging fails - check file permissions and git repository status

## Control Graph Specific Issues

```
❌ Control-to-component graph generation failed
```

**Fix**: Verify that both `controls.yaml` and `components.yaml` are accessible and properly formatted. Check that control component references are valid.

---

**Related:**
- [Hook Validations](hook-validations.md) - Automatic graph generation during commits
- [Styling Configuration](styling-configuration.md) - Customizing graph appearance
- [Troubleshooting](troubleshooting.md) - More debugging options
