# Manual Validation of Unstaged Files

The `pre-commit` hook and all individual validation scripts support the `--force` flag to validate all files regardless of their git staging status (useful during development).

```bash
# Validating unstaged files during development...
# Note: --force validates all relevant files, not just those staged for commit

# Run all validation steps
.git/hooks/pre-commit --force

# Run component edge validation-only
.git/hooks/validate_riskmap.py --force

# Run control-to-risk reference validation-only
.git/hooks/validate_control_risk_references.py --force
```

---

**Related:**
- [Validation Flow](validation-flow.md) - Normal commit validation process
- [Graph Generation](graph-generation.md) - Generating graphs manually
- [Table Generation](table-generation.md) - Generating tables manually
- [Troubleshooting](troubleshooting.md) - Debugging validation manually
