# Best Practices

Follow these best practices to ensure smooth development and contributions to the CoSAI Risk Map.

## Development Workflow

### 1. Create a GitHub issue first

For any ongoing development work:

```bash
# Before starting work, create an issue to:
# - Document the planned changes
# - Enable collaboration and discussion
# - Track progress and link related PRs
# - Provide context for reviewers
```

This helps maintain project visibility and enables better collaboration.

### 2. Always run manual validation during development

```bash
python scripts/hooks/validate_riskmap.py --force
```

### 3. Preview your changes visually

Generate graphs to see the impact of your changes:

```bash
# Generate component relationship graph
python scripts/hooks/validate_riskmap.py --to-graph ./preview-graph.md --force

# Generate control-to-component relationship graph
python scripts/hooks/validate_riskmap.py --to-controls-graph ./preview-controls.md --force

# Generate controls-to-risk relationship graph
python scripts/hooks/validate_riskmap.py --to-risk-graph ./preview-risks.md --force
```

### 4. Format files before committing

Though pre-commit handles this automatically, it's useful to format during development:

```bash
npx prettier --write risk-map/yaml/*.yaml
```

### 5. Test edge changes incrementally

Add one component connection at a time to make debugging easier.

### 6. Document complex edge relationships

Explain complex relationships in commit messages for future maintainers.

## Naming Conventions

### 7. Use meaningful component IDs

Follow the `component[Name]` convention for components:
- ✅ `componentModelTraining`
- ❌ `compMT` or `model_training`

Apply similar conventions to controls (`control[Name]`), risks (short acronyms), and personas (`persona[Name]`).

## Validation Strategies

### 8. Validate against JSON schemas

Schema validation is enforced by pre-commit hooks, but you can also validate manually before committing.

### 9. Review existing components

Study established patterns before adding new components to maintain consistency.

### 10. Leverage automatic graph generation

When you commit changes to `components.yaml`, the updated graph is automatically generated and staged.

### 11. Use debug mode for troubleshooting

When graph generation produces unexpected results:

```bash
python scripts/hooks/validate_riskmap.py --to-graph ./debug-graph.md --debug --force
```

### 12. Use control graphs to validate mappings

When adding or modifying controls, generate control graphs to verify your mappings are logical:

```bash
# Generate control graph to verify your control mappings
python scripts/hooks/validate_riskmap.py --to-controls-graph ./verify-controls.md --force

# Generate risk graph to verify control-risk relationships
python scripts/hooks/validate_riskmap.py --to-risk-graph ./verify-risks.md --force
```

### 13. Run all validations locally before pushing

Run the full pre-commit suite manually to catch issues early:

```bash
# Run the key validations manually before pushing
python scripts/hooks/validate_riskmap.py --force
python scripts/hooks/validate_control_risk_references.py --force
python scripts/hooks/validate_framework_references.py --force
```

## Collaboration

### Follow the branching strategy

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the proper branching workflow (develop vs. main).

### Write clear commit messages

Use the "This commit does..." format for clarity.

### Link PRs to issues

Always reference the related GitHub issue in your pull request description.

---

**Related:**
- [Validation Tools](validation.md) - All validation commands
- [Troubleshooting](troubleshooting.md) - Common issues and solutions
- [General Workflow](workflow.md) - Overall contribution process
