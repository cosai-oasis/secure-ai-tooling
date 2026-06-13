# Writing Documentation with Testable Code Examples

This project includes support for testing code block formatted Python code examples in markdown files. Automatic testing ensures that the samples remain valid thru changes to the project, additional developer engagement, etc. 

---

## Overview

All Python code blocks in documentation under `risk-map/docs/` are automatically tested as part of the validation suite. This ensures that:

- Code examples in documentation are always correct and up-to-date
- Breaking changes to the data model are caught when examples fail

The testing system is implemented in `scripts/hooks/tests/test_markdown_examples.py` and runs automatically in CI/CD pipelines.

---

## Writing Testable Python Code Blocks

### Basic Format Requirements

For a Python code block to be tested, it must meet these requirements:

1. **Preceded by a heading**: The code block must appear under a markdown heading (`###` or deeper)
2. **Language tag**: Use the `python` language identifier
3. **No intervening text**: The code block must appear immediately after the heading (minimal descriptive text is allowed)
4. **Executable code**: The code must be valid, executable Python

### Example: Correct Format

#### Example: Query Risks by Lifecycle Stage
 
```python
import yaml

with open('risk-map/yaml/risks.yaml', 'r') as f:
    data = yaml.safe_load(f)

runtime_risks = [r['id'] for r in data['risks'] if 'runtime' in r.get('lifecycleStage', [])]
print(f"Runtime risks: {runtime_risks}")
```

### Pattern Matching Details

The testing system uses this regex pattern to find code blocks:

```
###+\s+([^\n]+)\n(?:(?!^##)[\s\S])*?```python\n(.*?)```
```

**Pattern breakdown:**
- `###+\s+` - Matches heading with 3 or more `#` characters followed by whitespace
- `([^\n]+)\n` - Captures heading text up to newline
- `(?:(?!^##)[\s\S])*?` - Matches content between heading and code block, **but stops if another heading is encountered**
  - `(?:...)` - Non-capturing group
  - `(?!^##)` - Negative lookahead: ensures next line doesn't start with `##`
  - `[\s\S]*?` - Matches any character (including newlines), non-greedy
- ` ```python\n` - Matches start of Python code block
- `(.*?)` - Captures the code content
- ` ``` ` - Matches end of code block

**Key behavior:** The regex will **not** match across headings. If there's another heading between the initial heading and a code block, they won't be matched together. This prevents accidental association of code blocks with unrelated headings.

---

## Working Directory and File Paths

### Execution Context

Code examples are executed with:
- **Working directory**: Repository root (`/workspaces/secure-ai-tooling`)
- **Timeout**: 10 seconds maximum execution time
- **Isolated namespace**: Each code block runs in a fresh namespace (no state pollution between tests)

#### File Path Examples

When referencing files in code examples, use paths relative to the repository root:

**✅ Correct:**
```python
import yaml

with open('risk-map/yaml/components.yaml', 'r') as f:
    data = yaml.safe_load(f)
```

**❌ Incorrect:**
```python
with open('../yaml/components.yaml', 'r') as f:  # Wrong: assumes specific working directory
    data = yaml.safe_load(f)
```

---

## Skipping Tests for Documentation-Only Examples

Sometimes you need to include code examples that are for illustration purposes only and shouldn't be executed. Use skip markers to exclude these from testing.

### When to Skip Tests [doc-only]

Skip tests for code examples that:
- Require external dependencies not in the test environment
- Are incomplete or pseudocode
- Demonstrate error conditions
- Show conceptual patterns rather than runnable code

### Skip Marker Options

You can mark code blocks to be skipped in several ways:

#### Option 1: Skip Marker in Heading

Add `[skip-test]`, `[doc-only]`, or `[documentation-only]` to the heading:

##### Example: Advanced Configuration [skip-test]
 
This example requires additional setup and is for illustration only.
 
```python
import hypothetical_module
# This won't be executed in tests
```

#### Option 2: Skip Comment in Code

Add `# SKIP-TEST` in the first 3 lines of the code block:

##### Example: Pseudocode Pattern
 
```python
# SKIP-TEST
# This is pseudocode for illustration
for each_component in system:
    apply_security_controls()
```

### Skip Markers Reference [doc-only]

| Marker | Location | Case Sensitive | Example |
|--------|----------|----------------|---------|
| `[skip-test]` | Heading | No | `### Example [skip-test]` |
| `[doc-only]` | Heading | No | `### Example [doc-only]` |
| `[documentation-only]` | Heading | No | `### Example [documentation-only]` |
| `# SKIP-TEST` | Code (first 3 lines) | No | `# SKIP-TEST` or `# skip-test` |

---

## Timeout Protection

All code examples are subject to a **10-second timeout** to prevent:
- Infinite loops from hanging the test suite
- Resource-intensive operations from slowing down CI/CD
- Accidental blocking operations

If your example needs to demonstrate long-running operations, use a skip marker or mock the time-consuming parts:

### Example: Demonstrating Long Operations [doc-only]

```python
# This would timeout, so we mark it as doc-only
import time
while True:
    time.sleep(1)  # Would exceed 10-second timeout
```

---

## Common Patterns and Best Practices

### Pattern 1: Loading and Querying YAML Data

Most examples in the documentation query the risk map YAML files:

```python
import yaml

# Load data from YAML file
with open('risk-map/yaml/risks.yaml', 'r') as f:
    risks_data = yaml.safe_load(f)

# Query the data
high_impact_risks = [
    risk['id'] for risk in risks_data['risks']
    if 'confidentiality' in risk.get('impactType', [])
]

print(f"Found {len(high_impact_risks)} high-impact risks")
```

### Pattern 2: Working with Framework Mappings

```python
import yaml

with open('risk-map/yaml/frameworks.yaml', 'r') as f:
    frameworks = yaml.safe_load(f)

# Get framework by ID
mitre_atlas = next(f for f in frameworks['frameworks'] if f['id'] == 'mitre-atlas')

# Construct technique URI. Mapping values are version-pinned (e.g. AML.T0001@5.0.1);
# strip the @-token before {id} substitution so the URI targets the base ID.
technique_id = 'AML.T0001@5.0.1'
base_id = technique_id.split('@', 1)[0]
uri = mitre_atlas['techniqueUriPattern'].replace('{id}', base_id)
print(f"Technique URI: {uri}")
```

### Pattern 3: Cross-Referencing Data

```python
import yaml

# Load multiple data sources
with open('risk-map/yaml/risks.yaml', 'r') as f:
    risks = yaml.safe_load(f)
with open('risk-map/yaml/controls.yaml', 'r') as f:
    controls = yaml.safe_load(f)

# Cross-reference risks and controls
for risk in risks['risks']:
    related_controls = [
        c['id'] for c in controls['controls']
        if risk['id'] in c.get('risks', [])
    ]
    if related_controls:
        print(f"{risk['id']}: {len(related_controls)} controls")
```

---

## Testing Your Examples Locally

Before committing documentation with code examples, test them locally:

### Run All Documentation Tests

```bash
pytest scripts/hooks/tests/test_markdown_examples.py -v
```

### Run Tests for a Specific File

```bash
pytest scripts/hooks/tests/test_markdown_examples.py -v -k "your-doc-file"
```

### Run with Detailed Output

```bash
pytest scripts/hooks/tests/test_markdown_examples.py -v -s
```

### Expected Output

```
scripts/hooks/tests/test_markdown_examples.py::test_code_block[guide-frameworks.md - Example 1] PASSED
scripts/hooks/tests/test_markdown_examples.py::test_code_block[guide-frameworks.md - Example 2] PASSED
```

---

## Troubleshooting

### Code Block Not Being Tested

**Problem**: Your code block isn't being picked up by the test system.

**Solutions**:
- ✅ Ensure the code block is under a heading with `###` or more `#` characters
- ✅ Verify you're using the `python` language tag (not `py` or missing)
- ✅ Check there's minimal text between the heading and code block
- ✅ Confirm the file is in `risk-map/docs/` directory

### File Not Found Errors

**Problem**: Code fails with `FileNotFoundError` when accessing YAML files.

**Solutions**:
- ✅ Use paths relative to repository root: `risk-map/yaml/file.yaml`
- ✅ Don't use `../` relative paths
- ✅ Remember working directory is the repository root

### Import Errors

**Problem**: Code fails with `ModuleNotFoundError` for standard imports.

**Solutions**:
- ✅ Verify the module is in `requirements.txt`
- ✅ Common available imports: `yaml`, `pytest`, `pathlib`, `re`, `json`
- ✅ If the module isn't essential, consider using a skip marker

### Timeout Errors

**Problem**: Code exceeds 10-second execution limit.

**Solutions**:
- ✅ Use a skip marker if the example is for illustration
- ✅ Reduce the dataset size in the example
- ✅ Mock time-consuming operations
- ✅ Avoid network calls or heavy computations

---

## Examples: Good vs. Bad

### ❌ Bad: Missing Heading [doc-only]

Here's how to query risks:

```python
import yaml
# This won't be tested - no heading!
```

### ✅ Good: Proper Heading

### Example: Query Risks

```python
import yaml
# This will be tested
with open('risk-map/yaml/risks.yaml', 'r') as f:
    data = yaml.safe_load(f)
```

### ❌ Bad: Wrong Language Tag [doc-only]

### Example: Code with wrong tag

```py
# Won't be tested - wrong language tag
```

### ✅ Good: Correct Language Tag

### Example: Code with correct tag

```python
# Will be tested - correct language tag
print("Hello")
```

### ❌ Bad: Incomplete Code

### Example: Process Data [doc-only]

```python
for item in data:
    # Incomplete - 'data' not defined
    process(item)
```

### ✅ Good: Complete, Executable Code

### Example: Process Data

```python
data = ['a', 'b', 'c']
for item in data:
    print(f"Processing {item}")
```

---

## Related Documentation

- **[Validation Tools](validation.md)** - Manual validation commands and testing
- **[Best Practices](best-practices.md)** - Development workflow recommendations
- **[CI/CD Documentation](ci-cd.md)** - How tests run in GitHub Actions
- **[Troubleshooting Guide](troubleshooting.md)** - Common problems and solutions

---

## Summary

**To write testable Python code examples:**

1. ✅ Use `###` or deeper headings
2. ✅ Use the `python` language tag
3. ✅ Write complete, executable code
4. ✅ Use file paths relative to repository root
5. ✅ Use skip markers for documentation-only examples
6. ✅ Test locally before committing: `pytest scripts/hooks/tests/test_markdown_examples.py`

**Your examples will automatically:**
- Run in an isolated namespace
- Execute from the repository root
- Timeout after 10 seconds
- Be tested in CI/CD pipelines
