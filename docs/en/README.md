<p align="center">
  <img src="../../logo.png" alt="VISOR logo" height="180" />
</p>

<h1 align="center">VISOR — Vulnerability Identification Scanner & Operational Reporter</h1>

A fast security scanner for Infrastructure-as-Code and configuration files.

The key feature of VISOR is complete freedom of action. It is not a rigid set of checks. You can write and add your own rules for any text formats, specific configs, or internal company standards.

## Capabilities
- **Flexible Rules:** Plain YAML. You define what to look for.
- **Context Detectors:** The scanner understands the difference between a Dockerfile and an NGINX config by paths or content.
- **Bilingual:** Rule descriptions in Russian and English.
- **Risk Assessment:** Calculation of an overall Score, CVSS, CWE, and output of severity level.
- **Exception Management:** Support for ignoring checks via code comments.

## Requirements
- Python 3.9+
- Packages: `typer`, `rich`, `pyyaml`, `identify`

Installation:

```bash
pip install -r requirements.txt
# or:
pip install typer rich pyyaml identify
```

## Usage (CLI)

The main interface is the command line. Supports scanning files, folders, and flexible output filtering.

```text
Usage: main.py [OPTIONS] PATHS...

╭─ Arguments ──────────────────────────────────────────────────────────────────────────────────╮
│ * paths      PATHS...  Paths to scan [required]                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────────────────────╮
│ --rules           -r      PATH      [default: rules]                                         │
│ --rule-file       -f      PATH                                                               │
│ --lang            -l      TEXT      [default: ru]                                            │
│ --output          -o      PATH                                                               │
│ --threads         -t      INTEGER   [default: 4]                                             │
│ --sort-by         -s      TEXT      severity|file [default: severity]                        │
│ --hide-low-info   -m                Hide LOW and INFO fromoutput                             │
│ --min-severity            TEXT      Minimum level to show:                                   │
│                                     CRITICAL|HIGH|MEDIUM|LOW|INFO [default: INFO]            │
│ --help                              Show this message and exit.                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────╯

```

## Usage Examples

Scan a folder (output in English, grouped by file):

```bash
python main.py examples/ -s file -l en

```

Run with a specific rule file:

```bash
python main.py examples/ -f rules/dockerfile.yaml

```

Generate a JSON report (for CI/CD) and hide unimportant notifications:

```bash
python main.py examples/ -l en -o visor.json --hide-low-info

```

## How Rules Work

The system is built on YAML packs. You can create a rule for any file type.

Example rule structure:

```yaml
metadata:
  severity_map:
    CRITICAL: {color: "red", deduction: 40}
    HIGH: {color: "light_red", deduction: 25}
    MEDIUM: {color: "yellow", deduction: 15}
    LOW: {color: "blue", deduction: 5}
    INFO: {color: "white", deduction: 0}

target_tag: my-custom-conf  # Tag for binding rules to files (root level)

detect:                       # Rule activation conditions
  path_glob_any:
    - "**/*.conf"
  yaml:                       # (Optional) YAML structure check
    required_root_keys_any: ["settings"]

rules:
  - id: "SEC-001"
    type: "regex"             # regex | contains | not_contains
    pattern: "debug = true"
    severity: "CRITICAL"
    cvss: 7.5
    cwe: [200]
    description:
      ru: "Режим отладки включен в продакшене"
      en: "Debug mode is enabled"

```

Notes:
- `severity_map` is optional; `color` affects output formatting. The `deduction` field is preserved in results for custom integrations but does not affect the built-in Score calculation.
- `cvss` must be specified for accurate calculation. If not specified, the engine will use default values based on severity: `CRITICAL=9.0`, `HIGH=7.5`, `MEDIUM=5.0`, `LOW=3.0`, `INFO=0.0`.

### Check Types

1. **regex**: Search by regular expression (Python re).
2. **contains**: Search for an exact substring match.
3. **not_contains**: Triggers if a mandatory string is absent.

### Mandatory Rule Fields

For the scanner to work correctly, each rule MUST contain:
- `id`
- `type` (regex|contains|not_contains)
- `pattern`
- `severity`
- `cvss` (mandatory)
- `cwe` (mandatory)
- `description` with `ru` and `en` keys

> It is recommended to always explicitly set `cvss` in each rule. This affects the Score.

## Suppressions

You can disable checks directly in the files being checked, using comments.

Ignore an entire file:

```text
# scan-ignore-file
# scan-ignore-file: RULE_ID_1, RULE_ID_2

```

Ignore a specific line:

```text
# scan-ignore
# scan-ignore: RULE_ID_1

```

## CI Integration (GitHub Actions)

Example usage in a pipeline. The build will fail if the security Score is below 80.

```yaml
name: visor-scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with: { python-version: '3.11' }
      - name: Install jq
        run: sudo apt-get update && sudo apt-get install -y jq
      - run: pip install -r requirements.txt
      - run: python main.py . -l en -o visor.json
      - name: Gate Check
        run: |
          SCORE=$(jq -r '.score' visor.json)
          echo "Security Score: $SCORE"
          if [ "$SCORE" -lt 80 ]; then exit 1; fi

```

## Score Calculation

- For each file, the maximum CVSS from its findings is taken.
- The average of these maximums across all files is calculated: `avg_max_cvss`.
- Final score: `Score = max(0, 100 - round(avg_max_cvss * 10))`.

Examples:
- No findings → `avg_max_cvss = 0.0` → `Score = 100`.
- `avg_max_cvss = 5.0` → `Score = 50`.
- `avg_max_cvss = 9.8` → `Score = 2`.

Note: `Score` does not depend on `deduction` and is not equal to the sum of CVSS. It reflects the "average maximum" risk per file.

## Roadmap
- [ ] Export reports to SARIF format for integration with GitHub Security Tab.
- [ ] Native support for scanning environment variables (ENV).
- [ ] Extension of standard rule packs for Terraform and NGINX.
- [ ] Support for multiline regular expressions for complex checks.
- [ ] Web interface for viewing and managing rules.

## License
Distributed under the MIT license. Use, copy, and modify as you wish.