# 🐶 pii-hound

`pii-hound` is a lightning-fast, dependency-free CLI tool built in Go that sniffs out unprotected Personally Identifiable Information (PII) and Developer Secrets in your databases, data warehouses, and cloud storage.

It connects to your data sources, samples records (up to a configurable limit), and uses a combination of **heuristic column-name matching** and **regex data sampling** to identify risks before they become liabilities.

---

## 🚀 Key Features

*   **Multi-Source**: Support for PostgreSQL, MySQL, Snowflake, BigQuery, SQLite, AWS S3, and Google Cloud Storage.
*   **File Support**: Scans CSV, JSON (Array and JSON Lines), Excel (.xlsx, .xlsm), and Parquet formats.
*   **Project Configuration**: Use a `.pii-hound.yaml` file to set project-wide policies and ignore specific false positives.
*   **Custom Rules**: Define your own PII and Secrets patterns using a simple YAML configuration with high-performance **Aho-Corasick** keyword matching.
*   **Secrets Detection**: Sniffs out AWS Keys, GitHub Tokens, and Private Keys.
*   **PII Detection**: Detects SSNs, Credit Cards (with Luhn validation), Emails, IP Addresses, and Phone Numbers.
*   **CI/CD Ready**: Machine-readable JSON and **SARIF** output, plus a `--fail-on-pii` flag to block risky deployments.
*   **Git Integration**: Use the `--diff` flag to scan only files that have changed in your repository.
*   **GitHub Integration**: Upload SARIF results directly to GitHub's Security tab.
*   **Intelligence**: High-performance **Reservoir Sampling** for large files and random database sampling.
*   **Lightning Fast**: Concurrent, streaming architecture designed to handle gigabytes of data without high memory usage.

---

## 📥 Installation

### macOS (Homebrew)
```bash
brew tap saddledata/homebrew-tap
brew install pii-hound
```

### Docker
```bash
docker run --rm saddledata/pii-hound --help
```

### Binary Downloads
Download the latest pre-compiled binaries for Linux, Windows, or macOS from the [Releases](https://github.com/saddledata/pii-hound/releases) page.

---

## 🛠️ Usage

### Scan a Database
```bash
# PostgreSQL (quote the URI!)
pii-hound scan "postgres://user:pass@localhost:5432/db?sslmode=disable"

# MySQL
pii-hound scan "mysql://user:pass@tcp(localhost:3306)/db"

# Snowflake
pii-hound scan "snowflake://user:pass@account/MY_DB/MY_SCHEMA?warehouse=COMPUTE_WH"

# BigQuery
pii-hound scan "bigquery://my-project/my_dataset"

# SQLite
pii-hound scan "./my-app.db"
```

### Scan Cloud Storage
```bash
# AWS S3 (requires local AWS credentials)
pii-hound scan "s3://my-bucket/exports/*.csv"

# Google Cloud Storage (requires GOOGLE_APPLICATION_CREDENTIALS)
pii-hound scan "gs://my-bucket/backups/*.json"
```

### GitHub Action
The fastest way to use `pii-hound` in your CI/CD pipeline is with the official GitHub Action.

```yaml
- name: Scan for PII
  uses: saddledata/pii-hound@v1
  with:
    path: './data'
    fail-on-pii: true
    sarif: 'pii-results.sarif'

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: 'pii-results.sarif'
```

### Scan Local Files
...
# Scan multiple files (wildcards supported)
pii-hound scan ./data/*.csv ./backups/*.xlsx ./logs/*.parquet
```

### CI/CD Integration
Block your pipeline if PII is detected in your export folder:
```bash
pii-hound scan "./exports/*.csv" --fail-on-pii
```

### Git 'Changed Files' Only
Speed up your scans by only checking files that have changed in git (staged, unstaged, or since a base branch):
```bash
# Scan all local changes
pii-hound scan --diff

# Scan changed files compared to main branch
pii-hound scan --diff --base origin/main
```

### GitHub Actions (SARIF)
Generate a SARIF report to see PII findings in your PRs and Security tab:
```bash
pii-hound scan ./data --sarif > pii-results.sarif
```
Then use the `github/codeql-action/upload-sarif` action to upload the results.

### Custom Rules
Define proprietary PII patterns or sensitive keywords in a `rules.yaml` file:
```yaml
rules:
  - name: "Internal Project ID"
    type: "PII"
    risk: "HIGH"
    regex: "PRJ-[0-9]{5}"
    heuristic: "project_id|proj_code"
  - name: "Sensitive Keywords"
    type: "Sensitive Keyword"
    risk: "MEDIUM"
    keywords: ["AcmeCorp", "SecretProjectX"]
```
Then run the scan with the `--rules` flag:
```bash
pii-hound scan ./data.csv --rules rules.yaml
```

### Configuration & Ignore
`pii-hound` automatically looks for a `.pii-hound.yaml` file in your current directory. You can use this to set global limits, random sampling, and ignore specific files or columns that produce false positives.

Example `.pii-hound.yaml`:
```yaml
limit: 500
random: true
fail_on_pii: true

# Ignore specific false positives
ignore:
  - source: "legacy_data.csv"
    column: "fake_ssn"
  - source: "test_users.json"
    type: "Email Address"
  - source: "logs/*" # Use wildcards for sources

# Define custom rules inline
rules:
  - name: "Internal ID"
    regex: "INT-[0-9]{4}"
```

---

## ⚙️ CLI Flags

| Flag | Shorthand | Description |
| :--- | :--- | :--- |
| `--limit` | `-l` | Maximum rows/objects to sample per table/file (default: 1000). |
| `--random` | | Sample rows randomly (uses Reservoir Sampling for files). |
| `--diff` | | Only scan files that have changed in git. |
| `--base` | | Base git ref to compare against (used with --diff). |
| `--json` | | Output report in machine-readable JSON format. |
| `--sarif` | | Output report in SARIF format for GitHub Security. |
| `--fail-on-pii` | | Exit with code 1 if any PII or Secrets are detected. |
| `--config` | | Path to a YAML configuration file. |
| `--rules` | | Path to a YAML configuration file (legacy alias for --config). |

---

## 🎯 What does it detect?

`pii-hound` uses a dual-engine approach. It first checks for **suspicious column names** (e.g., `ssn`, `cc_num`, `apikey`) and then evaluates the **actual data** inside those columns.

### 🔴 High Risk
*   **Social Security Numbers (US)**: Matches standard patterns.
*   **Credit Card Numbers**: Validated via the **Luhn Algorithm** to eliminate false positives.
*   **Developer Secrets**: AWS Access Keys, GitHub Tokens, and RSA/SSH Private Keys.
*   **Email Addresses**: Standard RFC-compliant detection.

### 🟡 Medium Risk
*   **IP Addresses**: Both IPv4 and IPv6 detection.
*   **Phone Numbers**: Matches various international and US formats.
*   **Person Names**: Heuristic detection for common column names (e.g., `first_name`, `last_name`, `fullname`).

---

## 🛡️ Found PII? Automate your protection.

`pii-hound` is an open-source project maintained by the team at **Saddle Data**.

Finding PII is only half the battle. If you want to automatically mask, hash, and protect this data before it gets synced to your data warehouse, check out **Saddle Data's Governance Control Center**.

With Saddle Data, you can tag these columns once, and our **Execution Circuit Breakers** will automatically inject Hash/Mask transformations into every data pipeline you build—ensuring zero-trust compliance on autopilot.

[**Learn more about Saddle Data Governance →**](https://saddledata.com)

---

## 🤝 Contributing

Pull requests are welcome! If you want to add a new detector (e.g., Passport numbers) or a new source connector (e.g. MongoDB), please open an issue first to discuss the changes.
