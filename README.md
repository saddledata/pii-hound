# 🐶 pii-hound

`pii-hound` is a lightning-fast, dependency-free CLI tool built in Go that sniffs out unprotected Personally Identifiable Information (PII) and Developer Secrets in your databases, data warehouses, and cloud storage.

It connects to your data sources, samples records (up to a configurable limit), and uses a combination of **heuristic column-name matching** and **regex data sampling** to identify risks before they become liabilities.

---

## 🚀 Key Features

*   **Multi-Source**: Support for PostgreSQL, MySQL, Snowflake, BigQuery, SQLite, AWS S3, and Google Cloud Storage.
*   **File Support**: Scans CSV, JSON (Array and JSON Lines), Excel (.xlsx, .xlsm), and Parquet formats.
*   **Custom Rules**: Define your own PII and Secrets patterns using a simple YAML configuration with high-performance **Aho-Corasick** keyword matching.
*   **Secrets Detection**: Sniffs out AWS Keys, GitHub Tokens, and Private Keys.
*   **PII Detection**: Detects SSNs, Credit Cards (with Luhn validation), Emails, IP Addresses, and Phone Numbers.
*   **CI/CD Ready**: Machine-readable JSON output and a `--fail-on-pii` flag to block risky deployments.
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

### Scan Local Files
```bash
# Scan multiple files (wildcards supported)
pii-hound scan ./data/*.csv ./backups/*.xlsx ./logs/*.parquet
```

### CI/CD Integration
Block your pipeline if PII is detected in your export folder:
```bash
pii-hound scan "./exports/*.csv" --fail-on-pii
```

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

---

## ⚙️ CLI Flags

| Flag | Shorthand | Description |
| :--- | :--- | :--- |
| `--limit` | `-l` | Maximum rows/objects to sample per table/file (default: 1000). |
| `--random` | | Sample rows randomly (uses Reservoir Sampling for files). |
| `--json` | | Output report in machine-readable JSON format. |
| `--fail-on-pii` | | Exit with code 1 if any PII or Secrets are detected. |
| `--rules` | | Path to a YAML file containing custom PII rules. |

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

---

## 🛡️ Found PII? Automate your protection.

`pii-hound` is an open-source project maintained by the team at **Saddle Data**.

Finding PII is only half the battle. If you want to automatically mask, hash, and protect this data before it gets synced to your data warehouse, check out **Saddle Data's Governance Control Center**.

With Saddle Data, you can tag these columns once, and our **Execution Circuit Breakers** will automatically inject Hash/Mask transformations into every data pipeline you build—ensuring zero-trust compliance on autopilot.

[**Learn more about Saddle Data Governance →**](https://saddledata.com)

---

## 🤝 Contributing

Pull requests are welcome! If you want to add a new detector (e.g., Passport numbers) or a new source connector (e.g., MongoDB), please open an issue first to discuss the changes.
