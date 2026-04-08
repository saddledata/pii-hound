# 🐶 pii-hound

`pii-hound` is a lightning-fast, dependency-free CLI tool built in Go that sniffs out unprotected Personally Identifiable Information (PII) and Developer Secrets in your databases, data warehouses, and cloud storage.

It connects to your data sources, samples records (up to a configurable limit), and uses a combination of **heuristic column-name matching** and **regex data sampling** to identify risks before they become liabilities.

---

## 🚀 Key Features

*   **Multi-Source**: Support for PostgreSQL, MySQL, SQLite, AWS S3, and Google Cloud Storage.
*   **File Support**: Scans CSV and JSON (Array and JSON Lines) formats.
*   **Secrets Detection**: Sniffs out AWS Keys, GitHub Tokens, and Private Keys.
*   **PII Detection**: Detects SSNs, Credit Cards (with Luhn validation), Emails, IP Addresses, and Phone Numbers.
*   **CI/CD Ready**: Machine-readable JSON output and a `--fail-on-pii` flag to block risky deployments.
*   **Random Sampling**: Use the `--random` flag to sample data from across your entire database, not just the first rows.
*   **Lightning Fast**: Concurrent, streaming architecture designed to handle gigabytes of data without high memory usage.

---

## 🛠️ Usage

### Scan a Database
```bash
# PostgreSQL (quote the URI!)
pii-hound scan "postgres://user:pass@localhost:5432/db?sslmode=disable"

# MySQL
pii-hound scan "mysql://user:pass@tcp(localhost:3306)/db"

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
# Single CSV or JSON file
pii-hound scan "./data/users.csv"

# Directory with wildcard
pii-hound scan "./data/*.json"
```

### CI/CD Integration
Block your pipeline if PII is detected in your export folder:
```bash
pii-hound scan "./exports/*.csv" --fail-on-pii
```

---

## ⚙️ CLI Flags

| Flag | Shorthand | Description |
| :--- | :--- | :--- |
| `--limit` | `-l` | Maximum rows/objects to sample per table/file (default: 1000). |
| `--random` | | Sample rows randomly from databases instead of the first N rows. |
| `--json` | | Output report in machine-readable JSON format. |
| `--fail-on-pii` | | Exit with code 1 if any PII or Secrets are detected. |

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

Pull requests are welcome! If you want to add a new detector (e.g., Passport numbers) or a new source connector (e.g., Snowflake), please open an issue first to discuss the changes.
