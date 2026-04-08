package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/saddledata/pii-hound/internal/detectors"
	"github.com/saddledata/pii-hound/internal/scanner"
	"github.com/saddledata/pii-hound/internal/ui"
	"github.com/spf13/cobra"
)

var limit int
var failOnPii bool
var jsonOutput bool
var random bool
var rulesPath string

var scanCmd = &cobra.Command{
	Use:   "scan <uri> [uri...]",
	Short: "Scan one or more databases or file paths for PII",
	Long: `🐶 Sniff out unprotected PII and secrets in your data sources.

Supported Data Sources:
  - PostgreSQL: postgres://user:pass@host:port/db
  - MySQL:      mysql://user:pass@tcp(host:port)/db
  - Snowflake:  snowflake://user:pass@account/db/schema?role=x&warehouse=y
  - BigQuery:   bigquery://project-id/dataset-id
  - SQLite:     /path/to/database.db or sqlite:///path/to/database.db
  - S3:         s3://bucket/prefix/pattern (e.g. s3://my-bucket/data/*.csv)
  - GCS:        gs://bucket/prefix/pattern (e.g. gs://my-bucket/data/*.json)
  - CSV Files:  /path/to/data/*.csv
  - JSON Files: /path/to/data/*.json (Supports Arrays and JSON Lines)
  - Excel:      /path/to/data/*.xlsx
  - Parquet:    /path/to/data/*.parquet

The engine samples a configurable number of rows (default 1,000) per table/file
using a combination of column-name heuristics and regex data sampling.`,
	Example: `  # Scan a local CSV file
  pii-hound scan ./users.csv

  # Scan a Snowflake database
  pii-hound scan "snowflake://user:pass@account/MY_DB/MY_SCHEMA?warehouse=COMPUTE_WH"

  # Scan a BigQuery dataset
  pii-hound scan "bigquery://my-project/my_dataset"

  # Scan a SQLite database
  pii-hound scan ./my-data.db`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		// Load custom rules if provided
		if rulesPath != "" {
			if err := detectors.LoadCustomRules(rulesPath); err != nil {
				fmt.Printf("Error loading custom rules: %v\n", err)
				os.Exit(1)
			}
		}

		var allResults []scanner.Result

		for _, uri := range args {
			var s scanner.Scanner

			if strings.HasPrefix(uri, "postgres://") || strings.HasPrefix(uri, "postgresql://") {
				s = scanner.NewPostgresScanner(uri)
			} else if strings.HasPrefix(uri, "mysql://") {
				dsn := strings.TrimPrefix(uri, "mysql://")
				s = scanner.NewMySQLScanner(dsn)
			} else if strings.HasPrefix(uri, "snowflake://") {
				dsn := strings.TrimPrefix(uri, "snowflake://")
				s = scanner.NewSnowflakeScanner(dsn)
			} else if strings.HasPrefix(uri, "bigquery://") {
				s = scanner.NewBigQueryScanner(uri)
			} else if strings.HasPrefix(uri, "s3://") {
				s = scanner.NewS3Scanner(uri)
			} else if strings.HasPrefix(uri, "gs://") {
				s = scanner.NewGCSScanner(uri)
			} else if strings.HasPrefix(uri, "sqlite://") {
				path := strings.TrimPrefix(uri, "sqlite://")
				if strings.HasPrefix(path, "/") {
					path = strings.TrimPrefix(path, "/")
				}
				s = scanner.NewSQLiteScanner(path)
			} else if strings.HasSuffix(uri, ".db") || strings.HasSuffix(uri, ".sqlite") || strings.HasSuffix(uri, ".sqlite3") {
				s = scanner.NewSQLiteScanner(uri)
			} else if strings.HasSuffix(uri, ".csv") || strings.Contains(uri, ".csv") {
				s = scanner.NewCSVScanner(uri)
			} else if strings.HasSuffix(uri, ".json") || strings.HasSuffix(uri, ".jsonl") || strings.Contains(uri, ".json") {
				s = scanner.NewJSONScanner(uri)
			} else if strings.HasSuffix(uri, ".xlsx") || strings.HasSuffix(uri, ".xlsm") {
				s = scanner.NewExcelScanner(uri)
			} else if strings.HasSuffix(uri, ".parquet") {
				s = scanner.NewParquetScanner(uri)
			} else {
				fmt.Printf("Warning: Unsupported URI format '%s'. Skipping...\n", uri)
				continue
			}

			engine := scanner.NewEngine(s, limit)
			engine.Random = random
			if !jsonOutput {
				engine.Progress = &ui.ProgressBar{}
			}

			if !jsonOutput {
				fmt.Printf("🐶 Sniffing %s...\n", uri)
			}

			results, err := engine.Run(ctx)
			if err != nil {
				fmt.Printf("Error scanning %s: %v\n", uri, err)
				continue
			}
			allResults = append(allResults, results...)
		}

		if jsonOutput {
			ui.PrintJSONReport(allResults)
		} else {
			ui.PrintReport(allResults)
		}

		if failOnPii && len(allResults) > 0 {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().IntVarP(&limit, "limit", "l", 1000, "Maximum number of rows to sample per table/file")
	scanCmd.Flags().BoolVar(&failOnPii, "fail-on-pii", false, "Exit with code 1 if any PII is detected")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	scanCmd.Flags().BoolVar(&random, "random", false, "Sample rows randomly instead of the first N rows")
	scanCmd.Flags().StringVar(&rulesPath, "rules", "", "Path to a YAML file containing custom PII rules")
}
