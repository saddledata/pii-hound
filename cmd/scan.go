package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/saddledata/pii-hound/internal/scanner"
	"github.com/saddledata/pii-hound/internal/ui"
	"github.com/spf13/cobra"
)

var limit int
var failOnPii bool
var jsonOutput bool
var random bool

var scanCmd = &cobra.Command{
	Use:   "scan <uri>",
	Short: "Scan a database or file path for PII",
	Long: `🐶 Sniff out unprotected PII and secrets in your data sources.

Supported Data Sources:
  - PostgreSQL: postgres://user:pass@host:port/db
  - MySQL:      mysql://user:pass@tcp(host:port)/db
  - SQLite:     /path/to/database.db or sqlite:///path/to/database.db
  - S3:         s3://bucket/prefix/pattern (e.g. s3://my-bucket/data/*.csv)
  - GCS:        gs://bucket/prefix/pattern (e.g. gs://my-bucket/data/*.json)
  - CSV Files:  /path/to/data/*.csv
  - JSON Files: /path/to/data/*.json (Supports Arrays and JSON Lines)

The engine samples a configurable number of rows (default 1,000) per table/file
using a combination of column-name heuristics and regex data sampling.`,
	Example: `  # Scan a local CSV file
  pii-hound scan ./users.csv

  # Scan a SQLite database
  pii-hound scan ./my-data.db

  # Scan an S3 bucket (requires AWS credentials in env or ~/.aws/config)
  pii-hound scan "s3://my-bucket/exports/*.csv"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		uri := args[0]
		ctx := context.Background()

		var s scanner.Scanner

		if strings.HasPrefix(uri, "postgres://") || strings.HasPrefix(uri, "postgresql://") {
			s = scanner.NewPostgresScanner(uri)
		} else if strings.HasPrefix(uri, "mysql://") {
			// Convert mysql:// to DSN if needed, but the driver expects user:pass@tcp(host:port)/db
			// For simplicity we assume user:pass@tcp(host:port)/db format for now or handle the prefix
			dsn := strings.TrimPrefix(uri, "mysql://")
			s = scanner.NewMySQLScanner(dsn)
		} else if strings.HasPrefix(uri, "s3://") {
			s = scanner.NewS3Scanner(uri)
		} else if strings.HasPrefix(uri, "gs://") {
			s = scanner.NewGCSScanner(uri)
		} else if strings.HasPrefix(uri, "sqlite://") {
			path := strings.TrimPrefix(uri, "sqlite://")
			if strings.HasPrefix(path, "/") {
				path = strings.TrimPrefix(path, "/") // handle sqlite:///path
			}
			s = scanner.NewSQLiteScanner(path)
		} else if strings.HasSuffix(uri, ".db") || strings.HasSuffix(uri, ".sqlite") || strings.HasSuffix(uri, ".sqlite3") {
			s = scanner.NewSQLiteScanner(uri)
		} else if strings.HasSuffix(uri, ".csv") || strings.Contains(uri, ".csv") {
			s = scanner.NewCSVScanner(uri)
		} else if strings.HasSuffix(uri, ".json") || strings.HasSuffix(uri, ".jsonl") || strings.Contains(uri, ".json") {
			s = scanner.NewJSONScanner(uri)
		} else {
			fmt.Println("Error: Unsupported URI format. Must be postgres://, mysql://, s3://, gs://, sqlite://, *.db, *.csv, or *.json")
			os.Exit(1)
		}

		engine := scanner.NewEngine(s, limit)
		engine.Random = random

		if !jsonOutput {
			fmt.Printf("🐶 Sniffing %s (limit %d rows, random: %v)...\n", uri, limit, random)
		}

		results, err := engine.Run(ctx)
		if err != nil {
			fmt.Printf("Error during scan: %v\n", err)
			os.Exit(1)
		}

		if jsonOutput {
			ui.PrintJSONReport(results)
		} else {
			ui.PrintReport(results)
		}

		if failOnPii && len(results) > 0 {
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
}
