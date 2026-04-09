package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/saddledata/pii-hound/internal/detectors"
	"github.com/saddledata/pii-hound/internal/git"
	"github.com/saddledata/pii-hound/internal/scanner"
	"github.com/saddledata/pii-hound/internal/ui"
	"github.com/spf13/cobra"
)

var limit int
var failOnPii bool
var jsonOutput bool
var sarifOutput bool
var random bool
var diff bool
var baseRef string
var configPath string
var outputPath string

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

  # Scan only files that have changed in git
  pii-hound scan --diff

  # Scan changed files compared to a base branch
  pii-hound scan --diff --base main`,
	Args: cobra.ArbitraryArgs,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()

		// 1. Try to load config
		if configPath == "" {
			// Look for default config file
			if _, err := os.Stat(".pii-hound.yaml"); err == nil {
				configPath = ".pii-hound.yaml"
			}
		}

		if configPath != "" {
			if err := detectors.LoadConfig(configPath); err != nil {
				fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
				os.Exit(1)
			}
		}

		// 2. Override config with CLI flags if they were explicitly set
		if cmd.Flags().Changed("limit") {
			detectors.GlobalConfig.Limit = limit
		} else if detectors.GlobalConfig.Limit == 0 {
			detectors.GlobalConfig.Limit = 1000 // default
		}

		if cmd.Flags().Changed("random") {
			detectors.GlobalConfig.Random = random
		}

		if cmd.Flags().Changed("fail-on-pii") {
			detectors.GlobalConfig.FailOnPii = failOnPii
		}

		// 3. Handle Git Diff filtering
		targets := args
		if diff {
			if !git.IsGitRepo() {
				fmt.Fprintln(os.Stderr, "Error: --diff can only be used inside a git repository")
				os.Exit(1)
			}

			changedFiles, err := git.GetChangedFiles(baseRef)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error getting changed files from git: %v\n", err)
				os.Exit(1)
			}

			if len(args) > 0 {
				// Filter changed files to only include those that match the provided args/paths
				var filtered []string
				for _, cf := range changedFiles {
					for _, arg := range args {
						if strings.HasPrefix(cf, arg) || arg == "." {
							filtered = append(filtered, cf)
							break
						}
					}
				}
				targets = filtered
			} else {
				// No paths provided, scan all changed files
				targets = changedFiles
			}

			if len(targets) == 0 {
				if !jsonOutput && !sarifOutput {
					fmt.Fprintln(os.Stderr, "No changed files found to scan.")
				}
				return
			}
		} else if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "Error: No scan targets provided. Provide a URI or use --diff")
			os.Exit(1)
		}

		var allResults []scanner.Result

		for _, uri := range targets {
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
				fmt.Fprintf(os.Stderr, "Warning: Unsupported URI format '%s'. Skipping...\n", uri)
				continue
			}

			engine := scanner.NewEngine(s, detectors.GlobalConfig.Limit)
			engine.Random = detectors.GlobalConfig.Random
			if !jsonOutput && !sarifOutput {
				engine.Progress = &ui.ProgressBar{}
			}

			if !jsonOutput && !sarifOutput {
				fmt.Printf("🐶 Sniffing %s...\n", uri)
			} else {
				// Print to stderr so it doesn't corrupt stdout redirection
				fmt.Fprintf(os.Stderr, "🐶 Sniffing %s...\n", uri)
			}

			results, err := engine.Run(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", uri, err)
				continue
			}
			allResults = append(allResults, results...)
		}

		if sarifOutput {
			ui.PrintSARIFReport(allResults)
		} else if jsonOutput {
			ui.PrintJSONReport(allResults)
		} else {
			ui.PrintReport(allResults)
		}

		// Handle file output if requested
		if outputPath != "" {
			f, err := os.Create(outputPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()

			// Create a temporary stdout capture
			oldStdout := os.Stdout
			os.Stdout = f

			if sarifOutput {
				ui.PrintSARIFReport(allResults)
			} else if jsonOutput {
				ui.PrintJSONReport(allResults)
			} else {
				// We don't want colors in file output for text
				ui.PrintReport(allResults)
			}

			os.Stdout = oldStdout
			fmt.Fprintf(os.Stderr, "🐶 Report saved to %s\n", outputPath)
		}

		if detectors.GlobalConfig.FailOnPii && len(allResults) > 0 {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().IntVarP(&limit, "limit", "l", 1000, "Maximum number of rows to sample per table/file")
	scanCmd.Flags().BoolVar(&failOnPii, "fail-on-pii", false, "Exit with code 1 if any PII is detected")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results in JSON format")
	scanCmd.Flags().BoolVar(&sarifOutput, "sarif", false, "Output results in SARIF format for GitHub Security")
	scanCmd.Flags().BoolVar(&random, "random", false, "Sample rows randomly instead of the first N rows")
	scanCmd.Flags().BoolVar(&diff, "diff", false, "Only scan files that have changed in git")
	scanCmd.Flags().StringVar(&baseRef, "base", "", "Base git ref to compare against (used with --diff)")
	scanCmd.Flags().StringVar(&configPath, "config", "", "Path to a YAML configuration file")
	scanCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write report to a file")
	scanCmd.Flags().StringVar(&configPath, "rules", "", "Path to a YAML configuration file (alias for --config)")
	scanCmd.Flags().MarkHidden("rules")
}
