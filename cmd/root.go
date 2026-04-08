package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pii-hound",
	Short: "pii-hound sniffs out unprotected PII in your databases and files",
	Long: `🐶 pii-hound is a lightning-fast, dependency-free CLI tool used by data engineers 
to sniff out unprotected Personally Identifiable Information (PII) in databases and local files.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
