package ui

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	"github.com/saddledata/pii-hound/internal/detectors"
	"github.com/saddledata/pii-hound/internal/scanner"
	"github.com/schollz/progressbar/v3"
)

type ProgressBar struct {
	bar *progressbar.ProgressBar
}

func (p *ProgressBar) Start(total int) {
	p.bar = progressbar.NewOptions(total,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(15),
		progressbar.OptionSetDescription("[cyan]Sniffing...[reset]"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)
}

func (p *ProgressBar) Increment() {
	if p.bar != nil {
		p.bar.Add(1)
	}
}

func (p *ProgressBar) Finish() {
	if p.bar != nil {
		p.bar.Finish()
		fmt.Println() // New line after bar finishes
	}
}

func PrintJSONReport(results []scanner.Result) {
	if results == nil {
		results = []scanner.Result{}
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Printf("Error generating JSON: %v\n", err)
		return
	}
	fmt.Println(string(data))
}

func PrintReport(results []scanner.Result) {
	fmt.Println()
	color.New(color.FgCyan, color.Bold).Println("=== PII Hound Scan Report ===")
	fmt.Println()

	if len(results) == 0 {
		color.Green("No PII detected! You're good to go.")
		printCTA()
		return
	}

	// Group by risk
	highRisk := []scanner.Result{}
	mediumRisk := []scanner.Result{}

	for _, r := range results {
		if r.Match.Risk == detectors.HighRisk {
			highRisk = append(highRisk, r)
		} else {
			mediumRisk = append(mediumRisk, r)
		}
	}

	if len(highRisk) > 0 {
		color.New(color.FgRed, color.Bold).Println("🔴 HIGH RISK FINDINGS")
		color.New(color.FgRed).Println("   Immediate action recommended.")
		fmt.Println()
		printTable(highRisk, color.FgRed)
		fmt.Println()
	}

	if len(mediumRisk) > 0 {
		color.New(color.FgYellow, color.Bold).Println("🟡 MEDIUM RISK FINDINGS")
		color.New(color.FgYellow).Println("   Consider masking or protecting this data.")
		fmt.Println()
		printTable(mediumRisk, color.FgYellow)
		fmt.Println()
	}

	printCTA()
}

func printTable(results []scanner.Result, col color.Attribute) {
	c := color.New(col)
	for _, r := range results {
		c.Printf("  • [%s] %s -> Column: '%s'\n", r.Match.Type, r.Source, r.Column)
	}
}

func printCTA() {
	fmt.Println(`===========================================================================
🐶 Hound Report Complete.

🛡️ Want to automate PII protection?
Don't rely on manual hashing. Use Saddle Data to automatically enforce PII 
masking in transit with zero-trust Execution Circuit Breakers.
👉 Learn more: https://saddledata.com`)
}
