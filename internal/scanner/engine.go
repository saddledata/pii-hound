package scanner

import (
	"context"
	"fmt"
	"sync"

	"github.com/saddledata/pii-hound/internal/detectors"
)

// ProgressReporter defines an interface for reporting progress
type ProgressReporter interface {
	Start(total int)
	Increment()
	Finish()
}

// Result represents the finding in a specific column of a table/file
type Result struct {
	Source string                // Table name or file name
	Column string                // Column name
	Match  detectors.MatchResult // The PII match details
}

// Scanner defines the interface for different data source scanners
type Scanner interface {
	Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error
}

// Engine orchestrates the scanning process
type Engine struct {
	Scanner  Scanner
	Limit    int
	Random   bool
	Progress ProgressReporter
}

// NewEngine creates a new scanning engine
func NewEngine(s Scanner, limit int) *Engine {
	return &Engine{
		Scanner: s,
		Limit:   limit,
	}
}

// Run executes the scanner and collects results
func (e *Engine) Run(ctx context.Context) ([]Result, error) {
	resultsChan := make(chan Result, 100)
	var wg sync.WaitGroup
	var results []Result

	// Collect results in a separate goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Deduplicate results by Source + Column
		seen := make(map[string]bool)
		for r := range resultsChan {
			key := fmt.Sprintf("%s|%s", r.Source, r.Column)
			if !seen[key] {
				seen[key] = true
				results = append(results, r)
			}
		}
	}()

	// Run scanner
	err := e.Scanner.Scan(ctx, e.Limit, e.Random, resultsChan, e.Progress)
	close(resultsChan)

	// Wait for results collection to finish
	wg.Wait()

	if e.Progress != nil {
		e.Progress.Finish()
	}

	return results, err
}

// AnalyzeString evaluates a string value for PII.
// It checks column name heuristics first, then evaluates data.
func AnalyzeString(source, column, data string) *Result {
	// First check heuristics based on column name
	if match := detectors.EvaluateColumnHeuristics(column); match != nil {
		return &Result{
			Source: source,
			Column: column,
			Match:  *match,
		}
	}

	// Then evaluate actual data if not empty
	if data == "" {
		return nil
	}

	if match := detectors.EvaluateData(data); match != nil {
		return &Result{
			Source: source,
			Column: column,
			Match:  *match,
		}
	}

	return nil
}
