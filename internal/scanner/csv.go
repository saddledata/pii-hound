package scanner

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/saddledata/pii-hound/internal/detectors"
)

type CSVScanner struct {
	path string
}

func NewCSVScanner(path string) *CSVScanner {
	return &CSVScanner{path: path}
}

func (s *CSVScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result) error {
	matches, err := filepath.Glob(s.path)
	if err != nil {
		return fmt.Errorf("invalid path pattern: %w", err)
	}

	for _, match := range matches {
		if err := s.scanFile(match, limit, random, results); err != nil {
			fmt.Printf("Error scanning file %s: %v\n", match, err)
		}
	}
	return nil
}

func (s *CSVScanner) scanFile(filename string, limit int, random bool, results chan<- Result) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return ScanCSVStream(f, filepath.Base(filename), limit, random, results)
}

func ScanCSVStream(r io.Reader, sourceName string, limit int, random bool, results chan<- Result) error {
	reader := csv.NewReader(r)

	// Read headers
	headers, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}

	heuristicFound := make(map[string]bool)
	for _, header := range headers {
		if match := detectors.EvaluateColumnHeuristics(header); match != nil {
			heuristicFound[header] = true
			results <- Result{
				Source: sourceName,
				Column: header,
				Match:  *match,
			}
		}
	}

	// Read rows
	rowCount := 0
	for {
		if rowCount >= limit {
			break
		}

		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		for i, value := range record {
			if i >= len(headers) {
				continue // Skip if row is longer than headers
			}
			header := headers[i]

			// Skip if already found
			if heuristicFound[header] {
				continue
			}

			if value == "" {
				continue
			}

			if match := detectors.EvaluateData(value); match != nil {
				heuristicFound[header] = true
				results <- Result{
					Source: sourceName,
					Column: header,
					Match:  *match,
				}
			}
		}
		rowCount++
	}

	return nil
}
