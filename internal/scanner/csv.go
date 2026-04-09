package scanner

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/saddledata/pii-hound/internal/detectors"
)

type CSVScanner struct {
	path string
}

func NewCSVScanner(path string) *CSVScanner {
	return &CSVScanner{path: path}
}

func (s *CSVScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error {
	matches, err := filepath.Glob(s.path)
	if err != nil {
		return fmt.Errorf("invalid path pattern: %w", err)
	}

	if progress != nil {
		progress.Start(len(matches))
	}

	for _, match := range matches {
		if err := s.scanFile(match, limit, random, results); err != nil {
			fmt.Printf("Error scanning file %s: %v\n", match, err)
		}
		if progress != nil {
			progress.Increment()
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
		if match := detectors.EvaluateColumnHeuristics(sourceName, header); match != nil {
			heuristicFound[header] = true
			results <- Result{
				Source: sourceName,
				Column: header,
				Match:  *match,
			}
		}
	}

	if random {
		return scanCSVRandom(reader, headers, sourceName, limit, heuristicFound, results)
	}

	// Read first N rows (existing behavior)
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

		if processCSVRecord(record, headers, sourceName, heuristicFound, results) {
			// Optimization: if all columns found, we could break, but simple for now
		}
		rowCount++
	}

	return nil
}

func scanCSVRandom(reader *csv.Reader, headers []string, sourceName string, limit int, heuristicFound map[string]bool, results chan<- Result) error {
	reservoir := make([][]string, 0, limit)
	count := 0
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		count++
		if len(reservoir) < limit {
			reservoir = append(reservoir, record)
		} else {
			j := rng.Intn(count)
			if j < limit {
				reservoir[j] = record
			}
		}
	}

	// Process the random sample
	for _, record := range reservoir {
		processCSVRecord(record, headers, sourceName, heuristicFound, results)
	}

	return nil
}

func processCSVRecord(record []string, headers []string, sourceName string, heuristicFound map[string]bool, results chan<- Result) bool {
	foundAny := false
	for i, value := range record {
		if i >= len(headers) {
			continue
		}
		header := headers[i]
		if heuristicFound[header] {
			continue
		}
		if value == "" {
			continue
		}

		if match := detectors.EvaluateData(sourceName, header, value); match != nil {
			heuristicFound[header] = true
			results <- Result{
				Source: sourceName,
				Column: header,
				Match:  *match,
			}
			foundAny = true
		}
	}
	return foundAny
}
