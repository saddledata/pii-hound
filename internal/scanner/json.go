package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/saddledata/pii-hound/internal/detectors"
)

type JSONScanner struct {
	path string
}

func NewJSONScanner(path string) *JSONScanner {
	return &JSONScanner{path: path}
}

func (s *JSONScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result) error {
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

func (s *JSONScanner) scanFile(filename string, limit int, random bool, results chan<- Result) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return ScanJSONStream(f, filepath.Base(filename), limit, random, results)
}

func ScanJSONStream(r io.ReadSeeker, sourceName string, limit int, random bool, results chan<- Result) error {
	decoder := json.NewDecoder(r)

	// Check if it's an array of objects
	t, err := decoder.Token()
	if err != nil {
		return err
	}

	isArray := false
	if delim, ok := t.(json.Delim); ok && delim == '[' {
		isArray = true
	} else {
		// Reset if it's not an array (e.g., JSON Lines)
		r.Seek(0, io.SeekStart)
		decoder = json.NewDecoder(r)
	}

	return ScanJSONInternal(decoder, isArray, sourceName, limit, results)
}

func ScanJSONInternal(decoder *json.Decoder, isArray bool, sourceName string, limit int, results chan<- Result) error {
	heuristicFound := make(map[string]bool)
	rowCount := 0

	for {
		if rowCount >= limit {
			break
		}

		if isArray && !decoder.More() {
			break
		}

		var obj map[string]interface{}
		err := decoder.Decode(&obj)
		if err != nil {
			if err == io.EOF {
				break
			}
			// Skip invalid objects in array/lines
			continue
		}

		// Evaluate keys first (heuristics) if not already done for that key
		for key, val := range obj {
			if !heuristicFound[key] {
				if match := detectors.EvaluateColumnHeuristics(key); match != nil {
					heuristicFound[key] = true
					results <- Result{
						Source: sourceName,
						Column: key,
						Match:  *match,
					}
					continue
				}
			}

			// If heuristics didn't match, check data
			if !heuristicFound[key] {
				strVal := fmt.Sprintf("%v", val)
				if strVal == "" || strVal == "<nil>" {
					continue
				}

				if match := detectors.EvaluateData(strVal); match != nil {
					heuristicFound[key] = true
					results <- Result{
						Source: sourceName,
						Column: key,
						Match:  *match,
					}
				}
			}
		}

		rowCount++
	}

	return nil
}
