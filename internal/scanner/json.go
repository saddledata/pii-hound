package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/saddledata/pii-hound/internal/detectors"
)

type JSONScanner struct {
	path string
}

func NewJSONScanner(path string) *JSONScanner {
	return &JSONScanner{path: path}
}

func (s *JSONScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error {
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

	return ScanJSONInternal(decoder, isArray, sourceName, limit, random, results)
}

func ScanJSONInternal(decoder *json.Decoder, isArray bool, sourceName string, limit int, random bool, results chan<- Result) error {
	heuristicFound := make(map[string]bool)

	if random {
		return scanJSONRandom(decoder, isArray, sourceName, limit, heuristicFound, results)
	}

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
			continue
		}

		processJSONRecord(obj, sourceName, heuristicFound, results)
		rowCount++
	}

	return nil
}

func scanJSONRandom(decoder *json.Decoder, isArray bool, sourceName string, limit int, heuristicFound map[string]bool, results chan<- Result) error {
	reservoir := make([]map[string]interface{}, 0, limit)
	count := 0
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		if isArray && !decoder.More() {
			break
		}

		var obj map[string]interface{}
		err := decoder.Decode(&obj)
		if err == io.EOF {
			break
		}
		if err != nil {
			continue // Skip malformed objects
		}

		count++
		if len(reservoir) < limit {
			reservoir = append(reservoir, obj)
		} else {
			j := rng.Intn(count)
			if j < limit {
				reservoir[j] = obj
			}
		}
	}

	// Process the random sample
	for _, obj := range reservoir {
		processJSONRecord(obj, sourceName, heuristicFound, results)
	}

	return nil
}

func processJSONRecord(obj map[string]interface{}, sourceName string, heuristicFound map[string]bool, results chan<- Result) {
	for key, val := range obj {
		if !heuristicFound[key] {
			if match := detectors.EvaluateColumnHeuristics(sourceName, key); match != nil {
				heuristicFound[key] = true
				results <- Result{
					Source: sourceName,
					Column: key,
					Match:  *match,
				}
				continue
			}
		}

		if !heuristicFound[key] {
			strVal := fmt.Sprintf("%v", val)
			if strVal == "" || strVal == "<nil>" {
				continue
			}

			if match := detectors.EvaluateData(sourceName, key, strVal); match != nil {
				heuristicFound[key] = true
				results <- Result{
					Source: sourceName,
					Column: key,
					Match:  *match,
				}
			}
		}
	}
}
