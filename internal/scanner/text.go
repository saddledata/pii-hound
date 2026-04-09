package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/saddledata/pii-hound/internal/detectors"
)

type TextScanner struct {
	path string
}

func NewTextScanner(path string) *TextScanner {
	return &TextScanner{path: path}
}

func (s *TextScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error {
	matches, err := filepath.Glob(s.path)
	if err != nil {
		return fmt.Errorf("invalid path pattern: %w", err)
	}

	if progress != nil {
		progress.Start(len(matches))
	}

	for _, match := range matches {
		// 1. Check filename heuristic first
		if m := detectors.EvaluateColumnHeuristics(match, filepath.Base(match)); m != nil && m.Type == detectors.TypeFile {
			results <- Result{
				Source: match,
				Column: "filename",
				Match:  *m,
			}
		}

		// 2. Look inside the file
		f, err := os.Open(match)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file %s: %v\n", match, err)
			continue
		}
		if err := ScanTextStream(f, match, limit, random, results); err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning text file %s: %v\n", match, err)
		}
		f.Close()

		if progress != nil {
			progress.Increment()
		}
	}
	return nil
}

func ScanTextStream(r io.Reader, sourceName string, limit int, random bool, results chan<- Result) error {
	scanner := bufio.NewScanner(r)
	
	// Track findings to avoid duplicate column results for the same file
	foundTypes := make(map[detectors.PiiType]bool)

	if random {
		return scanTextRandom(scanner, sourceName, limit, foundTypes, results)
	}

	rowCount := 0
	for scanner.Scan() {
		if rowCount >= limit {
			break
		}
		line := scanner.Text()
		if processTextLine(line, sourceName, foundTypes, results) {
			// found something
		}
		rowCount++
	}

	return scanner.Err()
}

func scanTextRandom(scanner *bufio.Scanner, sourceName string, limit int, foundTypes map[detectors.PiiType]bool, results chan<- Result) error {
	reservoir := make([]string, 0, limit)
	count := 0
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for scanner.Scan() {
		line := scanner.Text()
		count++
		if len(reservoir) < limit {
			reservoir = append(reservoir, line)
		} else {
			j := rng.Intn(count)
			if j < limit {
				reservoir[j] = line
			}
		}
	}

	for _, line := range reservoir {
		processTextLine(line, sourceName, foundTypes, results)
	}

	return scanner.Err()
}

func processTextLine(line, sourceName string, foundTypes map[detectors.PiiType]bool, results chan<- Result) bool {
	// We pass the line as "data" and use a generic "content" column
	// EvaluateData already checks keywords, custom regex, and built-ins
	if match := detectors.EvaluateData(sourceName, "content", line); match != nil {
		// Only report each PII type once per text file to avoid noise
		if !foundTypes[match.Type] {
			results <- Result{
				Source: sourceName,
				Column: "content",
				Match:  *match,
			}
			foundTypes[match.Type] = true
			return true
		}
	}
	return false
}
