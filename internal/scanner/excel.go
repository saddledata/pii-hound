package scanner

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/saddledata/pii-hound/internal/detectors"
	"github.com/xuri/excelize/v2"
)

type ExcelScanner struct {
	path string
}

func NewExcelScanner(path string) *ExcelScanner {
	return &ExcelScanner{path: path}
}

func (s *ExcelScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error {
	matches, err := filepath.Glob(s.path)
	if err != nil {
		return fmt.Errorf("invalid path pattern: %w", err)
	}

	if progress != nil {
		progress.Start(len(matches))
	}

	for _, match := range matches {
		f, err := os.Open(match)
		if err != nil {
			fmt.Printf("Error opening file %s: %v\n", match, err)
			continue
		}
		if err := ScanExcelStream(f, filepath.Base(match), limit, random, results); err != nil {
			fmt.Printf("Error scanning excel file %s: %v\n", match, err)
		}
		f.Close()
		if progress != nil {
			progress.Increment()
		}
	}
	return nil
}

func ScanExcelStream(r io.Reader, sourceName string, limit int, random bool, results chan<- Result) error {
	f, err := excelize.OpenReader(r)
	if err != nil {
		return err
	}
	defer f.Close()

	// Scan all sheets
	sheets := f.GetSheetList()
	for _, sheet := range sheets {
		rows, err := f.GetRows(sheet)
		if err != nil {
			continue
		}

		if len(rows) == 0 {
			continue
		}

		headers := rows[0]
		sheetSource := fmt.Sprintf("%s [%s]", sourceName, sheet)

		heuristicFound := make(map[string]bool)
		for _, header := range headers {
			if match := detectors.EvaluateColumnHeuristics(header); match != nil {
				heuristicFound[header] = true
				results <- Result{
					Source: sheetSource,
					Column: header,
					Match:  *match,
				}
			}
		}

		dataRows := rows[1:]
		if len(dataRows) == 0 {
			continue
		}

		var sample [][]string
		if random {
			sample = reservoirSampleStrings(dataRows, limit)
		} else {
			end := limit
			if end > len(dataRows) {
				end = len(dataRows)
			}
			sample = dataRows[:end]
		}

		for _, row := range sample {
			for i, val := range row {
				if i >= len(headers) {
					continue
				}
				header := headers[i]
				if heuristicFound[header] {
					continue
				}
				if val == "" {
					continue
				}

				if match := detectors.EvaluateData(val); match != nil {
					heuristicFound[header] = true
					results <- Result{
						Source: sheetSource,
						Column: header,
						Match:  *match,
					}
				}
			}
		}
	}

	return nil
}

func reservoirSampleStrings(input [][]string, limit int) [][]string {
	if len(input) <= limit {
		return input
	}
	reservoir := make([][]string, limit)
	copy(reservoir, input[:limit])

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := limit; i < len(input); i++ {
		j := rng.Intn(i + 1)
		if j < limit {
			reservoir[j] = input[i]
		}
	}
	return reservoir
}
