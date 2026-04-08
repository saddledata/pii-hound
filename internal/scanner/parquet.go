package scanner

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/parquet-go/parquet-go"
	"github.com/saddledata/pii-hound/internal/detectors"
)

type ParquetScanner struct {
	path string
}

func NewParquetScanner(path string) *ParquetScanner {
	return &ParquetScanner{path: path}
}

func (s *ParquetScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error {
	matches, err := filepath.Glob(s.path)
	if err != nil {
		return fmt.Errorf("invalid path pattern: %w", err)
	}

	if progress != nil {
		progress.Start(len(matches))
	}

	for _, match := range matches {
		if err := s.scanFile(match, limit, random, results); err != nil {
			fmt.Printf("Error scanning parquet file %s: %v\n", match, err)
		}
		if progress != nil {
			progress.Increment()
		}
	}
	return nil
}

func (s *ParquetScanner) scanFile(filename string, limit int, random bool, results chan<- Result) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	pf, err := parquet.OpenFile(f, stat.Size())
	if err != nil {
		return err
	}
	return ScanParquetFile(pf, filepath.Base(filename), limit, random, results)
}

func ScanParquetFile(f *parquet.File, sourceName string, limit int, random bool, results chan<- Result) error {
	schema := f.Schema()
	fields := schema.Fields()

	heuristicFound := make(map[string]bool)
	for _, field := range fields {
		name := field.Name()
		if match := detectors.EvaluateColumnHeuristics(name); match != nil {
			heuristicFound[name] = true
			results <- Result{
				Source: sourceName,
				Column: name,
				Match:  *match,
			}
		}
	}

	if f.NumRows() == 0 {
		return nil
	}

	if random {
		return scanParquetRandom(f, sourceName, limit, heuristicFound, results)
	}

	// Read first N rows
	rowReader := parquet.NewReader(f)
	defer rowReader.Close()

	rowCount := 0
	for rowCount < limit {
		row := make(parquet.Row, len(fields))
		_, err := rowReader.ReadRows([]parquet.Row{row})
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		processParquetRow(row, fields, sourceName, heuristicFound, results)
		rowCount++
	}

	return nil
}

func scanParquetRandom(f *parquet.File, sourceName string, limit int, heuristicFound map[string]bool, results chan<- Result) error {
	fields := f.Schema().Fields()
	rowReader := parquet.NewReader(f)
	defer rowReader.Close()

	reservoir := make([]parquet.Row, 0, limit)
	count := 0
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		row := make(parquet.Row, len(fields))
		_, err := rowReader.ReadRows([]parquet.Row{row})
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		count++
		if len(reservoir) < limit {
			reservoir = append(reservoir, row)
		} else {
			j := rng.Intn(count)
			if j < limit {
				reservoir[j] = row
			}
		}
	}

	for _, row := range reservoir {
		processParquetRow(row, fields, sourceName, heuristicFound, results)
	}

	return nil
}

func processParquetRow(row parquet.Row, fields []parquet.Field, sourceName string, heuristicFound map[string]bool, results chan<- Result) {
	for i, val := range row {
		if i >= len(fields) {
			continue
		}
		field := fields[i]
		name := field.Name()
		if heuristicFound[name] {
			continue
		}

		strVal := val.String()
		if strVal == "" || strVal == "null" {
			continue
		}

		if match := detectors.EvaluateData(strVal); match != nil {
			heuristicFound[name] = true
			results <- Result{
				Source: sourceName,
				Column: name,
				Match:  *match,
			}
		}
	}
}
