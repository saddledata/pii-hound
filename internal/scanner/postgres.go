package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/lib/pq"
	"github.com/saddledata/pii-hound/internal/detectors"
)

type PostgresScanner struct {
	dsn string
}

func NewPostgresScanner(dsn string) *PostgresScanner {
	return &PostgresScanner{dsn: dsn}
}

func (s *PostgresScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error {
	db, err := sql.Open("postgres", s.dsn)
	if err != nil {
		return fmt.Errorf("failed to open postgres connection: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	tables, err := getTables(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to get tables: %w", err)
	}

	if progress != nil {
		progress.Start(len(tables))
	}

	var wg sync.WaitGroup
	// Limit concurrency to not overwhelm database
	semaphore := make(chan struct{}, 5)

	for _, table := range tables {
		wg.Add(1)
		semaphore <- struct{}{} // acquire
		go func(tableName string) {
			defer wg.Done()
			defer func() { <-semaphore }() // release
			s.scanTable(ctx, db, tableName, limit, random, results)
			if progress != nil {
				progress.Increment()
			}
		}(table)
	}

	wg.Wait()
	return nil
}

func (s *PostgresScanner) scanTable(ctx context.Context, db *sql.DB, tableName string, limit int, random bool, results chan<- Result) {
	// First check heuristics for column names without reading data
	columns, err := getColumns(ctx, db, tableName)
	if err != nil {
		return
	}

	heuristicFound := make(map[string]bool)
	for _, col := range columns {
		if match := detectors.EvaluateColumnHeuristics(tableName, col); match != nil {
			heuristicFound[col] = true
			results <- Result{
				Source: tableName,
				Column: col,
				Match:  *match,
			}
		}
	}

	// We only need to scan columns that didn't already trigger a heuristic
	// and are text-based or might contain PII.
	query := fmt.Sprintf("SELECT * FROM %s LIMIT %d", tableName, limit)
	if random {
		query = fmt.Sprintf("SELECT * FROM %s ORDER BY RANDOM() LIMIT %d", tableName, limit)
	}
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return
	}
	defer rows.Close()

	colNames, err := rows.Columns()
	if err != nil {
		return
	}

	// Prepare data structure to read into
	values := make([]sql.RawBytes, len(colNames))
	scanArgs := make([]interface{}, len(values))
	for i := range values {
		scanArgs[i] = &values[i]
	}

	for rows.Next() {
		if err := rows.Scan(scanArgs...); err != nil {
			continue
		}

		for i, col := range values {
			colName := colNames[i]
			// Skip if already flagged via heuristic
			if heuristicFound[colName] {
				continue
			}

			if col == nil {
				continue
			}

			data := string(col)
			if match := detectors.EvaluateData(tableName, colName, data); match != nil {
				heuristicFound[colName] = true // treat as found to skip subsequent rows for this column
				results <- Result{
					Source: tableName,
					Column: colName,
					Match:  *match,
				}
			}
		}
	}
}

func getTables(ctx context.Context, db *sql.DB) ([]string, error) {
	query := `SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema'`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}
	return tables, nil
}

func getColumns(ctx context.Context, db *sql.DB, tableName string) ([]string, error) {
	query := `SELECT column_name FROM information_schema.columns WHERE table_name = $1`
	rows, err := db.QueryContext(ctx, query, tableName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			return nil, err
		}
		columns = append(columns, column)
	}
	return columns, nil
}
