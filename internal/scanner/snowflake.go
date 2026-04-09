package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"github.com/saddledata/pii-hound/internal/detectors"
	_ "github.com/snowflakedb/gosnowflake"
)

type SnowflakeScanner struct {
	dsn string
}

func NewSnowflakeScanner(dsn string) *SnowflakeScanner {
	return &SnowflakeScanner{dsn: dsn}
}

func (s *SnowflakeScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error {
	db, err := sql.Open("snowflake", s.dsn)
	if err != nil {
		return fmt.Errorf("failed to open snowflake connection: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping snowflake: %w", err)
	}

	tables, err := getSnowflakeTables(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to get snowflake tables: %w", err)
	}

	if progress != nil {
		progress.Start(len(tables))
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5)

	for _, table := range tables {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(tableName string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			s.scanTable(ctx, db, tableName, limit, random, results)
			if progress != nil {
				progress.Increment()
			}
		}(table)
	}

	wg.Wait()
	return nil
}

func (s *SnowflakeScanner) scanTable(ctx context.Context, db *sql.DB, tableName string, limit int, random bool, results chan<- Result) {
	columns, err := getSnowflakeColumns(ctx, db, tableName)
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

	query := fmt.Sprintf("SELECT * FROM %s LIMIT %d", tableName, limit)
	if random {
		// Snowflake uses SAMPLE or ORDER BY RANDOM()
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

	values := make([]sql.NullString, len(colNames))
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
			if heuristicFound[colName] {
				continue
			}

			if !col.Valid {
				continue
			}

			if match := detectors.EvaluateData(tableName, colName, col.String); match != nil {
				heuristicFound[colName] = true
				results <- Result{
					Source: tableName,
					Column: colName,
					Match:  *match,
				}
			}
		}
	}
}

func getSnowflakeTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SHOW TABLES")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		// SHOW TABLES output is complex, but we mainly need the name
		// For simplicity, let's use INFORMATION_SCHEMA if SHOW TABLES is too varied
		// Actually, let's try a simpler approach
	}

	// Fallback to Information Schema for more stability
	rows, err = db.QueryContext(ctx, "SELECT table_name FROM information_schema.tables WHERE table_schema != 'INFORMATION_SCHEMA'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}

	return tables, nil
}

func getSnowflakeColumns(ctx context.Context, db *sql.DB, tableName string) ([]string, error) {
	query := fmt.Sprintf("SELECT column_name FROM information_schema.columns WHERE table_name = '%s'", tableName)
	rows, err := db.QueryContext(ctx, query)
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
