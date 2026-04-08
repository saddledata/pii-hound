package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	_ "modernc.org/sqlite"
	"github.com/saddledata/pii-hound/internal/detectors"
)

type SQLiteScanner struct {
	path string
}

func NewSQLiteScanner(path string) *SQLiteScanner {
	return &SQLiteScanner{path: path}
}

func (s *SQLiteScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result) error {
	db, err := sql.Open("sqlite", s.path)
	if err != nil {
		return fmt.Errorf("failed to open sqlite database: %w", err)
	}
	defer db.Close()

	tables, err := getSQLiteTables(ctx, db)
	if err != nil {
		return fmt.Errorf("failed to get tables: %w", err)
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
		}(table)
	}

	wg.Wait()
	return nil
}

func (s *SQLiteScanner) scanTable(ctx context.Context, db *sql.DB, tableName string, limit int, random bool, results chan<- Result) {
	columns, err := getSQLiteColumns(ctx, db, tableName)
	if err != nil {
		return
	}

	heuristicFound := make(map[string]bool)
	for _, col := range columns {
		if match := detectors.EvaluateColumnHeuristics(col); match != nil {
			heuristicFound[col] = true
			results <- Result{
				Source: tableName,
				Column: col,
				Match:  *match,
			}
		}
	}

	query := fmt.Sprintf("SELECT * FROM `%s` LIMIT %d", tableName, limit)
	if random {
		query = fmt.Sprintf("SELECT * FROM `%s` ORDER BY RANDOM() LIMIT %d", tableName, limit)
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
			if heuristicFound[colName] {
				continue
			}

			if col == nil {
				continue
			}

			data := string(col)
			if match := detectors.EvaluateData(data); match != nil {
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

func getSQLiteTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SELECT name FROM sqlite_master WHERE type='table'")
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
		// Skip internal sqlite tables
		if table == "sqlite_sequence" || table == "sqlite_stat1" {
			continue
		}
		tables = append(tables, table)
	}
	return tables, nil
}

func getSQLiteColumns(ctx context.Context, db *sql.DB, tableName string) ([]string, error) {
	query := fmt.Sprintf("PRAGMA table_info(`%s`)", tableName)
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		// table_info returns: cid, name, type, notnull, dflt_value, pk
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt_value interface{}
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt_value, &pk); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, nil
}
