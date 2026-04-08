package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/go-sql-driver/mysql"
	"github.com/saddledata/pii-hound/internal/detectors"
)

type MySQLScanner struct {
	dsn string
}

func NewMySQLScanner(dsn string) *MySQLScanner {
	return &MySQLScanner{dsn: dsn}
}

func (s *MySQLScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result) error {
	db, err := sql.Open("mysql", s.dsn)
	if err != nil {
		return fmt.Errorf("failed to open mysql connection: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	tables, err := getMySQLTables(ctx, db)
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

func (s *MySQLScanner) scanTable(ctx context.Context, db *sql.DB, tableName string, limit int, random bool, results chan<- Result) {
	columns, err := getMySQLColumns(ctx, db, tableName)
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
		query = fmt.Sprintf("SELECT * FROM `%s` ORDER BY RAND() LIMIT %d", tableName, limit)
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

func getMySQLTables(ctx context.Context, db *sql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SHOW TABLES")
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

func getMySQLColumns(ctx context.Context, db *sql.DB, tableName string) ([]string, error) {
	// Using SHOW COLUMNS because it's simpler for MySQL
	query := fmt.Sprintf("SHOW COLUMNS FROM `%s` ", tableName)
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		// SHOW COLUMNS returns: Field, Type, Null, Key, Default, Extra
		var field, typ, null, key, extra sql.NullString
		var def sql.NullString
		if err := rows.Scan(&field, &typ, &null, &key, &def, &extra); err != nil {
			return nil, err
		}
		if field.Valid {
			columns = append(columns, field.String)
		}
	}
	return columns, nil
}
