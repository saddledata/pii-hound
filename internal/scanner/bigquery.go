package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"cloud.google.com/go/bigquery"
	"github.com/saddledata/pii-hound/internal/detectors"
	"google.golang.org/api/iterator"
)

type BigQueryScanner struct {
	uri string
}

func NewBigQueryScanner(uri string) *BigQueryScanner {
	return &BigQueryScanner{uri: uri}
}

func (s *BigQueryScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error {
	// Parse bigquery://project-id/dataset-id
	u := strings.TrimPrefix(s.uri, "bigquery://")
	parts := strings.Split(u, "/")
	if len(parts) != 2 {
		return fmt.Errorf("invalid bigquery uri: %s. Use bigquery://project-id/dataset-id", s.uri)
	}
	projectID := parts[0]
	datasetID := parts[1]

	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to create bigquery client: %w", err)
	}
	defer client.Close()

	dataset := client.Dataset(datasetID)
	
	// Count tables first for progress bar
	it := dataset.Tables(ctx)
	var tables []*bigquery.Table
	for {
		t, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to list bigquery tables: %w", err)
		}
		tables = append(tables, t)
	}

	if progress != nil {
		progress.Start(len(tables))
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5)

	for _, table := range tables {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(t *bigquery.Table) {
			defer wg.Done()
			defer func() { <-semaphore }()
			s.scanTable(ctx, client, t, limit, random, results)
			if progress != nil {
				progress.Increment()
			}
		}(table)
	}

	wg.Wait()
	return nil
}

func (s *BigQueryScanner) scanTable(ctx context.Context, client *bigquery.Client, table *bigquery.Table, limit int, random bool, results chan<- Result) {
	md, err := table.Metadata(ctx)
	if err != nil {
		return
	}

	heuristicFound := make(map[string]bool)
	for _, field := range md.Schema {
		if match := detectors.EvaluateColumnHeuristics(field.Name); match != nil {
			heuristicFound[field.Name] = true
			results <- Result{
				Source: table.TableID,
				Column: field.Name,
				Match:  *match,
			}
		}
	}

	queryString := fmt.Sprintf("SELECT * FROM `%s.%s.%s` LIMIT %d", table.ProjectID, table.DatasetID, table.TableID, limit)
	if random {
		// BigQuery RAND() returns 0-1, we use it in WHERE or ORDER BY
		queryString = fmt.Sprintf("SELECT * FROM `%s.%s.%s` ORDER BY RAND() LIMIT %d", table.ProjectID, table.DatasetID, table.TableID, limit)
	}

	q := client.Query(queryString)
	it, err := q.Read(ctx)
	if err != nil {
		return
	}

	for {
		var row map[string]bigquery.Value
		err := it.Next(&row)
		if err == iterator.Done {
			break
		}
		if err != nil {
			continue
		}

		for colName, val := range row {
			if heuristicFound[colName] {
				continue
			}

			if val == nil {
				continue
			}

			strVal := fmt.Sprintf("%v", val)
			if match := detectors.EvaluateData(strVal); match != nil {
				heuristicFound[colName] = true
				results <- Result{
					Source: table.TableID,
					Column: colName,
					Match:  *match,
				}
			}
		}
	}
}
