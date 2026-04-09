package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/parquet-go/parquet-go"
	"google.golang.org/api/iterator"
)

type GCSScanner struct {
	uri string
}

func NewGCSScanner(uri string) *GCSScanner {
	return &GCSScanner{uri: uri}
}

func (s *GCSScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error {
	// Parse gs://bucket/key
	u := strings.TrimPrefix(s.uri, "gs://")
	parts := strings.SplitN(u, "/", 2)
	if len(parts) < 1 {
		return fmt.Errorf("invalid gcs uri: %s", s.uri)
	}
	bucketName := parts[0]
	path := ""
	if len(parts) > 1 {
		path = parts[1]
	}

	client, err := storage.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create gcs client: %w", err)
	}
	defer client.Close()

	bucket := client.Bucket(bucketName)

	// If path contains wildcards, we need to list
	if strings.Contains(path, "*") {
		prefix := strings.Split(path, "*")[0]

		query := &storage.Query{Prefix: prefix}
		it := bucket.Objects(ctx, query)

		var objects []string
		for {
			attrs, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to list gcs objects: %w", err)
			}

			key := attrs.Name
			if strings.HasSuffix(key, ".csv") || strings.HasSuffix(key, ".json") || strings.HasSuffix(key, ".jsonl") ||
				strings.HasSuffix(key, ".xlsx") || strings.HasSuffix(key, ".xlsm") || strings.HasSuffix(key, ".parquet") {
				objects = append(objects, key)
			}
		}

		if progress != nil {
			progress.Start(len(objects))
		}

		for _, key := range objects {
			if err := s.scanObject(ctx, bucket, key, limit, random, results); err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning gs://%s/%s: %v\n", bucketName, key, err)
			}
			if progress != nil {
				progress.Increment()
			}
		}
	} else {
		// Single object
		if progress != nil {
			progress.Start(1)
		}
		err := s.scanObject(ctx, bucket, path, limit, random, results)
		if progress != nil {
			progress.Increment()
		}
		return err
	}

	return nil
}

func (s *GCSScanner) scanObject(ctx context.Context, bucket *storage.BucketHandle, key string, limit int, random bool, results chan<- Result) error {
	obj := bucket.Object(key)
	r, err := obj.NewReader(ctx)
	if err != nil {
		return err
	}
	defer r.Close()

	sourceName := fmt.Sprintf("gs://%s/%s", obj.BucketName(), key)

	if strings.HasSuffix(key, ".csv") {
		return ScanCSVStream(r, sourceName, limit, random, results)
	} else if strings.HasSuffix(key, ".json") || strings.HasSuffix(key, ".jsonl") {
		// Wrap in bufio to peek for array vs lines
		br := bufio.NewReader(r)
		return ScanJSONStreamFromReader(br, sourceName, limit, random, results)
	} else if strings.HasSuffix(key, ".xlsx") || strings.HasSuffix(key, ".xlsm") {
		return ScanExcelStream(r, sourceName, limit, random, results)
	} else if strings.HasSuffix(key, ".parquet") {
		// Parquet needs ReaderAt, so we download to a temp file
		tmpFile, err := os.CreateTemp("", "piihound-*.parquet")
		if err != nil {
			return err
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		if _, err := io.Copy(tmpFile, r); err != nil {
			return err
		}

		stat, _ := tmpFile.Stat()
		pf, err := parquet.OpenFile(tmpFile, stat.Size())
		if err != nil {
			return err
		}
		return ScanParquetFile(pf, sourceName, limit, random, results)
	}

	return nil
}
