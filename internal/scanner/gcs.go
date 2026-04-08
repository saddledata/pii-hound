package scanner

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

type GCSScanner struct {
	uri string
}

func NewGCSScanner(uri string) *GCSScanner {
	return &GCSScanner{uri: uri}
}

func (s *GCSScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result) error {
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

		for {
			attrs, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to list gcs objects: %w", err)
			}

			key := attrs.Name
			// Simple suffix check for MVP
			if strings.HasSuffix(key, ".csv") || strings.HasSuffix(key, ".json") || strings.HasSuffix(key, ".jsonl") {
				if err := s.scanObject(ctx, bucket, key, limit, random, results); err != nil {
					fmt.Printf("Error scanning gs://%s/%s: %v\n", bucketName, key, err)
				}
			}
		}
	} else {
		// Single object
		return s.scanObject(ctx, bucket, path, limit, random, results)
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
	}

	return nil
}
