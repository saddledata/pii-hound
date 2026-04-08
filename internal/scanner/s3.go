package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/parquet-go/parquet-go"
)

type S3Scanner struct {
	uri string
}

func NewS3Scanner(uri string) *S3Scanner {
	return &S3Scanner{uri: uri}
}

func (s *S3Scanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result, progress ProgressReporter) error {
	// Parse s3://bucket/key
	u := strings.TrimPrefix(s.uri, "s3://")
	parts := strings.SplitN(u, "/", 2)
	if len(parts) < 1 {
		return fmt.Errorf("invalid s3 uri: %s", s.uri)
	}
	bucket := parts[0]
	path := ""
	if len(parts) > 1 {
		path = parts[1]
	}

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("unable to load SDK config: %w", err)
	}

	client := s3.NewFromConfig(cfg)

	// If path contains wildcards, we need to list
	if strings.Contains(path, "*") {
		// Get prefix before wildcard
		prefix := strings.Split(path, "*")[0]
		
		// Count first for progress bar
		var objects []string
		paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
			Bucket: aws.String(bucket),
			Prefix: aws.String(prefix),
		})

		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return fmt.Errorf("failed to list s3 objects: %w", err)
			}

			for _, obj := range page.Contents {
				key := *obj.Key
				if strings.HasSuffix(key, ".csv") || strings.HasSuffix(key, ".json") || strings.HasSuffix(key, ".jsonl") ||
					strings.HasSuffix(key, ".xlsx") || strings.HasSuffix(key, ".xlsm") || strings.HasSuffix(key, ".parquet") {
					objects = append(objects, key)
				}
			}
		}

		if progress != nil {
			progress.Start(len(objects))
		}

		for _, key := range objects {
			if err := s.scanObject(ctx, client, bucket, key, limit, random, results); err != nil {
				fmt.Printf("Error scanning s3://%s/%s: %v\n", bucket, key, err)
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
		err := s.scanObject(ctx, client, bucket, path, limit, random, results)
		if progress != nil {
			progress.Increment()
		}
		return err
	}

	return nil
}

func (s *S3Scanner) scanObject(ctx context.Context, client *s3.Client, bucket, key string, limit int, random bool, results chan<- Result) error {
	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	sourceName := fmt.Sprintf("s3://%s/%s", bucket, key)

	if strings.HasSuffix(key, ".csv") {
		return ScanCSVStream(resp.Body, sourceName, limit, random, results)
	} else if strings.HasSuffix(key, ".json") || strings.HasSuffix(key, ".jsonl") {
		// Wrap in bufio to peek for array vs lines
		br := bufio.NewReader(resp.Body)
		return ScanJSONStreamFromReader(br, sourceName, limit, random, results)
	} else if strings.HasSuffix(key, ".xlsx") || strings.HasSuffix(key, ".xlsm") {
		return ScanExcelStream(resp.Body, sourceName, limit, random, results)
	} else if strings.HasSuffix(key, ".parquet") {
		// Parquet needs ReaderAt, so we download to a temp file
		tmpFile, err := os.CreateTemp("", "piihound-*.parquet")
		if err != nil {
			return err
		}
		defer os.Remove(tmpFile.Name())
		defer tmpFile.Close()

		if _, err := io.Copy(tmpFile, resp.Body); err != nil {
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

// Updated ScanJSONStream to not require Seek
func ScanJSONStreamFromReader(r *bufio.Reader, sourceName string, limit int, random bool, results chan<- Result) error {
	// Peek to see if it starts with [
	peek, _ := r.Peek(1)
	isArray := false
	if len(peek) > 0 && peek[0] == '[' {
		isArray = true
	}

	decoder := json.NewDecoder(r)
	if isArray {
		// Consume the '[' token
		if _, err := decoder.Token(); err != nil {
			return err
		}
	}

	return ScanJSONInternal(decoder, isArray, sourceName, limit, random, results)
}
