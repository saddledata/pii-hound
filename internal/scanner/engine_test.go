package scanner

import (
	"context"
	"testing"

	"github.com/saddledata/pii-hound/internal/detectors"
)

// MockScanner for testing
type MockScanner struct {
	Results []Result
}

func (m *MockScanner) Scan(ctx context.Context, limit int, random bool, results chan<- Result) error {
	for _, r := range m.Results {
		results <- r
	}
	return nil
}

func TestEngine_Run(t *testing.T) {
	mock := &MockScanner{
		Results: []Result{
			{Source: "table1", Column: "col1", Match: detectors.MatchResult{Type: detectors.TypeEmail, Risk: detectors.HighRisk}},
			{Source: "table1", Column: "col1", Match: detectors.MatchResult{Type: detectors.TypeEmail, Risk: detectors.HighRisk}}, // Duplicate
			{Source: "table1", Column: "col2", Match: detectors.MatchResult{Type: detectors.TypeSSN, Risk: detectors.HighRisk}},
			{Source: "table2", Column: "col1", Match: detectors.MatchResult{Type: detectors.TypeIP, Risk: detectors.MediumRisk}},
		},
	}

	engine := NewEngine(mock, 10)
	results, err := engine.Run(context.Background())

	if err != nil {
		t.Fatalf("Engine.Run() error = %v", err)
	}

	// Should have 3 unique results
	if len(results) != 3 {
		t.Errorf("Engine.Run() returned %d results, want 3", len(results))
	}

	// Verify deduplication
	seen := make(map[string]bool)
	for _, r := range results {
		key := r.Source + r.Column
		if seen[key] {
			t.Errorf("Duplicate result found: %s.%s", r.Source, r.Column)
		}
		seen[key] = true
	}
}

func TestAnalyzeString(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		column   string
		data     string
		wantType detectors.PiiType
	}{
		{
			name:     "Match by heuristic",
			source:   "table",
			column:   "email",
			data:     "not an email",
			wantType: detectors.TypeEmail,
		},
		{
			name:     "Match by data",
			source:   "table",
			column:   "some_col",
			data:     "test@example.com",
			wantType: detectors.TypeEmail,
		},
		{
			name:     "No match",
			source:   "table",
			column:   "id",
			data:     "12345",
			wantType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AnalyzeString(tt.source, tt.column, tt.data)
			if tt.wantType == "" {
				if got != nil {
					t.Errorf("AnalyzeString() = %v, want nil", got.Match.Type)
				}
				return
			}
			if got == nil || got.Match.Type != tt.wantType {
				t.Errorf("AnalyzeString() = %v, want %v", got, tt.wantType)
			}
		})
	}
}
