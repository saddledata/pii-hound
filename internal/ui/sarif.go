package ui

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/saddledata/pii-hound/internal/scanner"
)

// SARIF structures for GitHub Security integration
type sarifReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string          `json:"name"`
	InformationUri string          `json:"informationUri"`
	Rules          []sarifRule     `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	ShortDescription sarifDescription `json:"shortDescription"`
	FullDescription  sarifDescription `json:"fullDescription"`
	HelpUri          string           `json:"helpUri"`
}

type sarifDescription struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	Uri string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func PrintSARIFReport(results []scanner.Result) {
	report := sarifReport{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifRun{}.Tool, // placeholder
			},
		},
	}

	driver := sarifDriver{
		Name:           "pii-hound",
		InformationUri: "https://github.com/saddledata/pii-hound",
	}

	// We create a rule for each PII type found
	ruleMap := make(map[string]bool)
	var sarifResults []sarifResult

	for _, res := range results {
		ruleID := string(res.Match.Type)
		if !ruleMap[ruleID] {
			driver.Rules = append(driver.Rules, sarifRule{
				ID: ruleID,
				ShortDescription: sarifDescription{
					Text: fmt.Sprintf("Unprotected %s detected", res.Match.Type),
				},
				FullDescription: sarifDescription{
					Text: fmt.Sprintf("The column '%s' in source '%s' appears to contain unprotected %s.", res.Column, res.Source, res.Match.Type),
				},
				HelpUri: "https://saddledata.com",
			})
			ruleMap[ruleID] = true
		}

		level := "warning"
		if res.Match.Risk == "HIGH" {
			level = "error"
		}

		sarifResults = append(sarifResults, sarifResult{
			RuleID: ruleID,
			Level:  level,
			Message: sarifMessage{
				Text: fmt.Sprintf("Column '%s' contains %s.", res.Column, res.Match.Type),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							Uri: res.Source,
						},
						Region: sarifRegion{
							StartLine: 1, // We don't have exact line numbers for all sources, default to 1
						},
					},
				},
			},
		})
	}

	report.Runs[0].Tool.Driver = driver
	report.Runs[0].Results = sarifResults

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Printf("Error generating SARIF: %v\n", err)
	}
}
