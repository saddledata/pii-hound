package detectors

import (
	"regexp"
)

type RiskLevel string

const (
	HighRisk   RiskLevel = "HIGH"
	MediumRisk RiskLevel = "MEDIUM"
)

type PiiType string

const (
	TypeSSN   PiiType = "Social Security Number"
	TypeCC    PiiType = "Credit Card"
	TypeEmail PiiType = "Email Address"
	TypePhone PiiType = "Phone Number"
	TypeIP    PiiType = "IP Address"
	TypeSecret PiiType = "Secret/Token"
)

// MatchResult stores information about a matched PII
type MatchResult struct {
	Type PiiType
	Risk RiskLevel
}

var (
	// Regex Patterns
	emailRegex = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	ssnRegex   = regexp.MustCompile(`(?i)\b(?:(?:\d{3}-\d{2}-\d{4})|(?:\d{9}))\b`)
	phoneRegex = regexp.MustCompile(`(?i)\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b`)
	ipRegex    = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	// Basic format for Credit Cards (digits, spaces, dashes)
	ccRegex = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)

	// Secret/Token Patterns
	awsKeyRegex      = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	githubTokenRegex = regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b`)
	privateKeyRegex  = regexp.MustCompile(`(?s)-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`)

	// Heuristics for column names - match whole 'words' separated by boundaries or underscores
	ssnHeuristic    = regexp.MustCompile(`(?i)(\b|_)(ssn|social.*security)(\b|_)`)
	ccHeuristic     = regexp.MustCompile(`(?i)(\b|_)(credit.*card|card.*num|ccnum|creditcard)(\b|_)`)
	emailHeuristic  = regexp.MustCompile(`(?i)(\b|_)(email)(\b|_)`)
	phoneHeuristic  = regexp.MustCompile(`(?i)(\b|_)(phone|mobile|cell)(\b|_)`)
	ipHeuristic     = regexp.MustCompile(`(?i)(\b|_)(ip.*addr|ip)(\b|_)`)
	secretHeuristic = regexp.MustCompile(`(?i)(\b|_)(secret|token|api.*key|apikey|passwd|password|credential)(\b|_)`)
)

// EvaluateColumnHeuristics checks if a column name suggests it contains PII
func EvaluateColumnHeuristics(columnName string) *MatchResult {
	if ssnHeuristic.MatchString(columnName) {
		return &MatchResult{Type: TypeSSN, Risk: HighRisk}
	}
	if ccHeuristic.MatchString(columnName) {
		return &MatchResult{Type: TypeCC, Risk: HighRisk}
	}
	if emailHeuristic.MatchString(columnName) {
		return &MatchResult{Type: TypeEmail, Risk: HighRisk}
	}
	if phoneHeuristic.MatchString(columnName) {
		return &MatchResult{Type: TypePhone, Risk: MediumRisk}
	}
	if ipHeuristic.MatchString(columnName) {
		return &MatchResult{Type: TypeIP, Risk: MediumRisk}
	}
	if secretHeuristic.MatchString(columnName) {
		return &MatchResult{Type: TypeSecret, Risk: HighRisk}
	}
	return nil
}

// EvaluateData checks if the data string matches any PII patterns
func EvaluateData(data string) *MatchResult {
	// High Risk - PII
	if ssnRegex.MatchString(data) {
		return &MatchResult{Type: TypeSSN, Risk: HighRisk}
	}
	if ccRegex.MatchString(data) {
		// Only return CC if it passes Luhn
		if passesLuhn(data) {
			return &MatchResult{Type: TypeCC, Risk: HighRisk}
		}
	}
	if emailRegex.MatchString(data) {
		return &MatchResult{Type: TypeEmail, Risk: HighRisk}
	}

	// High Risk - Secrets
	if awsKeyRegex.MatchString(data) {
		return &MatchResult{Type: TypeSecret, Risk: HighRisk}
	}
	if githubTokenRegex.MatchString(data) {
		return &MatchResult{Type: TypeSecret, Risk: HighRisk}
	}
	if privateKeyRegex.MatchString(data) {
		return &MatchResult{Type: TypeSecret, Risk: HighRisk}
	}

	// Medium Risk
	if phoneRegex.MatchString(data) {
		return &MatchResult{Type: TypePhone, Risk: MediumRisk}
	}
	if ipRegex.MatchString(data) {
		return &MatchResult{Type: TypeIP, Risk: MediumRisk}
	}

	return nil
}

// passesLuhn checks if the numeric characters in a string pass the Luhn algorithm
func passesLuhn(data string) bool {
	// Strip non-digit characters (like spaces and dashes)
	var digits []int
	for _, r := range data {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	var sum int
	for i := len(digits) - 1; i >= 0; i-- {
		digit := digits[i]
		// Double every second digit starting from the second to last
		if (len(digits)-1-i)%2 == 1 {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}

	return sum%10 == 0
}
