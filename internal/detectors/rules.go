package detectors

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cloudflare/ahocorasick"
	"gopkg.in/yaml.v3"
)

type RiskLevel string

const (
	HighRisk   RiskLevel = "HIGH"
	MediumRisk RiskLevel = "MEDIUM"
)

type PiiType string

const (
	TypeSSN     PiiType = "Social Security Number"
	TypeCC      PiiType = "Credit Card"
	TypeEmail   PiiType = "Email Address"
	TypePhone   PiiType = "Phone Number"
	TypeIP      PiiType = "IP Address"
	TypeSecret  PiiType = "Secret/Token"
	TypeKeyword PiiType = "Sensitive Keyword"
	TypeName    PiiType = "Person Name"
)

// MatchResult stores information about a matched PII
type MatchResult struct {
	Type PiiType
	Risk RiskLevel
}

// CustomRule allows users to define their own detectors via YAML
type CustomRule struct {
	Name      string    `yaml:"name"`
	Type      PiiType   `yaml:"type"`
	Risk      RiskLevel `yaml:"risk"`
	Regex     string    `yaml:"regex"`
	Heuristic string    `yaml:"heuristic"`
	Keywords  []string  `yaml:"keywords"`

	compiledRegex     *regexp.Regexp
	compiledHeuristic *regexp.Regexp
}

// IgnoreEntry defines targets to be ignored during scanning
type IgnoreEntry struct {
	Source string   `yaml:"source"` // File name or table name
	Column string   `yaml:"column"` // Specific column to ignore (optional)
	Type   PiiType  `yaml:"type"`   // Specific PII type to ignore (optional)
}

type Config struct {
	Limit      int           `yaml:"limit"`
	Random     bool          `yaml:"random"`
	FailOnPii  bool          `yaml:"fail_on_pii"`
	Rules      []CustomRule  `yaml:"rules"`
	Ignore     []IgnoreEntry `yaml:"ignore"`
}

var (
	// Global configuration
	GlobalConfig Config

	// Built-in Regex Patterns
	emailRegex = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	ssnRegex   = regexp.MustCompile(`(?i)\b(?:(?:\d{3}-\d{2}-\d{4})|(?:\d{9}))\b`)
	phoneRegex = regexp.MustCompile(`(?i)\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b`)
	ipRegex    = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ccRegex    = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)

	// Built-in Secret/Token Patterns
	awsKeyRegex      = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	githubTokenRegex = regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b`)
	privateKeyRegex  = regexp.MustCompile(`(?s)-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`)

	// Built-in Heuristics
	ssnHeuristic    = regexp.MustCompile(`(?i)(\b|_)(ssn|social.*security)(\b|_)`)
	ccHeuristic     = regexp.MustCompile(`(?i)(\b|_)(credit.*card|card.*num|ccnum|creditcard)(\b|_)`)
	emailHeuristic  = regexp.MustCompile(`(?i)(\b|_)(email)(\b|_)`)
	phoneHeuristic  = regexp.MustCompile(`(?i)(\b|_)(phone|mobile|cell)(\b|_)`)
	ipHeuristic     = regexp.MustCompile(`(?i)(\b|_)(ip.*addr|ip)(\b|_)`)
	secretHeuristic = regexp.MustCompile(`(?i)(\b|_)(secret|token|api.*key|apikey|passwd|password|credential)(\b|_)`)
	nameHeuristic   = regexp.MustCompile(`(?i)(\b|_)(first.*name|last.*name|fullname|cust.*name|customer.*name)(\b|_)`)

	// Aho-Corasick Automaton for high-speed keyword matching
	keywordMatcher *ahocorasick.Matcher
	// Maps keyword index in matcher to its Rule
	keywordMap map[int]*CustomRule
)

// LoadConfig reads configuration from a YAML file
func LoadConfig(path string) error {
	f, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var config Config
	if err := yaml.Unmarshal(f, &config); err != nil {
		return err
	}

	var allKeywords [][]byte
	keywordMap = make(map[int]*CustomRule)

	for i := range config.Rules {
		rule := &config.Rules[i]
		if rule.Regex != "" {
			re, err := regexp.Compile(rule.Regex)
			if err != nil {
				return fmt.Errorf("invalid regex in rule '%s': %w", rule.Name, err)
			}
			rule.compiledRegex = re
		}
		if rule.Heuristic != "" {
			re, err := regexp.Compile(fmt.Sprintf("(?i)(\\b|_)(%s)(\\b|_)", rule.Heuristic))
			if err != nil {
				return fmt.Errorf("invalid heuristic in rule '%s': %w", rule.Name, err)
			}
			rule.compiledHeuristic = re
		}

		if len(rule.Keywords) > 0 {
			for _, kw := range rule.Keywords {
				idx := len(allKeywords)
				allKeywords = append(allKeywords, []byte(strings.ToLower(kw)))
				keywordMap[idx] = rule
			}
		}
	}

	if len(allKeywords) > 0 {
		keywordMatcher = ahocorasick.NewMatcher(allKeywords)
	}

	GlobalConfig = config
	return nil
}

// IsIgnored checks if a specific finding should be ignored
func IsIgnored(source, column string, piiType PiiType) bool {
	for _, entry := range GlobalConfig.Ignore {
		// Match Source (exact or wildcard prefix/suffix simplified for now)
		sourceMatch := entry.Source == "" || entry.Source == "*" || entry.Source == source
		
		// Match Column
		columnMatch := entry.Column == "" || entry.Column == "*" || entry.Column == column
		
		// Match PII Type
		typeMatch := entry.Type == "" || entry.Type == "*" || entry.Type == piiType

		if sourceMatch && columnMatch && typeMatch {
			return true
		}
	}
	return false
}

// EvaluateColumnHeuristics checks if a column name suggests it contains PII
func EvaluateColumnHeuristics(source, columnName string) *MatchResult {
	// Check custom rules first
	for _, rule := range GlobalConfig.Rules {
		if rule.compiledHeuristic != nil && rule.compiledHeuristic.MatchString(columnName) {
			piiType := PiiType(rule.Name)
			if !IsIgnored(source, columnName, piiType) {
				return &MatchResult{Type: piiType, Risk: rule.Risk}
			}
		}
	}

	var match *MatchResult
	// Fallback to built-ins
	if ssnHeuristic.MatchString(columnName) {
		match = &MatchResult{Type: TypeSSN, Risk: HighRisk}
	} else if ccHeuristic.MatchString(columnName) {
		match = &MatchResult{Type: TypeCC, Risk: HighRisk}
	} else if emailHeuristic.MatchString(columnName) {
		match = &MatchResult{Type: TypeEmail, Risk: HighRisk}
	} else if phoneHeuristic.MatchString(columnName) {
		match = &MatchResult{Type: TypePhone, Risk: MediumRisk}
	} else if ipHeuristic.MatchString(columnName) {
		match = &MatchResult{Type: TypeIP, Risk: MediumRisk}
	} else if secretHeuristic.MatchString(columnName) {
		match = &MatchResult{Type: TypeSecret, Risk: HighRisk}
	} else if nameHeuristic.MatchString(columnName) {
		match = &MatchResult{Type: TypeName, Risk: MediumRisk}
	}

	if match != nil && IsIgnored(source, columnName, match.Type) {
		return nil
	}

	return match
}

// EvaluateData checks if the data string matches any PII patterns
func EvaluateData(source, column, data string) *MatchResult {
	// 1. High-speed Keyword Matching (Aho-Corasick)
	if keywordMatcher != nil {
		matches := keywordMatcher.Match([]byte(strings.ToLower(data)))
		if len(matches) > 0 {
			rule := keywordMap[matches[0]]
			piiType := PiiType(rule.Name)
			if !IsIgnored(source, column, piiType) {
				return &MatchResult{Type: piiType, Risk: rule.Risk}
			}
		}
	}

	// 2. Custom Regex Rules
	for _, rule := range GlobalConfig.Rules {
		if rule.compiledRegex != nil && rule.compiledRegex.MatchString(data) {
			piiType := PiiType(rule.Name)
			if !IsIgnored(source, column, piiType) {
				return &MatchResult{Type: piiType, Risk: rule.Risk}
			}
		}
	}

	var match *MatchResult
	// 3. Built-in Regex Rules
	if ssnRegex.MatchString(data) {
		match = &MatchResult{Type: TypeSSN, Risk: HighRisk}
	} else if ccRegex.MatchString(data) {
		if passesLuhn(data) {
			match = &MatchResult{Type: TypeCC, Risk: HighRisk}
		}
	} else if emailRegex.MatchString(data) {
		match = &MatchResult{Type: TypeEmail, Risk: HighRisk}
	} else if awsKeyRegex.MatchString(data) {
		match = &MatchResult{Type: TypeSecret, Risk: HighRisk}
	} else if githubTokenRegex.MatchString(data) {
		match = &MatchResult{Type: TypeSecret, Risk: HighRisk}
	} else if privateKeyRegex.MatchString(data) {
		match = &MatchResult{Type: TypeSecret, Risk: HighRisk}
	} else if phoneRegex.MatchString(data) {
		match = &MatchResult{Type: TypePhone, Risk: MediumRisk}
	} else if ipRegex.MatchString(data) {
		match = &MatchResult{Type: TypeIP, Risk: MediumRisk}
	}

	if match != nil && IsIgnored(source, column, match.Type) {
		return nil
	}

	return match
}

// passesLuhn checks if the numeric characters in a string pass the Luhn algorithm
func passesLuhn(data string) bool {
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
