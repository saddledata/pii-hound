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

type RuleConfig struct {
	Rules []CustomRule `yaml:"rules"`
}

var (
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

	// Loaded custom rules
	customRules []CustomRule

	// Aho-Corasick Automaton for high-speed keyword matching
	keywordMatcher *ahocorasick.Matcher
	// Maps keyword index in matcher to its Rule
	keywordMap map[int]*CustomRule
)

// LoadCustomRules reads rules from a YAML file
func LoadCustomRules(path string) error {
	f, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var config RuleConfig
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

		customRules = append(customRules, *rule)
	}

	if len(allKeywords) > 0 {
		keywordMatcher = ahocorasick.NewMatcher(allKeywords)
	}

	return nil
}

// EvaluateColumnHeuristics checks if a column name suggests it contains PII
func EvaluateColumnHeuristics(columnName string) *MatchResult {
	// Check custom rules first
	for _, rule := range customRules {
		if rule.compiledHeuristic != nil && rule.compiledHeuristic.MatchString(columnName) {
			return &MatchResult{Type: PiiType(rule.Name), Risk: rule.Risk}
		}
	}

	// Fallback to built-ins
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
	if nameHeuristic.MatchString(columnName) {
		return &MatchResult{Type: TypeName, Risk: MediumRisk}
	}
	return nil
}

// EvaluateData checks if the data string matches any PII patterns
func EvaluateData(data string) *MatchResult {
	// 1. High-speed Keyword Matching (Aho-Corasick)
	if keywordMatcher != nil {
		// Convert to lower for case-insensitive keyword match
		matches := keywordMatcher.Match([]byte(strings.ToLower(data)))
		if len(matches) > 0 {
			// Return the first match found
			rule := keywordMap[matches[0]]
			return &MatchResult{Type: PiiType(rule.Name), Risk: rule.Risk}
		}
	}

	// 2. Custom Regex Rules
	for _, rule := range customRules {
		if rule.compiledRegex != nil && rule.compiledRegex.MatchString(data) {
			return &MatchResult{Type: PiiType(rule.Name), Risk: rule.Risk}
		}
	}

	// 3. Built-in Regex Rules
	// High Risk - PII
	if ssnRegex.MatchString(data) {
		return &MatchResult{Type: TypeSSN, Risk: HighRisk}
	}
	if ccRegex.MatchString(data) {
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
