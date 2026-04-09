package detectors

import "testing"

func TestEvaluateData(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantType PiiType
		wantRisk RiskLevel
	}{
		{
			name:     "Valid Email",
			data:     "test@example.com",
			wantType: TypeEmail,
			wantRisk: HighRisk,
		},
		{
			name:     "Valid SSN with dashes",
			data:     "123-45-6789",
			wantType: TypeSSN,
			wantRisk: HighRisk,
		},
		{
			name:     "Valid SSN without dashes",
			data:     "123456789",
			wantType: TypeSSN,
			wantRisk: HighRisk,
		},
		{
			name:     "Valid Credit Card (Visa)",
			data:     "4111 1111 1111 1111",
			wantType: TypeCC,
			wantRisk: HighRisk,
		},
		{
			name:     "Invalid Credit Card (Failed Luhn)",
			data:     "4111 1111 1111 1112",
			wantType: "",
		},
		{
			name:     "Valid IP Address",
			data:     "192.168.1.1",
			wantType: TypeIP,
			wantRisk: MediumRisk,
		},
		{
			name:     "Valid Phone Number",
			data:     "555-555-0199",
			wantType: TypePhone,
			wantRisk: MediumRisk,
		},
		{
			name:     "AWS Access Key",
			data:     "AKIAIOSFODNN7EXAMPLE",
			wantType: TypeSecret,
			wantRisk: HighRisk,
		},
		{
			name:     "GitHub Token",
			data:     "ghp_1234567890abcdef1234567890abcdef1234",
			wantType: TypeSecret,
			wantRisk: HighRisk,
		},
		{
			name:     "Private Key Header",
			data:     "-----BEGIN RSA PRIVATE KEY-----",
			wantType: TypeSecret,
			wantRisk: HighRisk,
		},
		{
			name:     "No PII",
			data:     "just some regular text 12345",
			wantType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateData("test", "col", tt.data)
			if tt.wantType == "" {
				if got != nil {
					t.Errorf("EvaluateData() = %v, want nil", got.Type)
				}
				return
			}
			if got == nil {
				t.Fatalf("EvaluateData() returned nil, want %v", tt.wantType)
			}
			if got.Type != tt.wantType {
				t.Errorf("EvaluateData() Type = %v, want %v", got.Type, tt.wantType)
			}
			if got.Risk != tt.wantRisk {
				t.Errorf("EvaluateData() Risk = %v, want %v", got.Risk, tt.wantRisk)
			}
		})
	}
}

func TestEvaluateColumnHeuristics(t *testing.T) {
	tests := []struct {
		columnName string
		wantType   PiiType
	}{
		{"email", TypeEmail},
		{"user_email", TypeEmail},
		{"ssn", TypeSSN},
		{"social_security_number", TypeSSN},
		{"ccnum", TypeCC},
		{"credit_card", TypeCC},
		{"ip_address", TypeIP},
		{"ip", TypeIP},
		{"mobile_phone", TypePhone},
		{"api_key", TypeSecret},
		{"token", TypeSecret},
		{"password", TypeSecret},
		{"first_name", TypeName},
		{"last_name", TypeName},
		{"fullname", TypeName},
		{"customer_name", TypeName},
		{"zipcode", ""}, // Should NOT match IP
		{"description", ""},
	}

	for _, tt := range tests {
		t.Run(tt.columnName, func(t *testing.T) {
			got := EvaluateColumnHeuristics("test", tt.columnName)
			if tt.wantType == "" {
				if got != nil {
					t.Errorf("EvaluateColumnHeuristics(%v) = %v, want nil", tt.columnName, got.Type)
				}
				return
			}
			if got == nil {
				t.Fatalf("EvaluateColumnHeuristics(%v) returned nil, want %v", tt.columnName, tt.wantType)
			}
			if got.Type != tt.wantType {
				t.Errorf("EvaluateColumnHeuristics(%v) Type = %v, want %v", tt.columnName, got.Type, tt.wantType)
			}
		})
	}
}

func TestPassesLuhn(t *testing.T) {
	tests := []struct {
		cc   string
		want bool
	}{
		{"4111 1111 1111 1111", true},
		{"4111111111111111", true},
		{"4111-1111-1111-1111", true},
		{"4111 1111 1111 1112", false},
		{"1234", false}, // too short
	}
	for _, tt := range tests {
		if got := passesLuhn(tt.cc); got != tt.want {
			t.Errorf("passesLuhn(%v) = %v, want %v", tt.cc, got, tt.want)
		}
	}
}
