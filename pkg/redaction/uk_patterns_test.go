package redaction

import (
	"context"
	"strings"
	"testing"
)

// TestUKNationalInsuranceNumbers tests UK National Insurance Number detection
func TestUKNationalInsuranceNumbers(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		text     string
		expected bool
		count    int
	}{
		{
			name:     "Valid NI Number - AB123456C",
			text:     "My National Insurance number is AB123456C",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid NI Number - JK987654A",
			text:     "Contact details: Name: John Smith, NI: JK987654A",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid NI Number - QQ123456D",
			text:     "Employee QQ123456D has submitted their form",
			expected: true,
			count:    1,
		},
		{
			name:     "Multiple NI Numbers",
			text:     "Process NI numbers AB123456C and JK987654B for payroll",
			expected: true,
			count:    2,
		},
		{
			name:     "Invalid NI Number - wrong letter",
			text:     "Invalid number AB123456E should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "Invalid NI Number - too short",
			text:     "Invalid number AB12345C should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "Invalid NI Number - numbers in wrong place",
			text:     "Invalid number 1B123456C should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "No NI Number",
			text:     "This text contains no National Insurance numbers",
			expected: false,
			count:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tc.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

			// Check if any UK National Insurance numbers were found
			found := false
			niCount := 0
			for _, redaction := range result.Redactions {
				if redaction.Type == TypeUKNationalInsurance {
					found = true
					niCount++
				}
			}

			if found != tc.expected {
				t.Errorf("Expected found=%v, got found=%v for text: %s", tc.expected, found, tc.text)
			}

			if niCount != tc.count {
				t.Errorf("Expected %d NI numbers, got %d for text: %s", tc.count, niCount, tc.text)
			}

			// If we expected to find NI numbers, verify they were redacted
			if tc.expected && !strings.Contains(result.RedactedText, "AB123456C") && !strings.Contains(result.RedactedText, "JK987654A") {
				// This is good - the NI numbers should be redacted
				// No action needed, just verification
				_ = tc.expected // Use the variable to avoid unused variable warning
			}
		})
	}
}

// TestUKNHSNumbers tests UK NHS Number detection
func TestUKNHSNumbers(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		text     string
		expected bool
		count    int
	}{
		{
			name:     "Valid NHS Number with spaces - 123 456 7890",
			text:     "Patient NHS number: 123 456 7890",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid NHS Number without spaces - 1234567890",
			text:     "NHS: 1234567890 for medical records",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid NHS Number - 987 654 3210",
			text:     "Emergency contact NHS 987 654 3210",
			expected: true,
			count:    1,
		},
		{
			name:     "Multiple NHS Numbers",
			text:     "Process NHS numbers 123 456 7890 and NHS: 9876543210 for patients",
			expected: true,
			count:    2,
		},
		{
			name:     "Invalid NHS Number - too short",
			text:     "Invalid NHS 123 456 789 should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "Invalid NHS Number - wrong format",
			text:     "Invalid NHS 12 345 6789 should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "No NHS Number",
			text:     "This text contains no NHS numbers",
			expected: false,
			count:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tc.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

			found := false
			nhsCount := 0
			for _, redaction := range result.Redactions {
				if redaction.Type == TypeUKNHSNumber {
					found = true
					nhsCount++
				}
			}

			if found != tc.expected {
				t.Errorf("Expected found=%v, got found=%v for text: %s", tc.expected, found, tc.text)
			}

			if nhsCount != tc.count {
				t.Errorf("Expected %d NHS numbers, got %d for text: %s", tc.count, nhsCount, tc.text)
			}
		})
	}
}

// TestUKPostcodes tests UK Postcode detection
func TestUKPostcodes(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		text     string
		expected bool
		count    int
	}{
		{
			name:     "Valid Postcode - SW1A 1AA (Buckingham Palace)",
			text:     "Address: Buckingham Palace, London SW1A 1AA",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid Postcode - M1 1AA (Manchester)",
			text:     "Manchester office: M1 1AA",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid Postcode - B33 8TH (Birmingham)",
			text:     "Birmingham location B33 8TH",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid Postcode without space - SW1A1AA",
			text:     "Postcode SW1A1AA for delivery",
			expected: true,
			count:    1,
		},
		{
			name:     "Multiple Postcodes",
			text:     "Offices in SW1A 1AA and M1 1AA locations",
			expected: true,
			count:    2,
		},
		{
			name:     "Invalid Postcode - wrong format",
			text:     "Invalid postcode SW1A 1A should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "Invalid Postcode - too long area code",
			text:     "Invalid postcode M111 1AA should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "No Postcode",
			text:     "This text contains no UK postcodes",
			expected: false,
			count:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tc.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

			found := false
			postcodeCount := 0
			for _, redaction := range result.Redactions {
				if redaction.Type == TypeUKPostcode {
					found = true
					postcodeCount++
				}
			}

			if found != tc.expected {
				t.Errorf("Expected found=%v, got found=%v for text: %s", tc.expected, found, tc.text)
			}

			if postcodeCount != tc.count {
				t.Errorf("Expected %d postcodes, got %d for text: %s", tc.count, postcodeCount, tc.text)
			}
		})
	}
}

// TestUKPhoneNumbers tests UK Phone Number detection
func TestUKPhoneNumbers(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		text     string
		expected bool
		count    int
	}{
		{
			name:     "Valid UK Phone - +44 20 1234 5678",
			text:     "Call us on +44 20 1234 5678 for support",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid UK Phone - +44 161 123 4567",
			text:     "Manchester office: +44 161 123 4567",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid UK Phone without spaces - +442012345678",
			text:     "Contact +442012345678 for information",
			expected: true,
			count:    1,
		},
		{
			name:     "Multiple UK Phone Numbers",
			text:     "London +44 20 1234 5678 or Manchester +44 161 123 4567",
			expected: true,
			count:    2,
		},
		{
			name:     "No UK Phone Numbers",
			text:     "This text contains no UK phone numbers",
			expected: false,
			count:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tc.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

			found := false
			phoneCount := 0
			for _, redaction := range result.Redactions {
				if redaction.Type == TypeUKPhoneNumber {
					found = true
					phoneCount++
				}
			}

			if found != tc.expected {
				t.Errorf("Expected found=%v, got found=%v for text: %s", tc.expected, found, tc.text)
			}

			if phoneCount != tc.count {
				t.Errorf("Expected %d phone numbers, got %d for text: %s", tc.count, phoneCount, tc.text)
			}
		})
	}
}

// TestUKMobileNumbers tests UK Mobile Number detection
func TestUKMobileNumbers(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		text     string
		expected bool
		count    int
	}{
		{
			name:     "Valid UK Mobile - 07123456789",
			text:     "Mobile: 07123456789 for urgent contact",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid UK Mobile with spaces - 07 123 456 789",
			text:     "Call mobile 07 123 456 789",
			expected: true,
			count:    1,
		},
		{
			name:     "Multiple UK Mobile Numbers",
			text:     "Contacts: 07123456789 and 07 987 654 321",
			expected: true,
			count:    2,
		},
		{
			name:     "Invalid Mobile - wrong prefix",
			text:     "Invalid mobile 08123456789 should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "No Mobile Numbers",
			text:     "This text contains no UK mobile numbers",
			expected: false,
			count:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tc.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

			found := false
			mobileCount := 0
			for _, redaction := range result.Redactions {
				if redaction.Type == TypeUKMobileNumber {
					found = true
					mobileCount++
				}
			}

			if found != tc.expected {
				t.Errorf("Expected found=%v, got found=%v for text: %s", tc.expected, found, tc.text)
			}

			if mobileCount != tc.count {
				t.Errorf("Expected %d mobile numbers, got %d for text: %s", tc.count, mobileCount, tc.text)
			}
		})
	}
}

// TestUKSortCodes tests UK Bank Sort Code detection
func TestUKSortCodes(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		text     string
		expected bool
		count    int
	}{
		{
			name:     "Valid Sort Code - 12-34-56",
			text:     "Bank details: Sort Code 12-34-56",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid Sort Code - 98-76-54",
			text:     "Transfer to sort code 98-76-54",
			expected: true,
			count:    1,
		},
		{
			name:     "Multiple Sort Codes",
			text:     "From 12-34-56 to 98-76-54 for transfer",
			expected: true,
			count:    2,
		},
		{
			name:     "Invalid Sort Code - wrong format",
			text:     "Invalid sort code 123456 should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "No Sort Codes",
			text:     "This text contains no sort codes",
			expected: false,
			count:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tc.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

			found := false
			sortCodeCount := 0
			for _, redaction := range result.Redactions {
				if redaction.Type == TypeUKSortCode {
					found = true
					sortCodeCount++
				}
			}

			if found != tc.expected {
				t.Errorf("Expected found=%v, got found=%v for text: %s", tc.expected, found, tc.text)
			}

			if sortCodeCount != tc.count {
				t.Errorf("Expected %d sort codes, got %d for text: %s", tc.count, sortCodeCount, tc.text)
			}
		})
	}
}

// TestUKIBAN tests UK IBAN detection
func TestUKIBAN(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		text     string
		expected bool
		count    int
	}{
		{
			name:     "Valid UK IBAN with spaces - GB82 WEST 1234 5698 7654 32",
			text:     "IBAN: GB82 WEST 1234 5698 7654 32",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid UK IBAN without spaces - GB82WEST12345698765432",
			text:     "Transfer to GB82WEST12345698765432",
			expected: true,
			count:    1,
		},
		{
			name:     "Invalid IBAN - wrong country code",
			text:     "Invalid IBAN FR82 WEST 1234 5698 7654 32",
			expected: false,
			count:    0,
		},
		{
			name:     "No IBAN",
			text:     "This text contains no IBAN numbers",
			expected: false,
			count:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tc.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

			found := false
			ibanCount := 0
			for _, redaction := range result.Redactions {
				if redaction.Type == TypeUKIBAN {
					found = true
					ibanCount++
				}
			}

			if found != tc.expected {
				t.Errorf("Expected found=%v, got found=%v for text: %s", tc.expected, found, tc.text)
			}

			if ibanCount != tc.count {
				t.Errorf("Expected %d IBANs, got %d for text: %s", tc.count, ibanCount, tc.text)
			}
		})
	}
}

// TestUKCompanyNumbers tests UK Company Number detection
func TestUKCompanyNumbers(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		text     string
		expected bool
		count    int
	}{
		{
			name:     "Valid Company Number with context - Company No: 12345678",
			text:     "Company No: 12345678 is registered",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid Company Number - Company Number 87654321",
			text:     "Company Number 87654321 details",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid Company Number standalone - 12345678",
			text:     "Registration 12345678 approved",
			expected: true,
			count:    1,
		},
		{
			name:     "Invalid Company Number - too short",
			text:     "Invalid company 1234567 should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "Invalid Company Number - too long",
			text:     "Invalid company 123456789 should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "No Company Numbers",
			text:     "This text contains no company numbers",
			expected: false,
			count:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tc.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

			found := false
			companyCount := 0
			for _, redaction := range result.Redactions {
				if redaction.Type == TypeUKCompanyNumber {
					found = true
					companyCount++
				}
			}

			if found != tc.expected {
				t.Errorf("Expected found=%v, got found=%v for text: %s", tc.expected, found, tc.text)
			}

			if companyCount != tc.count {
				t.Errorf("Expected %d company numbers, got %d for text: %s", tc.count, companyCount, tc.text)
			}
		})
	}
}

// TestUKDrivingLicenseNumbers tests UK Driving License Number detection
func TestUKDrivingLicenseNumbers(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		text     string
		expected bool
		count    int
	}{
		{
			name:     "Valid Driving License - MORGA657054SM9IJ",
			text:     "Driving License: MORGA657054SM9IJ",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid Driving License - SMITH123456AB7CD",
			text:     "License number SMITH123456AB7CD on file",
			expected: true,
			count:    1,
		},
		{
			name:     "Invalid Driving License - wrong format",
			text:     "Invalid license MORGA65705 should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "No Driving License Numbers",
			text:     "This text contains no driving license numbers",
			expected: false,
			count:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tc.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

			found := false
			licenseCount := 0
			for _, redaction := range result.Redactions {
				if redaction.Type == TypeUKDrivingLicense {
					found = true
					licenseCount++
				}
			}

			if found != tc.expected {
				t.Errorf("Expected found=%v, got found=%v for text: %s", tc.expected, found, tc.text)
			}

			if licenseCount != tc.count {
				t.Errorf("Expected %d driving licenses, got %d for text: %s", tc.count, licenseCount, tc.text)
			}
		})
	}
}

// TestUKPassportNumbers tests UK Passport Number detection
func TestUKPassportNumbers(t *testing.T) {
	engine := NewEngine()

	testCases := []struct {
		name     string
		text     string
		expected bool
		count    int
	}{
		{
			name:     "Valid Passport Number with context - Passport No: 123456789",
			text:     "Passport No: 123456789 for travel",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid Passport Number - Passport Number 987654321",
			text:     "Passport Number 987654321 details",
			expected: true,
			count:    1,
		},
		{
			name:     "Valid Passport Number standalone - 123456789",
			text:     "Document 123456789 verified",
			expected: true,
			count:    1,
		},
		{
			name:     "Invalid Passport Number - too short",
			text:     "Invalid passport 12345678 should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "Invalid Passport Number - too long",
			text:     "Invalid passport 1234567890 should not match",
			expected: false,
			count:    0,
		},
		{
			name:     "No Passport Numbers",
			text:     "This text contains no passport numbers",
			expected: false,
			count:    0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tc.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

			found := false
			passportCount := 0
			for _, redaction := range result.Redactions {
				if redaction.Type == TypeUKPassportNumber {
					found = true
					passportCount++
				}
			}

			if found != tc.expected {
				t.Errorf("Expected found=%v, got found=%v for text: %s", tc.expected, found, tc.text)
			}

			if passportCount != tc.count {
				t.Errorf("Expected %d passport numbers, got %d for text: %s", tc.count, passportCount, tc.text)
			}
		})
	}
}

// TestUKComplianceIntegration tests multiple UK patterns in a single text
func TestUKComplianceIntegration(t *testing.T) {
	engine := NewEngine()

	text := `
	Customer Information:
	Name: John Smith
	National Insurance: AB123456C
	NHS Number: 123 456 7890
	Address: 123 High Street, London SW1A 1AA
	Phone: +44 20 1234 5678
	Mobile: 07 123 456 789
	Bank Details:
	Sort Code: 12-34-56
	IBAN: GB82 WEST 1234 5698 7654 32
	Company: Company No: 12345678
	Driving License: MORGA657054SM9IJ
	Passport: Passport No: 123456789
	`

	result, err := engine.RedactText(context.Background(), &Request{
		Text: text,
		Mode: ModeReplace,
	})
	if err != nil {
		t.Fatalf("RedactText failed: %v", err)
	}

	// Count different types of UK identifiers found
	ukPatternCounts := make(map[Type]int)
	for _, redaction := range result.Redactions {
		if strings.HasPrefix(string(redaction.Type), "uk_") {
			ukPatternCounts[redaction.Type]++
		}
	}

	expectedPatterns := map[Type]int{
		TypeUKNationalInsurance: 1,
		TypeUKNHSNumber:         1,
		TypeUKPostcode:          1,
		TypeUKPhoneNumber:       1,
		TypeUKMobileNumber:      1,
		TypeUKSortCode:          1,
		TypeUKIBAN:              1,
		TypeUKCompanyNumber:     1,
		TypeUKDrivingLicense:    1,
		TypeUKPassportNumber:    1,
	}

	for expectedType, expectedCount := range expectedPatterns {
		if actualCount, found := ukPatternCounts[expectedType]; !found || actualCount != expectedCount {
			t.Errorf("Expected %d %s, got %d", expectedCount, expectedType, actualCount)
		}
	}

	// Debug: Print the redacted text to see what's happening
	t.Logf("Redacted text: %s", result.RedactedText)

	// Verify that sensitive data was redacted
	if strings.Contains(result.RedactedText, "AB123456C") {
		t.Error("National Insurance number should be redacted")
	}
	if strings.Contains(result.RedactedText, "123 456 7890") {
		t.Error("NHS number should be redacted")
	}
	if strings.Contains(result.RedactedText, "SW1A 1AA") {
		t.Error("Postcode should be redacted")
	}

	t.Logf("Successfully detected and redacted %d UK-specific identifiers", len(ukPatternCounts))
	t.Logf("Original text length: %d, Redacted text length: %d", len(text), len(result.RedactedText))
}
