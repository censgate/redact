package strategies

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// FakeDataStrategy replaces sensitive data with realistic fake data
type FakeDataStrategy struct {
	name string
}

// NewFakeDataStrategy creates a new fake data replacement strategy
func NewFakeDataStrategy() *FakeDataStrategy {
	return &FakeDataStrategy{
		name: "fake_data",
	}
}

// GetName returns the name of the strategy
func (s *FakeDataStrategy) GetName() string {
	return s.name
}

// GetDescription returns a description of the strategy
func (s *FakeDataStrategy) GetDescription() string {
	return "Replaces sensitive data with realistic fake data for testing and development"
}

// Replace performs the replacement using fake data strategy
func (s *FakeDataStrategy) Replace(ctx context.Context, request *ReplacementRequest) (*ReplacementResult, error) {
	if request == nil {
		return nil, fmt.Errorf("replacement request cannot be nil")
	}

	var replacedText string
	var confidence float64 = 0.85

	switch strings.ToLower(request.DetectedType) {
	case "name", "person_name":
		replacedText = s.generateFakeName()
	case "email":
		replacedText = s.generateFakeEmail()
	case "phone", "phone_number":
		replacedText = s.generateFakePhone()
	case "address":
		replacedText = s.generateFakeAddress()
	case "company", "organization":
		replacedText = s.generateFakeCompany()
	case "date", "date_of_birth":
		replacedText = s.generateFakeDate()
	case "city":
		replacedText = s.generateFakeCity()
	case "state":
		replacedText = s.generateFakeState()
	case "country":
		replacedText = s.generateFakeCountry()
	default:
		// For unknown types, generate generic fake data
		replacedText = s.generateGenericFakeData(request.OriginalText)
		confidence = 0.6
	}

	return &ReplacementResult{
		ReplacedText: replacedText,
		Strategy:     s.name,
		Confidence:   confidence,
		Reversible:   false,
		Metadata: map[string]interface{}{
			"original_length": len(request.OriginalText),
			"replaced_length": len(replacedText),
			"data_type":       "fake",
			"detected_type":   request.DetectedType,
		},
	}, nil
}

// IsReversible indicates whether this strategy supports reversible operations
func (s *FakeDataStrategy) IsReversible() bool {
	return false
}

// GetCapabilities returns the capabilities of this strategy
func (s *FakeDataStrategy) GetCapabilities() *StrategyCapabilities {
	return &StrategyCapabilities{
		Name: s.name,
		SupportedTypes: []string{
			"name", "person_name", "email", "phone", "phone_number",
			"address", "company", "organization", "date", "date_of_birth",
			"city", "state", "country",
		},
		SupportsReversible: false,
		SupportsFormatting: true,
		RequiresContext:    false,
		PerformanceLevel:   "fast",
		AccuracyLevel:      "good",
	}
}

// Private helper methods for generating realistic fake data

func (s *FakeDataStrategy) generateFakeName() string {
	firstNames := []string{
		"James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
		"William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
		"Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
		"Matthew", "Betty", "Anthony", "Helen", "Mark", "Sandra", "Donald", "Donna",
	}

	lastNames := []string{
		"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
		"Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
		"Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
		"Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young",
	}

	rand.Seed(time.Now().UnixNano())
	firstName := firstNames[rand.Intn(len(firstNames))]
	lastName := lastNames[rand.Intn(len(lastNames))]

	return fmt.Sprintf("%s %s", firstName, lastName)
}

func (s *FakeDataStrategy) generateFakeEmail() string {
	domains := []string{
		"example.com", "test.org", "sample.net", "demo.co", "fake.email",
		"placeholder.com", "mock.org", "dummy.net", "testing.co", "dev.email",
	}

	usernames := []string{
		"john.doe", "jane.smith", "alex.johnson", "chris.wilson", "taylor.brown",
		"jordan.davis", "casey.miller", "riley.garcia", "avery.martinez", "drew.anderson",
	}

	rand.Seed(time.Now().UnixNano())
	username := usernames[rand.Intn(len(usernames))]
	domain := domains[rand.Intn(len(domains))]

	return fmt.Sprintf("%s@%s", username, domain)
}

func (s *FakeDataStrategy) generateFakePhone() string {
	rand.Seed(time.Now().UnixNano())
	// Use 555 prefix which is reserved for fictional use
	return fmt.Sprintf("555-%03d-%04d", rand.Intn(1000), rand.Intn(10000))
}

func (s *FakeDataStrategy) generateFakeAddress() string {
	streetNumbers := rand.Intn(9999) + 1
	streetNames := []string{
		"Main St", "Oak Ave", "Pine Rd", "Elm Dr", "First St", "Second Ave",
		"Third Blvd", "Fourth Pl", "Fifth Way", "Sixth Ct", "Maple St", "Cedar Ave",
		"Birch Rd", "Willow Dr", "Cherry St", "Walnut Ave", "Hickory Blvd",
	}

	rand.Seed(time.Now().UnixNano())
	streetName := streetNames[rand.Intn(len(streetNames))]

	return fmt.Sprintf("%d %s", streetNumbers, streetName)
}

func (s *FakeDataStrategy) generateFakeCompany() string {
	prefixes := []string{
		"Global", "United", "International", "National", "Advanced", "Innovative",
		"Dynamic", "Strategic", "Premier", "Elite", "Professional", "Superior",
	}

	suffixes := []string{
		"Systems", "Solutions", "Technologies", "Services", "Enterprises", "Corporation",
		"Industries", "Group", "Associates", "Partners", "Consulting", "Holdings",
	}

	rand.Seed(time.Now().UnixNano())
	prefix := prefixes[rand.Intn(len(prefixes))]
	suffix := suffixes[rand.Intn(len(suffixes))]

	return fmt.Sprintf("%s %s", prefix, suffix)
}

func (s *FakeDataStrategy) generateFakeDate() string {
	rand.Seed(time.Now().UnixNano())
	year := rand.Intn(50) + 1970 // 1970-2020
	month := rand.Intn(12) + 1   // 1-12
	day := rand.Intn(28) + 1     // 1-28 (safe for all months)

	return fmt.Sprintf("%04d-%02d-%02d", year, month, day)
}

func (s *FakeDataStrategy) generateFakeCity() string {
	cities := []string{
		"Springfield", "Franklin", "Georgetown", "Clinton", "Greenville", "Madison",
		"Washington", "Chester", "Oxford", "Bristol", "Manchester", "Salem",
		"Auburn", "Milton", "Lexington", "Riverside", "Arlington", "Fairfield",
	}

	rand.Seed(time.Now().UnixNano())
	return cities[rand.Intn(len(cities))]
}

func (s *FakeDataStrategy) generateFakeState() string {
	states := []string{
		"California", "Texas", "Florida", "New York", "Pennsylvania", "Illinois",
		"Ohio", "Georgia", "North Carolina", "Michigan", "New Jersey", "Virginia",
		"Washington", "Arizona", "Massachusetts", "Tennessee", "Indiana", "Missouri",
	}

	rand.Seed(time.Now().UnixNano())
	return states[rand.Intn(len(states))]
}

func (s *FakeDataStrategy) generateFakeCountry() string {
	countries := []string{
		"United States", "Canada", "United Kingdom", "Germany", "France", "Australia",
		"Japan", "South Korea", "Netherlands", "Sweden", "Norway", "Denmark",
		"Switzerland", "Austria", "Belgium", "Finland", "Ireland", "New Zealand",
	}

	rand.Seed(time.Now().UnixNano())
	return countries[rand.Intn(len(countries))]
}

func (s *FakeDataStrategy) generateGenericFakeData(original string) string {
	length := len(original)

	if length <= 5 {
		return "FAKE"
	} else if length <= 15 {
		return "FAKE_DATA"
	} else {
		return "REALISTIC_FAKE_DATA_PLACEHOLDER"
	}
}
