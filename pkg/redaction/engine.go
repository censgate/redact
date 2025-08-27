package redaction

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// RedactionType represents the type of sensitive data
type RedactionType string

// ContextDomain represents the context domain for enhanced detection
type ContextDomain string

const (
	DomainMedical   ContextDomain = "medical"
	DomainFinancial ContextDomain = "financial"
	DomainLegal     ContextDomain = "legal"
	DomainGeneral   ContextDomain = "general"
)

const (
	TypeEmail         RedactionType = "email"
	TypePhone         RedactionType = "phone"
	TypeCreditCard    RedactionType = "credit_card"
	TypeSSN           RedactionType = "ssn"
	TypeAddress       RedactionType = "address"
	TypeName          RedactionType = "name"
	TypeIPAddress     RedactionType = "ip_address"
	TypeDate          RedactionType = "date"
	TypeTime          RedactionType = "time"
	TypeLink          RedactionType = "link"
	TypeZipCode       RedactionType = "zip_code"
	TypePoBox         RedactionType = "po_box"
	TypeBTCAddress    RedactionType = "btc_address"
	TypeMD5Hex        RedactionType = "md5_hex"
	TypeSHA1Hex       RedactionType = "sha1_hex"
	TypeSHA256Hex     RedactionType = "sha256_hex"
	TypeGUID          RedactionType = "guid"
	TypeISBN          RedactionType = "isbn"
	TypeMACAddress    RedactionType = "mac_address"
	TypeIBAN          RedactionType = "iban"
	TypeGitRepo       RedactionType = "git_repo"
	TypeCustom        RedactionType = "custom"
)

// RedactionResult represents the result of a redaction operation
type RedactionResult struct {
	OriginalText string      `json:"original_text"`
	RedactedText string      `json:"redacted_text"`
	Redactions   []Redaction `json:"redactions"`
	Token        string      `json:"token,omitempty"`
	Timestamp    time.Time   `json:"timestamp"`
}

// Redaction represents a single redaction operation
type Redaction struct {
	Type        RedactionType `json:"type"`
	Start       int           `json:"start"`
	End         int           `json:"end"`
	Original    string        `json:"original"`
	Replacement string        `json:"replacement"`
	Confidence  float64       `json:"confidence"`
	Context     string        `json:"context,omitempty"`
	Domain      ContextDomain `json:"domain,omitempty"`
}

// RedactionEngine handles PII/PHI detection and redaction
type RedactionEngine struct {
	patterns       map[RedactionType]*regexp.Regexp
	contextPatterns map[ContextDomain]map[string]*regexp.Regexp
	tokens         map[string]TokenInfo
	mutex          sync.RWMutex
	masterKey      []byte
	keyVersion     int
}

// TokenInfo stores information about a redaction token
type TokenInfo struct {
	EncryptedData []byte        `json:"encrypted_data"`
	RedactionType RedactionType `json:"redaction_type"`
	Created       time.Time     `json:"created"`
	Expires       time.Time     `json:"expires"`
	KeyVersion    int           `json:"key_version"`
	Nonce         []byte        `json:"nonce"`
}

// ContextAnalysisResult represents the result of context analysis
type ContextAnalysisResult struct {
	Domain     ContextDomain `json:"domain"`
	Confidence float64       `json:"confidence"`
	Keywords   []string      `json:"keywords"`
}

// NewRedactionEngine creates a new redaction engine
func NewRedactionEngine() *RedactionEngine {
	engine := &RedactionEngine{
		patterns:        make(map[RedactionType]*regexp.Regexp),
		contextPatterns: make(map[ContextDomain]map[string]*regexp.Regexp),
		tokens:          make(map[string]TokenInfo),
		keyVersion:      1,
	}

	// Initialize master key for encryption
	engine.initMasterKey()

	// Initialize default patterns
	engine.initDefaultPatterns()

	// Initialize context-aware patterns
	engine.initContextPatterns()

	return engine
}

// initDefaultPatterns initializes the default detection patterns
func (re *RedactionEngine) initDefaultPatterns() {
	// Email patterns
	re.patterns[TypeEmail] = regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)

	// Phone number patterns (US format) - more restrictive to avoid GUID conflicts
	re.patterns[TypePhone] = regexp.MustCompile(`\b(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b`)

	// Credit card patterns - simplified pattern for testing
	re.patterns[TypeCreditCard] = regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`)

	// SSN patterns (US format) - match exactly XXX-XX-XXXX format to avoid ZIP conflicts
	re.patterns[TypeSSN] = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

	// IP address patterns (IPv4)
	re.patterns[TypeIPAddress] = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

	// Date patterns (various formats)
	re.patterns[TypeDate] = regexp.MustCompile(`\b(?:0?[1-9]|1[012])[-/](?:0?[1-9]|[12][0-9]|3[01])[-/](?:19|20)\d{2}\b`)

	// Time patterns (24-hour format)
	re.patterns[TypeTime] = regexp.MustCompile(`\b(?:[01]?[0-9]|2[0-3]):[0-5][0-9](?::[0-5][0-9])?\s*(?:AM|PM|am|pm)?\b`)

	// Link patterns (URLs)
	re.patterns[TypeLink] = regexp.MustCompile(`\b(?:https?://|www\.)[^\s<>"{}|\\^` + "`" + `\[\]]+`)


	// ZIP code patterns (US format) - only match full ZIP+4 format to avoid conflicts
	re.patterns[TypeZipCode] = regexp.MustCompile(`\b\d{5}-\d{4}\b`)

	// PO Box patterns
	re.patterns[TypePoBox] = regexp.MustCompile(`\b(?:P\.?O\.?\s*Box|Post\s*Office\s*Box|PO\s*Box)\s+\d+\b`)

	// Bitcoin address patterns
	re.patterns[TypeBTCAddress] = regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`)

	// MD5 hash patterns
	re.patterns[TypeMD5Hex] = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)

	// SHA1 hash patterns
	re.patterns[TypeSHA1Hex] = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)

	// SHA256 hash patterns
	re.patterns[TypeSHA256Hex] = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)

	// GUID/UUID patterns
	re.patterns[TypeGUID] = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)

	// ISBN patterns (10 or 13 digits)
	re.patterns[TypeISBN] = regexp.MustCompile(`\b(?:ISBN(?:-1[03])?\s*:?\s*)?[0-9X]{10}(?:[-\s][0-9X]{3}){3}\b`)

	// MAC address patterns
	re.patterns[TypeMACAddress] = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)

	// IBAN patterns (basic format)
	re.patterns[TypeIBAN] = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b`)

	// Git repository patterns
	re.patterns[TypeGitRepo] = regexp.MustCompile(`\b(?:git@|https?://)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[a-zA-Z0-9_.-]+)*\.git\b`)
}

// initMasterKey initializes the master encryption key
func (re *RedactionEngine) initMasterKey() {
	// In production, this should come from a secure key management system
	// For now, we'll generate a random key and derive it properly
	salt := make([]byte, 32)
	rand.Read(salt)
	
	// Use a default passphrase - in production this should come from environment or KMS
	passphrase := "redactly-master-key-v1"
	re.masterKey = pbkdf2.Key([]byte(passphrase), salt, 10000, 32, sha256.New)
}

// initContextPatterns initializes context-aware detection patterns
func (re *RedactionEngine) initContextPatterns() {
	// Medical domain patterns
	re.contextPatterns[DomainMedical] = map[string]*regexp.Regexp{
		"diagnosis":    regexp.MustCompile(`(?i)\b(diagnosed?\s+with|diagnosis\s+of|suffers?\s+from)\s+([a-zA-Z\s]{2,30})`),
		"medication":   regexp.MustCompile(`(?i)\b(prescribed|taking|medication|drug)\s+([a-zA-Z0-9\s]{2,20}mg?)`),
		"procedure":    regexp.MustCompile(`(?i)\b(surgery|procedure|operation|treatment)\s+([a-zA-Z\s]{2,30})`),
		"vital_signs":  regexp.MustCompile(`(?i)\b(blood\s+pressure|bp|heart\s+rate|hr|temperature|temp)\s*:?\s*([0-9/\s]{2,10})`),
		"lab_results":  regexp.MustCompile(`(?i)\b(glucose|cholesterol|hemoglobin|hgb|white\s+blood\s+cell|wbc)\s*:?\s*([0-9\.\s]{1,10})`),
	}

	// Financial domain patterns
	re.contextPatterns[DomainFinancial] = map[string]*regexp.Regexp{
		"account":      regexp.MustCompile(`(?i)\b(account\s+number|acct\s+#?|account\s+#)\s*:?\s*([0-9\-\s]{6,20})`),
		"routing":      regexp.MustCompile(`(?i)\b(routing\s+number|routing\s+#|aba\s+number)\s*:?\s*([0-9]{9})`),
		"loan":         regexp.MustCompile(`(?i)\b(loan\s+number|loan\s+id|mortgage\s+#)\s*:?\s*([0-9A-Z\-]{6,20})`),
		"investment":   regexp.MustCompile(`(?i)\b(portfolio|investment\s+account|brokerage)\s+([0-9A-Z\-]{6,20})`),
		"transaction":  regexp.MustCompile(`(?i)\b(transaction\s+id|txn\s+#|reference\s+#)\s*:?\s*([0-9A-Z\-]{6,20})`),
	}

	// Legal domain patterns
	re.contextPatterns[DomainLegal] = map[string]*regexp.Regexp{
		"case_number":  regexp.MustCompile(`(?i)\b(case\s+number|case\s+#|docket\s+#)\s*:?\s*([0-9A-Z\-]{6,20})`),
		"court":        regexp.MustCompile(`(?i)\b(court\s+of|superior\s+court|district\s+court)\s+([a-zA-Z\s]{2,30})`),
		"attorney":     regexp.MustCompile(`(?i)\b(attorney|lawyer|counsel)\s+([A-Z][a-zA-Z\.\s]{2,30})`),
		"contract":     regexp.MustCompile(`(?i)\b(contract\s+number|agreement\s+#|policy\s+#)\s*:?\s*([0-9A-Z\-]{6,20})`),
		"defendant":    regexp.MustCompile(`(?i)\b(defendant|plaintiff|party)\s+([A-Z][a-zA-Z\.\s]{2,30})`),
	}
}

// AddCustomPattern adds a custom detection pattern
func (re *RedactionEngine) AddCustomPattern(name string, pattern string) error {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %v", err)
	}

	re.patterns[RedactionType(name)] = compiled
	return nil
}

// AnalyzeContext analyzes the text to determine the most likely context domain
func (re *RedactionEngine) AnalyzeContext(text string) ContextAnalysisResult {
	lowerText := strings.ToLower(text)
	domainScores := make(map[ContextDomain]float64)
	domainKeywords := make(map[ContextDomain][]string)

	// Medical keywords
	medicalKeywords := []string{"patient", "doctor", "physician", "hospital", "clinic", "medical", "health", "treatment", "diagnosis", "medication", "surgery", "symptoms", "condition"}
	for _, keyword := range medicalKeywords {
		if strings.Contains(lowerText, keyword) {
			domainScores[DomainMedical] += 1.0
			domainKeywords[DomainMedical] = append(domainKeywords[DomainMedical], keyword)
		}
	}

	// Financial keywords
	financialKeywords := []string{"bank", "account", "loan", "credit", "debit", "payment", "transaction", "investment", "portfolio", "mortgage", "finance", "money", "balance"}
	for _, keyword := range financialKeywords {
		if strings.Contains(lowerText, keyword) {
			domainScores[DomainFinancial] += 1.0
			domainKeywords[DomainFinancial] = append(domainKeywords[DomainFinancial], keyword)
		}
	}

	// Legal keywords
	legalKeywords := []string{"court", "judge", "attorney", "lawyer", "case", "lawsuit", "contract", "agreement", "legal", "law", "defendant", "plaintiff", "verdict"}
	for _, keyword := range legalKeywords {
		if strings.Contains(lowerText, keyword) {
			domainScores[DomainLegal] += 1.0
			domainKeywords[DomainLegal] = append(domainKeywords[DomainLegal], keyword)
		}
	}

	// Find the domain with the highest score
	var bestDomain ContextDomain = DomainGeneral
	var bestScore float64 = 0
	for domain, score := range domainScores {
		if score > bestScore {
			bestDomain = domain
			bestScore = score
		}
	}

	// Calculate confidence as percentage of total words
	wordCount := float64(len(strings.Fields(text)))
	confidence := bestScore / wordCount
	if confidence > 1.0 {
		confidence = 1.0
	}

	return ContextAnalysisResult{
		Domain:     bestDomain,
		Confidence: confidence,
		Keywords:   domainKeywords[bestDomain],
	}
}

// RedactText performs redaction on the input text
func (re *RedactionEngine) RedactText(text string) *RedactionResult {
	result := &RedactionResult{
		OriginalText: text,
		RedactedText: text,
		Redactions:   []Redaction{},
		Timestamp:    time.Now(),
	}

	// Analyze context to improve detection accuracy
	contextAnalysis := re.AnalyzeContext(text)

	// Process standard redaction patterns
	for redactionType, pattern := range re.patterns {
		matches := pattern.FindAllStringIndex(text, -1)

		for _, match := range matches {
			start, end := match[0], match[1]
			original := text[start:end]

			// Create redaction
			redaction := Redaction{
				Type:        redactionType,
				Start:       start,
				End:         end,
				Original:    original,
				Replacement: re.generateReplacement(redactionType, original),
				Confidence:  0.95, // High confidence for regex matches
				Context:     re.extractContext(text, start, end),
				Domain:      contextAnalysis.Domain,
			}

			result.Redactions = append(result.Redactions, redaction)
		}
	}

	// Process context-aware patterns if domain was detected
	if contextAnalysis.Domain != DomainGeneral {
		if domainPatterns, exists := re.contextPatterns[contextAnalysis.Domain]; exists {
			for patternName, pattern := range domainPatterns {
				matches := pattern.FindAllStringSubmatch(text, -1)
				matchIndices := pattern.FindAllStringSubmatchIndex(text, -1)

				for i, match := range matches {
					if len(match) >= 3 && len(matchIndices[i]) >= 6 {
						// Extract the sensitive part (usually the second capture group)
						start, end := matchIndices[i][4], matchIndices[i][5]
						original := match[2]

						// Create context-aware redaction
						redaction := Redaction{
							Type:        RedactionType(fmt.Sprintf("%s_%s", contextAnalysis.Domain, patternName)),
							Start:       start,
							End:         end,
							Original:    original,
							Replacement: fmt.Sprintf("[%s_%s_REDACTED]", strings.ToUpper(string(contextAnalysis.Domain)), strings.ToUpper(patternName)),
							Confidence:  0.85 + (contextAnalysis.Confidence * 0.1), // Higher confidence with better context
							Context:     re.extractContext(text, start, end),
							Domain:      contextAnalysis.Domain,
						}

						result.Redactions = append(result.Redactions, redaction)
					}
				}
			}
		}
	}

	// Apply redactions in reverse order to maintain indices
	// We need to track offset changes as we modify the text
	offset := 0
	for i := len(result.Redactions) - 1; i >= 0; i-- {
		redaction := result.Redactions[i]
		adjustedStart := redaction.Start + offset
		adjustedEnd := redaction.End + offset

		if adjustedStart >= 0 && adjustedEnd <= len(result.RedactedText) {
			result.RedactedText = result.RedactedText[:adjustedStart] +
				redaction.Replacement +
				result.RedactedText[adjustedEnd:]

			// Update offset for next redaction
			offset += len(redaction.Replacement) - (redaction.End - redaction.Start)
		}
	}

	if len(result.Redactions) > 0 {
		result.Token = re.generateSecureToken(result)
	}

	return result
}

// RestoreText restores redacted text using a secure token
func (re *RedactionEngine) RestoreText(token string) (string, error) {
	re.mutex.RLock()
	tokenInfo, exists := re.tokens[token]
	re.mutex.RUnlock()

	if !exists {
		return "", fmt.Errorf("invalid or expired token")
	}

	// Check if token has expired
	if time.Now().After(tokenInfo.Expires) {
		return "", fmt.Errorf("token has expired")
	}

	// Decrypt the original text
	originalText, err := re.decryptData(tokenInfo.EncryptedData, tokenInfo.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt token data: %v", err)
	}

	return originalText, nil
}

// generateReplacement generates a replacement string for redacted content
func (re *RedactionEngine) generateReplacement(redactionType RedactionType, original string) string {
	switch redactionType {
	case TypeEmail:
		return "[EMAIL_REDACTED]"
	case TypePhone:
		return "[PHONE_REDACTED]"
	case TypeCreditCard:
		return "[CREDIT_CARD_REDACTED]"
	case TypeSSN:
		return "[SSN_REDACTED]"
	case TypeAddress:
		return "[ADDRESS_REDACTED]"
	case TypeName:
		return "[NAME_REDACTED]"
	case TypeIPAddress:
		return "[IP_ADDRESS_REDACTED]"
	case TypeDate:
		return "[DATE_REDACTED]"
	case TypeTime:
		return "[TIME_REDACTED]"
	case TypeLink:
		return "[LINK_REDACTED]"
	case TypeZipCode:
		return "[ZIP_CODE_REDACTED]"
	case TypePoBox:
		return "[PO_BOX_REDACTED]"
	case TypeBTCAddress:
		return "[BTC_ADDRESS_REDACTED]"
	case TypeMD5Hex:
		return "[MD5_HASH_REDACTED]"
	case TypeSHA1Hex:
		return "[SHA1_HASH_REDACTED]"
	case TypeSHA256Hex:
		return "[SHA256_HASH_REDACTED]"
	case TypeGUID:
		return "[GUID_REDACTED]"
	case TypeISBN:
		return "[ISBN_REDACTED]"
	case TypeMACAddress:
		return "[MAC_ADDRESS_REDACTED]"
	case TypeIBAN:
		return "[IBAN_REDACTED]"
	case TypeGitRepo:
		return "[GIT_REPO_REDACTED]"
	default:
		return "[REDACTED]"
	}
}

// extractContext extracts context around the redacted content
func (re *RedactionEngine) extractContext(text string, start, end int) string {
	contextStart := max(0, start-20)
	contextEnd := min(len(text), end+20)
	return text[contextStart:contextEnd]
}

// generateSecureToken generates a cryptographically secure token for reversible redaction
func (re *RedactionEngine) generateSecureToken(result *RedactionResult) string {
	// Generate random token ID
	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	// Encrypt the original text
	nonce := make([]byte, 12) // 96-bit nonce for GCM
	rand.Read(nonce)
	
	encryptedData, err := re.encryptData(result.OriginalText, nonce)
	if err != nil {
		// Fallback to generating a new token if encryption fails
		return re.generateFallbackToken(result)
	}

	// Store encrypted token information
	tokenInfo := TokenInfo{
		EncryptedData: encryptedData,
		RedactionType: result.Redactions[0].Type, // Store first redaction type
		Created:       time.Now(),
		Expires:       time.Now().Add(24 * time.Hour), // Token expires in 24 hours
		KeyVersion:    re.keyVersion,
		Nonce:         nonce,
	}

	re.mutex.Lock()
	re.tokens[token] = tokenInfo
	re.mutex.Unlock()

	return token
}

// encryptData encrypts data using AES-GCM with the master key
func (re *RedactionEngine) encryptData(plaintext string, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(re.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return ciphertext, nil
}

// decryptData decrypts data using AES-GCM with the master key
func (re *RedactionEngine) decryptData(ciphertext []byte, nonce []byte) (string, error) {
	block, err := aes.NewCipher(re.masterKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// generateFallbackToken generates a fallback token if encryption fails
func (re *RedactionEngine) generateFallbackToken(result *RedactionResult) string {
	// Generate random token
	bytes := make([]byte, 16)
	rand.Read(bytes)
	token := hex.EncodeToString(bytes)

	// Store unencrypted as fallback (not recommended for production)
	tokenInfo := TokenInfo{
		EncryptedData: []byte(result.OriginalText), // Store as plaintext fallback
		RedactionType: result.Redactions[0].Type,
		Created:       time.Now(),
		Expires:       time.Now().Add(24 * time.Hour),
		KeyVersion:    0, // Indicates unencrypted
		Nonce:         nil,
	}

	re.mutex.Lock()
	re.tokens[token] = tokenInfo
	re.mutex.Unlock()

	return token
}

// GetRedactionStats returns statistics about redaction operations
func (re *RedactionEngine) GetRedactionStats() map[string]interface{} {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_tokens"] = len(re.tokens)
	stats["active_patterns"] = len(re.patterns)
	stats["context_patterns"] = len(re.contextPatterns)
	stats["key_version"] = re.keyVersion

	// Count tokens by type
	typeCounts := make(map[RedactionType]int)
	encryptedCount := 0
	
	for _, tokenInfo := range re.tokens {
		typeCounts[tokenInfo.RedactionType]++
		if tokenInfo.KeyVersion > 0 {
			encryptedCount++
		}
	}
	
	stats["tokens_by_type"] = typeCounts
	stats["encrypted_tokens"] = encryptedCount
	stats["unencrypted_tokens"] = len(re.tokens) - encryptedCount

	return stats
}

// CleanupExpiredTokens removes expired tokens and securely clears memory
func (re *RedactionEngine) CleanupExpiredTokens() int {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	now := time.Now()
	removed := 0

	for token, tokenInfo := range re.tokens {
		if now.After(tokenInfo.Expires) {
			// Securely clear encrypted data before deletion
			for i := range tokenInfo.EncryptedData {
				tokenInfo.EncryptedData[i] = 0
			}
			for i := range tokenInfo.Nonce {
				tokenInfo.Nonce[i] = 0
			}
			
			delete(re.tokens, token)
			removed++
		}
	}

	return removed
}

// RotateKeys rotates the encryption keys (for enhanced security)
func (re *RedactionEngine) RotateKeys() error {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	// Generate new master key
	salt := make([]byte, 32)
	rand.Read(salt)
	
	passphrase := fmt.Sprintf("redactly-master-key-v%d", re.keyVersion+1)
	newMasterKey := pbkdf2.Key([]byte(passphrase), salt, 10000, 32, sha256.New)

	// In a production system, you would:
	// 1. Re-encrypt all existing tokens with the new key
	// 2. Store old keys for a transition period
	// 3. Integrate with a proper Key Management Service (KMS)
	
	re.masterKey = newMasterKey
	re.keyVersion++

	return nil
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
