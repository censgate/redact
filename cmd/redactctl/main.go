package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	phoneRegex = regexp.MustCompile(`(\+?1?[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})`)
)

func main() {
	fmt.Fprintf(os.Stderr, "Redactly CLI - Simple demonstration redaction tool\n")
	fmt.Fprintf(os.Stderr, "Reading from stdin, writing redacted output to stdout...\n\n")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		redacted := redactLine(line)
		fmt.Println(redacted)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}
}

func redactLine(text string) string {
	// TODO: Implement proper PII/PHI detection
	// TODO: Add reversible tokenization
	// TODO: Add policy-based enforcement
	// TODO: Add reporting functionality
	
	// Simple demo redaction
	result := text
	
	// Redact emails
	result = emailRegex.ReplaceAllString(result, "[EMAIL_REDACTED]")
	
	// Redact phone numbers
	result = phoneRegex.ReplaceAllString(result, "[PHONE_REDACTED]")
	
	// Simple name patterns (basic demo)
	namePatterns := []string{
		"John Doe", "Jane Smith", "Dr. Johnson", "Mr. Anderson", "Ms. Wilson",
	}
	
	for _, pattern := range namePatterns {
		result = strings.ReplaceAll(result, pattern, "[NAME_REDACTED]")
	}
	
	return result
}
