package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/censgate/redact/config"
	"github.com/censgate/redact/pkg/redaction"
	"github.com/spf13/cobra"
)

var (
	inputFile       string
	outputFile      string
	outputFormat    string
	enableTypes     []string
	disableTypes    []string
	showRedactStats bool
	batchMode       bool
)

// redactCmd represents the redact command
var redactCmd = &cobra.Command{
	Use:   "redact [text]",
	Short: "Redact PII/PHI from text input",
	Long: `Redact personally identifiable information (PII) and protected health 
information (PHI) from text input. Supports multiple input sources and output formats.

Examples:
  # Redact text from command line
  redactctl redact "Contact John Doe at john@example.com or 555-123-4567"
  
  # Redact from file
  redactctl redact --input document.txt --output redacted.txt
  
  # Redact from stdin with JSON output
  echo "SSN: 123-45-6789" | redactctl redact --format json
  
  # Show redaction statistics
  redactctl redact --input data.txt --stats`,
	Run: func(_ *cobra.Command, args []string) {
		runRedact(args)
	},
}

func init() {
	rootCmd.AddCommand(redactCmd)

	// Input/Output flags
	redactCmd.Flags().StringVarP(&inputFile, "input", "i", "", "input file (default: stdin)")
	redactCmd.Flags().StringVarP(&outputFile, "output", "o", "", "output file (default: stdout)")
	redactCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "output format (text, json, yaml)")

	// Redaction control flags
	redactCmd.Flags().StringSliceVar(&enableTypes, "enable", []string{}, "enable specific redaction types")
	redactCmd.Flags().StringSliceVar(&disableTypes, "disable", []string{}, "disable specific redaction types")
	redactCmd.Flags().BoolVar(&showRedactStats, "stats", false, "show redaction statistics")
	redactCmd.Flags().BoolVar(&batchMode, "batch", false, "process input in batch mode")
}

func runRedact(args []string) {
	// Load configuration
	cfg, err := config.LoadConfig(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Initialize redaction engine
	engine := redaction.NewRedactionEngine()

	// Configure enabled types based on flags and config
	if len(enableTypes) > 0 {
		// Use only explicitly enabled types
		for _, redType := range enableTypes {
			// Note: This is a placeholder - in a real implementation we'd have a way to enable/disable specific types
			fmt.Fprintf(os.Stderr, "Note: Explicitly enabling redaction type: %s\n", redType)
		}
	}

	// Get input text
	var inputText string
	if len(args) > 0 {
		// Text provided as command line argument
		inputText = strings.Join(args, " ")
	} else if inputFile != "" {
		// Read from file
		data, err := os.ReadFile(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
			os.Exit(1)
		}
		inputText = string(data)
	} else {
		// Read from stdin
		if batchMode {
			inputText = readBatchInput()
		} else {
			inputText = readStdinInput()
		}
	}

	// Perform redaction
	result, err := engine.RedactText(context.Background(), &redaction.RedactionRequest{
		Text:       inputText,
		Mode:       redaction.ModeReplace,
		Reversible: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Redaction failed: %v\n", err)
		os.Exit(1)
	}

	// Output results
	if err := outputResults(result, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	// Show statistics if requested
	if showRedactStats {
		printStatistics(result, engine)
	}
}

func readStdinInput() string {
	fmt.Fprintf(os.Stderr, "Reading from stdin (press Ctrl+D when done)...\n")
	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
		os.Exit(1)
	}
	return strings.Join(lines, "\n")
}

func readBatchInput() string {
	var lines []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading batch input: %v\n", err)
		os.Exit(1)
	}
	return strings.Join(lines, "\n")
}

func outputResults(result *redaction.RedactionResult, _ *config.Config) error {
	var output string
	var err error

	switch outputFormat {
	case "json":
		output, err = formatJSON(result)
	case "yaml":
		output, err = formatYAML(result)
	default: // text
		output = result.RedactedText
	}

	if err != nil {
		return err
	}

	// Write to output
	if outputFile != "" {
		return os.WriteFile(outputFile, []byte(output), 0644)
	}
	fmt.Print(output)
	if outputFormat == "text" {
		fmt.Println() // Add newline for text output
	}

	return nil
}

func formatJSON(result *redaction.RedactionResult) (string, error) {
	// Simple JSON formatting - could use encoding/json for more complex formatting
	return fmt.Sprintf(`{
  "original_text": %q,
  "redacted_text": %q,
  "token": %q,
  "redaction_count": %d,
  "redactions": [
%s  ]
}`, result.OriginalText, result.RedactedText, result.Token, len(result.Redactions), formatRedactionsJSON(result.Redactions)), nil
}

func formatYAML(result *redaction.RedactionResult) (string, error) {
	return fmt.Sprintf(`original_text: %q
redacted_text: %q
token: %q
redaction_count: %d
redactions:
%s`, result.OriginalText, result.RedactedText, result.Token, len(result.Redactions), formatRedactionsYAML(result.Redactions)), nil
}

func formatRedactionsJSON(redactions []redaction.Redaction) string {
	var parts []string
	for _, r := range redactions {
		parts = append(parts, fmt.Sprintf(`    {
      "type": %q,
      "original": %q,
      "replacement": %q,
      "start": %d,
      "end": %d,
      "confidence": %.2f
    }`, r.Type, r.Original, r.Replacement, r.Start, r.End, r.Confidence))
	}
	return strings.Join(parts, ",\n")
}

func formatRedactionsYAML(redactions []redaction.Redaction) string {
	var parts []string
	for _, r := range redactions {
		parts = append(parts, fmt.Sprintf(`  - type: %q
    original: %q
    replacement: %q
    start: %d
    end: %d
    confidence: %.2f`, r.Type, r.Original, r.Replacement, r.Start, r.End, r.Confidence))
	}
	return strings.Join(parts, "\n")
}

func printStatistics(result *redaction.RedactionResult, engine *redaction.RedactionEngine) {
	fmt.Fprintf(os.Stderr, "\n📊 Redaction Statistics:\n")
	fmt.Fprintf(os.Stderr, "========================\n")
	fmt.Fprintf(os.Stderr, "Total redactions: %d\n", len(result.Redactions))
	fmt.Fprintf(os.Stderr, "Token generated: %s\n", result.Token)

	// Group by type
	typeCount := make(map[redaction.RedactionType]int)
	for _, r := range result.Redactions {
		typeCount[r.Type]++
	}

	if len(typeCount) > 0 {
		fmt.Fprintf(os.Stderr, "\nBy type:\n")
		for rType, count := range typeCount {
			fmt.Fprintf(os.Stderr, "  %s: %d\n", rType, count)
		}
	}

	// Engine statistics
	stats := engine.GetRedactionStats()
	fmt.Fprintf(os.Stderr, "\nEngine stats:\n")
	fmt.Fprintf(os.Stderr, "  Active patterns: %v\n", stats["active_patterns"])
	fmt.Fprintf(os.Stderr, "  Total tokens: %v\n", stats["total_tokens"])
}
