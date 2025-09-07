// Package main provides the redactctl CLI tool for managing redaction engines.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/censgate/redact/config"
	"github.com/censgate/redact/pkg/redaction"
	"github.com/spf13/cobra"
)

var (
	testPattern string
)

// engineCmd represents the engine command
var engineCmd = &cobra.Command{
	Use:   "engine",
	Short: "Manage and inspect the redaction engine",
	Long: `Manage and inspect the redaction engine including patterns, statistics,
token management, and security operations.

This command provides administrative functions for the redaction engine:
- View active patterns and statistics
- Clean up expired tokens
- Rotate encryption keys
- Test custom patterns`,
}

// engineStatsCmd shows engine statistics
var engineStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show redaction engine statistics",
	Long: "Display detailed statistics about the redaction engine including " +
		"active patterns, tokens, and performance metrics.",
	Run: func(_ *cobra.Command, _ []string) {
		runEngineStats()
	},
}

// enginePatternsCmd shows active patterns
var enginePatternsCmd = &cobra.Command{
	Use:   "patterns",
	Short: "List active redaction patterns",
	Long:  "Display all active redaction patterns and their configurations.",
	Run: func(_ *cobra.Command, _ []string) {
		runEnginePatterns()
	},
}

// engineCleanupCmd cleans up expired tokens
var engineCleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up expired redaction tokens",
	Long:  "Remove expired redaction tokens from the engine to free up memory and maintain security.",
	Run: func(_ *cobra.Command, _ []string) {
		runEngineCleanup()
	},
}

// engineRotateCmd rotates encryption keys
var engineRotateCmd = &cobra.Command{
	Use:   "rotate-keys",
	Short: "Rotate encryption keys",
	Long:  "Rotate the master encryption keys used for token encryption. This is a security best practice.",
	Run: func(_ *cobra.Command, _ []string) {
		runEngineRotate()
	},
}

// engineTestCmd tests pattern matching
var engineTestCmd = &cobra.Command{
	Use:   "test [text]",
	Short: "Test pattern matching against text",
	Long:  "Test how the redaction engine would process specific text without actually performing redaction.",
	Args:  cobra.MinimumNArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		runEngineTest(args)
	},
}

func init() {
	rootCmd.AddCommand(engineCmd)

	// Add subcommands
	engineCmd.AddCommand(engineStatsCmd)
	engineCmd.AddCommand(enginePatternsCmd)
	engineCmd.AddCommand(engineCleanupCmd)
	engineCmd.AddCommand(engineRotateCmd)
	engineCmd.AddCommand(engineTestCmd)

	// Flags for test command
	engineTestCmd.Flags().StringVar(&testPattern, "pattern", "", "test specific pattern type")
}

func runEngineStats() {
	cfg, err := config.LoadConfig(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	engine := redaction.NewEngine()
	stats := engine.GetRedactionStats()

	fmt.Println("🔧 Redaction Engine Statistics")
	fmt.Println("===============================")
	fmt.Printf("Active patterns: %v\n", stats["active_patterns"])
	fmt.Printf("Context patterns: %v\n", stats["context_patterns"])
	fmt.Printf("Total tokens: %v\n", stats["total_tokens"])
	fmt.Printf("Encrypted tokens: %v\n", stats["encrypted_tokens"])
	fmt.Printf("Unencrypted tokens: %v\n", stats["unencrypted_tokens"])
	fmt.Printf("Key version: %v\n", stats["key_version"])

	if tokensByType, ok := stats["tokens_by_type"].(map[redaction.Type]int); ok && len(tokensByType) > 0 {
		fmt.Println("\nTokens by type:")
		for rType, count := range tokensByType {
			fmt.Printf("  %s: %d\n", rType, count)
		}
	}

	fmt.Printf("\nConfiguration:\n")
	fmt.Printf("  Confidence threshold: %.2f\n", cfg.Redaction.Engine.ConfidenceThreshold)
	fmt.Printf("  Max tokens: %d\n", cfg.Redaction.Engine.MaxTokens)
	fmt.Printf("  Token expiry: %s\n", cfg.Redaction.Engine.TokenExpiry)
	fmt.Printf("  Context analysis: %v\n", cfg.Redaction.Context.AnalysisEnabled)
}

func runEnginePatterns() {
	fmt.Println("📝 Active Redaction Patterns")
	fmt.Println("=============================")

	// This would require exposing pattern information from the engine
	// For now, show the enabled types from config
	cfg, err := config.LoadConfig(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Enabled pattern types (%d):\n", len(cfg.Redaction.Engine.EnabledTypes))
	for i, pType := range cfg.Redaction.Engine.EnabledTypes {
		fmt.Printf("  %d. %s\n", i+1, pType)
	}

	if cfg.Redaction.Context.AnalysisEnabled {
		fmt.Printf("\nContext domains (%d):\n", len(cfg.Redaction.Context.Domains))
		for i, domain := range cfg.Redaction.Context.Domains {
			fmt.Printf("  %d. %s\n", i+1, domain)
		}
	}
}

func runEngineCleanup() {
	engine := redaction.NewEngine()

	fmt.Println("🧹 Cleaning up expired tokens...")
	removed := engine.CleanupExpiredTokens()
	fmt.Printf("✅ Removed %d expired tokens\n", removed)

	if removed > 0 {
		stats := engine.GetRedactionStats()
		fmt.Printf("Remaining tokens: %v\n", stats["total_tokens"])
	}
}

func runEngineRotate() {
	engine := redaction.NewEngine()

	fmt.Println("🔄 Rotating encryption keys...")
	if err := engine.RotateKeys(); err != nil {
		fmt.Fprintf(os.Stderr, "Error rotating keys: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Keys rotated successfully")
	stats := engine.GetRedactionStats()
	fmt.Printf("New key version: %v\n", stats["key_version"])
}

func runEngineTest(args []string) {
	engine := redaction.NewEngine()
	testText := strings.Join(args, " ")

	fmt.Printf("🧪 Testing redaction on: %q\n", testText)
	fmt.Println("========================================")

	// Perform redaction
	result, err := engine.RedactText(context.Background(), &redaction.Request{
		Text:       testText,
		Mode:       redaction.ModeReplace,
		Reversible: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Redaction failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Original: %s\n", result.OriginalText)
	fmt.Printf("Redacted: %s\n", result.RedactedText)
	fmt.Printf("Token: %s\n", result.Token)
	fmt.Printf("Redaction count: %d\n", len(result.Redactions))

	if len(result.Redactions) > 0 {
		fmt.Println("\nDetected patterns:")
		for i, r := range result.Redactions {
			fmt.Printf("  %d. Type: %s, Original: %q, Confidence: %.2f\n",
				i+1, r.Type, r.Original, r.Confidence)
			if r.Context != "" {
				fmt.Printf("      Context: %s\n", r.Context)
			}
		}
	}

	// Test restoration
	if result.Token != "" {
		fmt.Println("\n🔄 Testing token restoration...")
		restoreResult, err := engine.RestoreText(context.Background(), result.Token)
		if err != nil {
			fmt.Printf("❌ Restoration failed: %v\n", err)
		} else if restoreResult.OriginalText == result.OriginalText {
			fmt.Println("✅ Token restoration successful")
		} else {
			fmt.Println("❌ Token restoration mismatch")
		}
	}
}
