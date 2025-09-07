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
	token      string
	tokenFile  string
	restoreOut string
)

// restoreCmd represents the restore command
var restoreCmd = &cobra.Command{
	Use:   "restore [token]",
	Short: "Restore original text from redaction token",
	Long: `Restore the original text using a redaction token generated during
the redaction process. Tokens are used for reversible redaction and contain
encrypted references to the original content.

Examples:
  # Restore using token from command line
  redactctl restore abc123def456
  
  # Restore using token from file
  redactctl restore --token-file tokens.txt
  
  # Restore and save to file
  redactctl restore abc123def456 --output original.txt`,
	Args: cobra.MaximumNArgs(1),
	Run: func(_ *cobra.Command, args []string) {
		runRestore(args)
	},
}

func init() {
	rootCmd.AddCommand(restoreCmd)

	// Restore-specific flags
	restoreCmd.Flags().StringVar(&token, "token", "", "redaction token to restore")
	restoreCmd.Flags().StringVar(&tokenFile, "token-file", "", "file containing redaction token")
	restoreCmd.Flags().StringVarP(&restoreOut, "output", "o", "", "output file for restored text (default: stdout)")
}

func runRestore(args []string) {
	// Load configuration
	cfg, err := config.LoadConfig(cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Get token from various sources
	var targetToken string
	if len(args) > 0 {
		targetToken = args[0]
	} else if token != "" {
		targetToken = token
	} else if tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading token file: %v\n", err)
			os.Exit(1)
		}
		targetToken = string(data)
	} else {
		fmt.Fprintf(os.Stderr, "Error: No token provided. Use --token, --token-file, or provide token as argument\n")
		os.Exit(1)
	}

	// Trim whitespace from token
	targetToken = strings.TrimSpace(targetToken)

	// Initialize redaction engine
	engine := redaction.NewEngine()

	// Restore original text
	restoreResult, err := engine.RestoreText(context.Background(), targetToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error restoring text: %v\n", err)
		os.Exit(1)
	}

	// Output restored text
	if restoreOut != "" {
		if err := os.WriteFile(restoreOut, []byte(restoreResult.OriginalText), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Restored text written to: %s\n", restoreOut)
	} else {
		fmt.Print(restoreResult.OriginalText)
	}

	// Log success
	if logLevel == "debug" || cfg.Logging.Level == "debug" {
		fmt.Fprintf(os.Stderr, "Successfully restored %d characters from token: %s\n", len(restoreResult.OriginalText), targetToken)
	}
}
