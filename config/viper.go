package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Redaction  RedactionConfig  `mapstructure:"redaction"`
	Encryption EncryptionConfig `mapstructure:"encryption"`
	Logging    LoggingConfig    `mapstructure:"logging"`
	CLI        CLIConfig        `mapstructure:"cli"`
}

type RedactionConfig struct {
	Engine  EngineConfig  `mapstructure:"engine"`
	Context ContextConfig `mapstructure:"context"`
}

type EngineConfig struct {
	EnabledTypes        []string      `mapstructure:"enabled_types"`
	ConfidenceThreshold float64       `mapstructure:"confidence_threshold"`
	MaxTokens           int           `mapstructure:"max_tokens"`
	TokenExpiry         time.Duration `mapstructure:"token_expiry"`
}

type ContextConfig struct {
	AnalysisEnabled bool     `mapstructure:"analysis_enabled"`
	Domains         []string `mapstructure:"domains"`
}

type EncryptionConfig struct {
	KeyRotationInterval time.Duration `mapstructure:"key_rotation_interval"`
	PBKDF2Iterations    int           `mapstructure:"pbkdf2_iterations"`
	KeyVersion          int           `mapstructure:"key_version"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
	Output string `mapstructure:"output"`
}

type CLIConfig struct {
	DefaultFormat   string `mapstructure:"default_format"`
	BatchSize       int    `mapstructure:"batch_size"`
	ProgressEnabled bool   `mapstructure:"progress_enabled"`
}

// LoadConfig loads configuration from multiple sources
func LoadConfig(configFile string) (*Config, error) {
	v := viper.New()

	// Set config file name and paths
	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("./config")
		v.AddConfigPath(".")
	}

	// Environment variable configuration
	v.SetEnvPrefix("REDACT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Set defaults
	setDefaults(v)

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, using defaults and env vars
	}

	// Unmarshal config
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Redaction engine defaults
	v.SetDefault("redaction.engine.enabled_types", []string{
		"email", "phone", "ssn", "credit_card", "name", "address",
		"date_time", "link", "zip_code", "po_box", "btc_address",
		"md5_hex", "sha1_hex", "sha256_hex", "guid", "isbn", "mac_address", "iban", "git_repo",
	})
	v.SetDefault("redaction.engine.confidence_threshold", 0.8)
	v.SetDefault("redaction.engine.max_tokens", 1000)
	v.SetDefault("redaction.engine.token_expiry", "24h")

	// Context analysis defaults
	v.SetDefault("redaction.context.analysis_enabled", true)
	v.SetDefault("redaction.context.domains", []string{"medical", "financial", "legal", "general"})

	// Encryption defaults
	v.SetDefault("encryption.key_rotation_interval", "30d")
	v.SetDefault("encryption.pbkdf2_iterations", 10000)
	v.SetDefault("encryption.key_version", 1)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")

	// CLI defaults
	v.SetDefault("cli.default_format", "text")
	v.SetDefault("cli.batch_size", 100)
	v.SetDefault("cli.progress_enabled", true)
}

// GetViperInstance returns a configured viper instance for advanced usage
func GetViperInstance(configFile string) (*viper.Viper, error) {
	v := viper.New()

	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath("./config")
		v.AddConfigPath(".")
	}

	v.SetEnvPrefix("REDACT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	return v, nil
}

