package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadJSON reads a JSON config file from path, applies defaults, and validates.
// Returns a ready-to-use Config or a descriptive error.
//
// Example JSON:
//
//	{
//	  "uuid":    "550e8400-e29b-41d4-a716-446655440000",
//	  "server":  "vpn.example.com",
//	  "port":    443
//	}
func LoadJSON(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	var cfg Config
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields() // catch typos early
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config %q: %w", path, err)
	}

	cfg.withDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %q: %w", path, err)
	}
	return &cfg, nil
}

// SaveJSON writes the Config as pretty-printed JSON to path.
// The file is created or truncated. Parent directories must exist.
func (c *Config) SaveJSON(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create config %q: %w", path, err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	return nil
}
