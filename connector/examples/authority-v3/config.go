package main

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// Config carries every runtime knob the example reads from the environment.
// Loaded once at startup via envconfig.Process("APP", &cfg); all variables
// share the APP_ prefix.
//
// Every field has a default so APP_* may be omitted in development; in
// production deployers should at minimum override APP_API_KEY.
// envconfig note: the explicit `envconfig:"NAME"` tag is intentionally not
// used — with a tag set, envconfig also consults the bare un-prefixed env
// var as a fallback, which is surprising (see the secret-v1 example).
// `split_words:"true"` produces SNAKE_CASE names for multi-word fields.
type Config struct {
	Addr         string        `default:":8080"`
	LogLevel     string        `split_words:"true" default:"INFO"`
	StrictDecode bool          `split_words:"true" default:"false"`
	CaName       string        `split_words:"true" default:"demo-ca"`
	ApiKey       string        `split_words:"true" default:"changeme"`
	AsyncIssue   bool          `split_words:"true" default:"false"`
	AsyncDelay   time.Duration `split_words:"true" default:"2s"`
}

// LoadConfig reads APP_* environment variables into a Config.
func LoadConfig() (*Config, error) {
	var c Config
	if err := envconfig.Process("APP", &c); err != nil {
		return nil, err
	}
	return &c, nil
}
