package main

import (
	"github.com/kelseyhightower/envconfig"
)

// Config carries every runtime knob the example reads from the environment.
// Loaded once at startup via envconfig.Process("APP", &cfg); all variables
// share the APP_ prefix.
//
// Every field has a default so APP_* may be omitted in development; in
// production deployers should at minimum override APP_USERNAME and
// APP_PASSWORD to non-default values.
// envconfig note: the explicit `envconfig:"NAME"` tag is intentionally not
// used. With a tag set, envconfig also checks the bare un-prefixed env var
// as a fallback (so `APP_USERNAME` unset + `USERNAME=alice` in the shell
// would pick up the latter — surprising for callers and an actual bug we
// hit during development). Without the tag, envconfig derives the env var
// name from the field name; `split_words:"true"` opt-in produces SNAKE_CASE
// for multi-word fields so we get `APP_LOG_LEVEL` instead of `APP_LOGLEVEL`.
type Config struct {
	Addr         string `default:":8080"`
	LogLevel     string `split_words:"true" default:"INFO"`
	StrictDecode bool   `split_words:"true" default:"false"`
	Username     string `default:"admin"`
	Password     string `default:"admin"`
}

// LoadConfig reads APP_* environment variables into a Config.
func LoadConfig() (*Config, error) {
	var c Config
	if err := envconfig.Process("APP", &c); err != nil {
		return nil, err
	}
	return &c, nil
}
