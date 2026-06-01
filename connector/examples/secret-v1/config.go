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
type Config struct {
	Addr         string `envconfig:"ADDR"          default:":8080"`
	LogLevel     string `envconfig:"LOG_LEVEL"     default:"INFO"`
	StrictDecode bool   `envconfig:"STRICT_DECODE" default:"false"`
	Username     string `envconfig:"USERNAME"      default:"admin"`
	Password     string `envconfig:"PASSWORD"      default:"admin"`
}

// LoadConfig reads APP_* environment variables into a Config.
func LoadConfig() (*Config, error) {
	var c Config
	if err := envconfig.Process("APP", &c); err != nil {
		return nil, err
	}
	return &c, nil
}
