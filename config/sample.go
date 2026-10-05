// Package config ships logwisp.toml, the annotated default configuration that
// make install and the packages place and lw config init writes.
package config

import _ "embed"

//go:embed logwisp.toml
var Sample []byte
