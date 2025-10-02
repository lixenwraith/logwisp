// FILE: logwisp/src/internal/filter/chain_test.go
package filter

import (
	"testing"

	"logwisp/src/internal/config"
	"logwisp/src/internal/core"

	"github.com/stretchr/testify/assert"
)

func TestNewChain(t *testing.T) {
	logger := newTestLogger()

	t.Run("Success", func(t *testing.T) {
		configs := []config.FilterConfig{
			{Type: config.FilterTypeInclude, Patterns: []string{"apple"}},
			{Type: config.FilterTypeExclude, Patterns: []string{"banana"}},
		}
		chain, err := NewChain(configs, logger)
		assert.NoError(t, err)
		assert.NotNil(t, chain)
		assert.Len(t, chain.filters, 2)
	})

	t.Run("ErrorInvalidRegexInChain", func(t *testing.T) {
		configs := []config.FilterConfig{
			{Patterns: []string{"apple"}},
			{Patterns: []string{"["}},
		}
		chain, err := NewChain(configs, logger)
		assert.Error(t, err)
		assert.Nil(t, chain)
		assert.Contains(t, err.Error(), "filter[1]")
	})
}

func TestChain_Apply(t *testing.T) {
	logger := newTestLogger()
	entry := core.LogEntry{Message: "an apple a day"}

	t.Run("EmptyChain", func(t *testing.T) {
		chain, err := NewChain([]config.FilterConfig{}, logger)
		assert.NoError(t, err)
		assert.True(t, chain.Apply(entry))
	})

	t.Run("AllFiltersPass", func(t *testing.T) {
		configs := []config.FilterConfig{
			{Type: config.FilterTypeInclude, Patterns: []string{"apple"}},
			{Type: config.FilterTypeInclude, Patterns: []string{"day"}},
			{Type: config.FilterTypeExclude, Patterns: []string{"banana"}},
		}
		chain, err := NewChain(configs, logger)
		assert.NoError(t, err)
		assert.True(t, chain.Apply(entry))
	})

	t.Run("OneFilterFails", func(t *testing.T) {
		configs := []config.FilterConfig{
			{Type: config.FilterTypeInclude, Patterns: []string{"apple"}},
			{Type: config.FilterTypeExclude, Patterns: []string{"day"}}, // This one will fail
			{Type: config.FilterTypeInclude, Patterns: []string{"a"}},
		}
		chain, err := NewChain(configs, logger)
		assert.NoError(t, err)
		assert.False(t, chain.Apply(entry))
	})

	t.Run("FirstFilterFails", func(t *testing.T) {
		configs := []config.FilterConfig{
			{Type: config.FilterTypeInclude, Patterns: []string{"banana"}}, // This one will fail
			{Type: config.FilterTypeInclude, Patterns: []string{"apple"}},
		}
		chain, err := NewChain(configs, logger)
		assert.NoError(t, err)
		assert.False(t, chain.Apply(entry))
	})
}