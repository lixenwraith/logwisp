// FILE: logwisp/src/internal/filter/filter_test.go
package filter

import (
	"logwisp/src/internal/config"
	"logwisp/src/internal/core"
	"testing"

	"github.com/lixenwraith/log"
	"github.com/stretchr/testify/assert"
)

func newTestLogger() *log.Logger {
	return log.NewLogger()
}

func TestNewFilter(t *testing.T) {
	logger := newTestLogger()

	t.Run("SuccessWithDefaults", func(t *testing.T) {
		cfg := config.FilterConfig{Patterns: []string{"test"}}
		f, err := NewFilter(cfg, logger)
		assert.NoError(t, err)
		assert.NotNil(t, f)
		assert.Equal(t, config.FilterTypeInclude, f.config.Type)
		assert.Equal(t, config.FilterLogicOr, f.config.Logic)
	})

	t.Run("SuccessWithCustomConfig", func(t *testing.T) {
		cfg := config.FilterConfig{
			Type:     config.FilterTypeExclude,
			Logic:    config.FilterLogicAnd,
			Patterns: []string{"test", "pattern"},
		}
		f, err := NewFilter(cfg, logger)
		assert.NoError(t, err)
		assert.NotNil(t, f)
		assert.Equal(t, config.FilterTypeExclude, f.config.Type)
		assert.Equal(t, config.FilterLogicAnd, f.config.Logic)
		assert.Len(t, f.patterns, 2)
	})

	t.Run("ErrorInvalidRegex", func(t *testing.T) {
		cfg := config.FilterConfig{Patterns: []string{"["}}
		f, err := NewFilter(cfg, logger)
		assert.Error(t, err)
		assert.Nil(t, f)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})
}

func TestFilter_Apply(t *testing.T) {
	logger := newTestLogger()

	testCases := []struct {
		name     string
		cfg      config.FilterConfig
		entry    core.LogEntry
		expected bool
	}{
		// Include OR logic
		{
			name:     "IncludeOR_MatchOne",
			cfg:      config.FilterConfig{Type: config.FilterTypeInclude, Logic: config.FilterLogicOr, Patterns: []string{"apple", "banana"}},
			entry:    core.LogEntry{Message: "this is an apple"},
			expected: true,
		},
		{
			name:     "IncludeOR_NoMatch",
			cfg:      config.FilterConfig{Type: config.FilterTypeInclude, Logic: config.FilterLogicOr, Patterns: []string{"apple", "banana"}},
			entry:    core.LogEntry{Message: "this is a pear"},
			expected: false,
		},
		// Include AND logic
		{
			name:     "IncludeAND_MatchAll",
			cfg:      config.FilterConfig{Type: config.FilterTypeInclude, Logic: config.FilterLogicAnd, Patterns: []string{"apple", "doctor"}},
			entry:    core.LogEntry{Message: "an apple keeps the doctor away"},
			expected: true,
		},
		{
			name:     "IncludeAND_MatchOne",
			cfg:      config.FilterConfig{Type: config.FilterTypeInclude, Logic: config.FilterLogicAnd, Patterns: []string{"apple", "doctor"}},
			entry:    core.LogEntry{Message: "this is an apple"},
			expected: false,
		},
		// Exclude OR logic
		{
			name:     "ExcludeOR_MatchOne",
			cfg:      config.FilterConfig{Type: config.FilterTypeExclude, Logic: config.FilterLogicOr, Patterns: []string{"error", "fatal"}},
			entry:    core.LogEntry{Message: "this is an error"},
			expected: false,
		},
		{
			name:     "ExcludeOR_NoMatch",
			cfg:      config.FilterConfig{Type: config.FilterTypeExclude, Logic: config.FilterLogicOr, Patterns: []string{"error", "fatal"}},
			entry:    core.LogEntry{Message: "this is a warning"},
			expected: true,
		},
		// Exclude AND logic
		{
			name:     "ExcludeAND_MatchAll",
			cfg:      config.FilterConfig{Type: config.FilterTypeExclude, Logic: config.FilterLogicAnd, Patterns: []string{"critical", "database"}},
			entry:    core.LogEntry{Message: "critical error in database"},
			expected: false,
		},
		{
			name:     "ExcludeAND_MatchOne",
			cfg:      config.FilterConfig{Type: config.FilterTypeExclude, Logic: config.FilterLogicAnd, Patterns: []string{"critical", "database"}},
			entry:    core.LogEntry{Message: "critical error in app"},
			expected: true,
		},
		// Edge Cases
		{
			name:     "NoPatterns",
			cfg:      config.FilterConfig{Type: config.FilterTypeInclude, Patterns: []string{}},
			entry:    core.LogEntry{Message: "any message"},
			expected: true,
		},
		{
			name:     "EmptyEntry_NoPatterns",
			cfg:      config.FilterConfig{Patterns: []string{}},
			entry:    core.LogEntry{},
			expected: true,
		},
		{
			name:     "EmptyEntry_DoesNotMatchSpace",
			cfg:      config.FilterConfig{Type: config.FilterTypeInclude, Patterns: []string{" "}},
			entry:    core.LogEntry{Level: "", Source: "", Message: ""},
			expected: false, // CORRECTED: An empty entry results in an empty string, which doesn't match a space.
		},
		{
			name:     "MatchOnLevel",
			cfg:      config.FilterConfig{Type: config.FilterTypeInclude, Patterns: []string{"ERROR"}},
			entry:    core.LogEntry{Level: "ERROR", Message: "A message"},
			expected: true,
		},
		{
			name:     "MatchOnSource",
			cfg:      config.FilterConfig{Type: config.FilterTypeInclude, Patterns: []string{"database"}},
			entry:    core.LogEntry{Source: "database", Message: "A message"},
			expected: true,
		},
		{
			name:     "MatchOnCombinedFields",
			cfg:      config.FilterConfig{Type: config.FilterTypeInclude, Patterns: []string{"^app ERROR"}},
			entry:    core.LogEntry{Source: "app", Level: "ERROR", Message: "A message"},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := NewFilter(tc.cfg, logger)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, f.Apply(tc.entry))
		})
	}
}