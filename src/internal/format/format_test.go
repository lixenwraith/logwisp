// FILE: logwisp/src/internal/format/format_test.go
package format

import (
	"testing"

	"github.com/lixenwraith/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLogger() *log.Logger {
	return log.NewLogger()
}

func TestNewFormatter(t *testing.T) {
	logger := newTestLogger()

	testCases := []struct {
		name        string
		formatName  string
		expected    string
		expectError bool
	}{
		{
			name:       "JSONFormatter",
			formatName: "json",
			expected:   "json",
		},
		{
			name:       "TextFormatter",
			formatName: "txt",
			expected:   "txt",
		},
		{
			name:       "RawFormatter",
			formatName: "raw",
			expected:   "raw",
		},
		{
			name:       "DefaultToRaw",
			formatName: "",
			expected:   "raw",
		},
		{
			name:        "UnknownFormatter",
			formatName:  "xml",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			formatter, err := NewFormatter(tc.formatName, nil, logger)
			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, formatter)
			} else {
				require.NoError(t, err)
				require.NotNil(t, formatter)
				assert.Equal(t, tc.expected, formatter.Name())
			}
		})
	}
}