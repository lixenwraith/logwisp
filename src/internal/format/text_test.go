// FILE: logwisp/src/internal/format/text_test.go
package format

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"logwisp/src/internal/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTextFormatter(t *testing.T) {
	logger := newTestLogger()
	t.Run("InvalidTemplate", func(t *testing.T) {
		options := map[string]any{"template": "{{ .Timestamp | InvalidFunc }}"}
		_, err := NewTextFormatter(options, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid template")
	})
}

func TestTextFormatter_Format(t *testing.T) {
	logger := newTestLogger()
	testTime := time.Date(2023, 10, 27, 10, 30, 0, 0, time.UTC)
	entry := core.LogEntry{
		Time:    testTime,
		Source:  "api",
		Level:   "WARN",
		Message: "rate limit exceeded",
	}

	t.Run("DefaultTemplate", func(t *testing.T) {
		formatter, err := NewTextFormatter(nil, logger)
		require.NoError(t, err)

		output, err := formatter.Format(entry)
		require.NoError(t, err)

		expected := fmt.Sprintf("[%s] [WARN] api - rate limit exceeded\n", testTime.Format(time.RFC3339))
		assert.Equal(t, expected, string(output))
	})

	t.Run("CustomTemplate", func(t *testing.T) {
		options := map[string]any{"template": "{{.Level}}:{{.Source}}:{{.Message}}"}
		formatter, err := NewTextFormatter(options, logger)
		require.NoError(t, err)

		output, err := formatter.Format(entry)
		require.NoError(t, err)

		expected := "WARN:api:rate limit exceeded\n"
		assert.Equal(t, expected, string(output))
	})

	t.Run("CustomTimestampFormat", func(t *testing.T) {
		options := map[string]any{"timestamp_format": "2006-01-02"}
		formatter, err := NewTextFormatter(options, logger)
		require.NoError(t, err)

		output, err := formatter.Format(entry)
		require.NoError(t, err)

		assert.True(t, strings.HasPrefix(string(output), "[2023-10-27]"))
	})

	t.Run("EmptyLevelDefaultsToInfo", func(t *testing.T) {
		emptyLevelEntry := entry
		emptyLevelEntry.Level = ""
		formatter, err := NewTextFormatter(nil, logger)
		require.NoError(t, err)

		output, err := formatter.Format(emptyLevelEntry)
		require.NoError(t, err)

		assert.Contains(t, string(output), "[INFO]")
	})
}