// FILE: logwisp/src/internal/format/json_test.go
package format

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"logwisp/src/internal/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONFormatter_Format(t *testing.T) {
	logger := newTestLogger()
	testTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	entry := core.LogEntry{
		Time:    testTime,
		Source:  "test-app",
		Level:   "INFO",
		Message: "this is a test",
	}

	t.Run("BasicFormatting", func(t *testing.T) {
		formatter, err := NewJSONFormatter(nil, logger)
		require.NoError(t, err)

		output, err := formatter.Format(entry)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(output, &result)
		require.NoError(t, err, "Output should be valid JSON")

		assert.Equal(t, testTime.Format(time.RFC3339Nano), result["timestamp"])
		assert.Equal(t, "INFO", result["level"])
		assert.Equal(t, "test-app", result["source"])
		assert.Equal(t, "this is a test", result["message"])
		assert.True(t, strings.HasSuffix(string(output), "\n"), "Output should end with a newline")
	})

	t.Run("PrettyFormatting", func(t *testing.T) {
		formatter, err := NewJSONFormatter(map[string]any{"pretty": true}, logger)
		require.NoError(t, err)

		output, err := formatter.Format(entry)
		require.NoError(t, err)

		assert.Contains(t, string(output), `  "level": "INFO"`)
		assert.True(t, strings.HasSuffix(string(output), "\n"))
	})

	t.Run("MessageIsJSON", func(t *testing.T) {
		jsonMessageEntry := entry
		jsonMessageEntry.Message = `{"user":"test","request_id":"abc-123"}`
		formatter, err := NewJSONFormatter(nil, logger)
		require.NoError(t, err)

		output, err := formatter.Format(jsonMessageEntry)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(output, &result)
		require.NoError(t, err)

		assert.Equal(t, "test", result["user"])
		assert.Equal(t, "abc-123", result["request_id"])
		_, messageExists := result["message"]
		assert.False(t, messageExists, "message field should not exist when message is merged JSON")
	})

	t.Run("MessageIsJSONWithConflicts", func(t *testing.T) {
		jsonMessageEntry := entry
		jsonMessageEntry.Level = "INFO" // top-level
		jsonMessageEntry.Message = `{"level":"DEBUG","msg":"hello"}`
		formatter, err := NewJSONFormatter(nil, logger)
		require.NoError(t, err)

		output, err := formatter.Format(jsonMessageEntry)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(output, &result)
		require.NoError(t, err)

		assert.Equal(t, "INFO", result["level"], "Top-level LogEntry field should take precedence")
	})

	t.Run("CustomFieldNames", func(t *testing.T) {
		options := map[string]any{"timestamp_field": "@timestamp"}
		formatter, err := NewJSONFormatter(options, logger)
		require.NoError(t, err)

		output, err := formatter.Format(entry)
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(output, &result)
		require.NoError(t, err)

		_, defaultExists := result["timestamp"]
		assert.False(t, defaultExists)
		assert.Equal(t, testTime.Format(time.RFC3339Nano), result["@timestamp"])
	})
}

func TestJSONFormatter_FormatBatch(t *testing.T) {
	logger := newTestLogger()
	formatter, err := NewJSONFormatter(nil, logger)
	require.NoError(t, err)

	entries := []core.LogEntry{
		{Time: time.Now(), Level: "INFO", Message: "First message"},
		{Time: time.Now(), Level: "WARN", Message: "Second message"},
	}

	output, err := formatter.FormatBatch(entries)
	require.NoError(t, err)

	var result []map[string]interface{}
	err = json.Unmarshal(output, &result)
	require.NoError(t, err, "Batch output should be a valid JSON array")
	require.Len(t, result, 2)

	assert.Equal(t, "First message", result[0]["message"])
	assert.Equal(t, "WARN", result[1]["level"])
}