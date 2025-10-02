// FILE: logwisp/src/internal/format/raw_test.go
package format

import (
	"testing"
	"time"

	"logwisp/src/internal/core"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRawFormatter_Format(t *testing.T) {
	logger := newTestLogger()
	formatter, err := NewRawFormatter(nil, logger)
	require.NoError(t, err)

	entry := core.LogEntry{
		Time:    time.Now(),
		Message: "This is a raw log line.",
	}

	output, err := formatter.Format(entry)
	require.NoError(t, err)

	expected := "This is a raw log line.\n"
	assert.Equal(t, expected, string(output))
}