package main

import (
	"strings"

	lconfig "github.com/lixenwraith/config"
)

// collectConfigChanges folds the queued hints into one snapshot read. Error
// events describe an unpublished edit and must not restart a healthy service.
func collectConfigChanges(first string, changes <-chan string) bool {
	changed := reportConfigEvent(first)
	// Bound the drain to the currently queued events so a busy writer cannot
	// starve signal handling. Later events remain queued for the next iteration.
	for remaining := len(changes); remaining > 0; remaining-- {
		select {
		case event, ok := <-changes:
			if !ok {
				return changed
			}
			changed = reportConfigEvent(event) || changed
		default:
			return changed
		}
	}
	return changed
}

func reportConfigEvent(event string) bool {
	if event == lconfig.EventFileDeleted || event == lconfig.EventPermissionsChanged ||
		event == lconfig.EventReloadTimeout || strings.HasPrefix(event, lconfig.EventReloadError+":") {
		logger.Warn("msg", "Configuration update not applied", "event", event, "action", "keeping current service")
		return false
	}
	return event != ""
}
