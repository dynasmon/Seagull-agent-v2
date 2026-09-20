//go:build !linux

package dumps_test

import (
	"errors"
	"runtime"
	"testing"

	"github.com/dynasmon/Seagull-agent-v2/internal/platform/dumps"
)

func TestAPlatformThatOffersNoSuchControlSaysSo(t *testing.T) {
	if err := dumps.Withhold(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("withholding the agent's memory on %s returned %v", runtime.GOOS, err)
	}
}
