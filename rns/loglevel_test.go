package rns

import (
	"fmt"
	"testing"
	"time"
)

type levelRecord struct {
	level LogLevel
	line  string
}

type recordingLeveledLogger struct{ got []levelRecord }

func (r *recordingLeveledLogger) Printf(format string, args ...any) {
	r.got = append(r.got, levelRecord{level: -100, line: fmt.Sprintf(format, args...)})
}

func (r *recordingLeveledLogger) Logf(level LogLevel, format string, args ...any) {
	r.got = append(r.got, levelRecord{level: level, line: fmt.Sprintf(format, args...)})
}

type recordingPlainLogger struct{ got []string }

func (r *recordingPlainLogger) Printf(format string, args ...any) {
	r.got = append(r.got, fmt.Sprintf(format, args...))
}

func TestParseLogLevel(t *testing.T) {
	cases := map[string]LogLevel{
		"debug": LogDebug, "INFO": LogInfo, "warn": LogWarn,
		"warning": LogWarn, " Error ": LogError,
	}
	for in, want := range cases {
		got, err := ParseLogLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLogLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseLogLevel("verbose"); err == nil {
		t.Error("ParseLogLevel(verbose) accepted an unknown level")
	}
	for _, l := range []LogLevel{LogDebug, LogInfo, LogWarn, LogError} {
		if back, err := ParseLogLevel(l.String()); err != nil || back != l {
			t.Errorf("String/Parse round trip for %d: %q -> %v, %v", int(l), l.String(), back, err)
		}
	}
}

// A LeveledLogger receives the severity; a Printf-only logger — what every
// consumer passed before levels existed — still receives every line.
func TestLogAtRoutesByCapability(t *testing.T) {
	ll := &recordingLeveledLogger{}
	logAt(ll, LogWarn, "x=%d", 1)
	if len(ll.got) != 1 || ll.got[0].level != LogWarn || ll.got[0].line != "x=1" {
		t.Fatalf("leveled logger got %+v", ll.got)
	}

	pl := &recordingPlainLogger{}
	logAt(pl, LogDebug, "y=%d", 2)
	if len(pl.got) != 1 || pl.got[0] != "y=2" {
		t.Fatalf("plain logger got %+v", pl.got)
	}
}

// The suppression summary must carry the category's level, or a warn
// threshold would hide the info lines yet still print their summaries.
func TestRateLimitedLoggerCarriesLevel(t *testing.T) {
	ll := &recordingLeveledLogger{}
	rl := newRateLimitedLogger(ll)
	rl.burst = 1
	rl.interval = time.Millisecond

	rl.Limited(LogInfo, "cat", "first")
	rl.Limited(LogInfo, "cat", "suppressed")
	time.Sleep(5 * time.Millisecond)
	rl.Limited(LogInfo, "cat", "after window")

	if len(ll.got) != 3 {
		t.Fatalf("want first, summary, after-window; got %+v", ll.got)
	}
	for _, r := range ll.got {
		if r.level != LogInfo {
			t.Errorf("line %q at %v, want info", r.line, r.level)
		}
	}
}
