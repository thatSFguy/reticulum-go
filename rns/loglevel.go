package rns

import (
	"fmt"
	"strings"
)

// LogLevel is the severity of a library log line.
//
// WHY this exists alongside the Printf-only Logger: operators run these
// services under systemd and want the journal quiet by default. The
// complaint that prompted this was a hub where clients announce every
// second; whatever the noisy line turns out to be, an operator should be
// able to say "warnings and above" (`LogLevelMax=warning` in the unit, or
// a config threshold) without patching code. That needs every call site
// to carry a severity, and only the library knows the severity of its
// own lines.
//
// The numeric values match log/slog (-4, 0, 4, 8) so a consumer bridging
// to slog can convert with slog.Level(l) and get the same ordering.
//
// Assignment policy for call sites in this package:
//
//   - LogError: we failed to build or sign our own data. That is a local
//     bug, never something a peer can cause, so it should never be seen.
//   - LogWarn: degraded but recovering, or operator-actionable — an
//     interface down or reconnecting, our own sends failing, a transfer
//     timing out, a queue shedding data, a key-conflicting announce.
//   - LogInfo: lifecycle (link up/down, announce first seen, transfer
//     complete) and protocol errors caused by a peer's packets. Peer
//     garbage is deliberately NOT a warning: it is not actionable, and on
//     a public hub it is attacker-controlled volume — at warn it would
//     defeat the very threshold this type exists for.
//   - LogDebug: per-transfer chatter (ADV/HMU detail, retries, path
//     requests, RPC sent/answered) that is only useful when tracing.
type LogLevel int

const (
	LogDebug LogLevel = -4
	LogInfo  LogLevel = 0
	LogWarn  LogLevel = 4
	LogError LogLevel = 8
)

// String returns the lower-case name used by ParseLogLevel.
func (l LogLevel) String() string {
	switch l {
	case LogDebug:
		return "debug"
	case LogInfo:
		return "info"
	case LogWarn:
		return "warn"
	case LogError:
		return "error"
	}
	return fmt.Sprintf("LogLevel(%d)", int(l))
}

// ParseLogLevel accepts debug, info, warn/warning and error, case
// insensitively. It lives here rather than in each consumer so the three
// services that embed this library spell their config values the same way.
func ParseLogLevel(s string) (LogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LogDebug, nil
	case "info":
		return LogInfo, nil
	case "warn", "warning":
		return LogWarn, nil
	case "error":
		return LogError, nil
	}
	return LogInfo, fmt.Errorf("unknown log level %q (want debug, info, warn or error)", s)
}

// LeveledLogger is optionally implemented by a Logger that wants each
// line's severity. The library type-asserts for it on every call, so
// existing Printf-only loggers keep working unchanged and still receive
// every line — this is additive API, not a breaking change to Logger.
type LeveledLogger interface {
	Logger
	Logf(level LogLevel, format string, args ...any)
}

// logAt emits one line at the given severity, through Logf when the
// logger supports levels and through Printf otherwise.
func logAt(l Logger, level LogLevel, format string, args ...any) {
	if ll, ok := l.(LeveledLogger); ok {
		ll.Logf(level, format, args...)
		return
	}
	l.Printf(format, args...)
}
