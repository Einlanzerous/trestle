// Package config loads Trestle's configuration from the environment.
//
// Env-only, TRESTLE_-prefixed. No config files: a service with two places to
// look for a setting has two places for it to be wrong, and the one that is
// not in the compose file is the one nobody checks.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultPort is the next free slot in the estate's 40xx block after
// catenary's 4012/4013; cf-access-guard holds 4020.
const DefaultPort = 4014

const (
	DefaultMaxImageBytes      = 10 << 20
	DefaultMaxVideoBytes      = 100 << 20
	DefaultQuotaBytesPerToken = 2 << 30
	DefaultSweepInterval      = time.Hour
	DefaultShutdownGrace      = 20 * time.Second
)

// Token is one entry of TRESTLE_TOKENS. The service only ever holds the
// digest; the plaintext lives with the consumer, in Signet.
type Token struct {
	Name string
	Hash [sha256.Size]byte
}

// Config is the process-wide configuration. Every field is set from exactly
// one environment variable, so `grep TRESTLE_` over this file is the complete
// list.
type Config struct {
	Addr               string        // TRESTLE_PORT
	DataDir            string        // TRESTLE_DATA_DIR
	PublicBaseURL      string        // TRESTLE_PUBLIC_BASE_URL
	Tokens             []Token       // TRESTLE_TOKENS
	MaxImageBytes      int64         // TRESTLE_MAX_IMAGE_BYTES
	MaxVideoBytes      int64         // TRESTLE_MAX_VIDEO_BYTES
	QuotaBytesPerToken int64         // TRESTLE_QUOTA_BYTES_PER_TOKEN
	SweepInterval      time.Duration // TRESTLE_SWEEP_INTERVAL
	LogLevel           slog.Level    // TRESTLE_LOG_LEVEL
	LogFormat          string        // TRESTLE_LOG_FORMAT
	ShutdownGrace      time.Duration // TRESTLE_SHUTDOWN_GRACE
}

// Load reads the environment and validates it, or returns the first error.
//
// Every failure names the variable. Each os.Getenv call takes a literal name
// because cmd/trestle's usage test scans this file for them to prove the help
// text documents every variable.
func Load() (Config, error) {
	var c Config
	var err error

	port := DefaultPort
	if v := strings.TrimSpace(os.Getenv("TRESTLE_PORT")); v != "" {
		port, err = strconv.Atoi(v)
		if err != nil || port < 1 || port > 65535 {
			return c, fmt.Errorf("config: TRESTLE_PORT %q is not a valid port", v)
		}
	}
	c.Addr = fmt.Sprintf(":%d", port)

	c.DataDir = strings.TrimSpace(os.Getenv("TRESTLE_DATA_DIR"))
	if c.DataDir == "" {
		return c, fmt.Errorf("config: TRESTLE_DATA_DIR is required")
	}

	if c.PublicBaseURL, err = parseBaseURL(os.Getenv("TRESTLE_PUBLIC_BASE_URL")); err != nil {
		return c, err
	}

	if c.Tokens, err = ParseTokens(os.Getenv("TRESTLE_TOKENS")); err != nil {
		return c, err
	}

	if c.MaxImageBytes, err = positiveBytes("TRESTLE_MAX_IMAGE_BYTES", os.Getenv("TRESTLE_MAX_IMAGE_BYTES"), DefaultMaxImageBytes); err != nil {
		return c, err
	}
	if c.MaxVideoBytes, err = positiveBytes("TRESTLE_MAX_VIDEO_BYTES", os.Getenv("TRESTLE_MAX_VIDEO_BYTES"), DefaultMaxVideoBytes); err != nil {
		return c, err
	}
	if c.QuotaBytesPerToken, err = positiveBytes("TRESTLE_QUOTA_BYTES_PER_TOKEN", os.Getenv("TRESTLE_QUOTA_BYTES_PER_TOKEN"), DefaultQuotaBytesPerToken); err != nil {
		return c, err
	}

	if c.SweepInterval, err = positiveDuration("TRESTLE_SWEEP_INTERVAL", os.Getenv("TRESTLE_SWEEP_INTERVAL"), DefaultSweepInterval); err != nil {
		return c, err
	}
	if c.ShutdownGrace, err = positiveDuration("TRESTLE_SHUTDOWN_GRACE", os.Getenv("TRESTLE_SHUTDOWN_GRACE"), DefaultShutdownGrace); err != nil {
		return c, err
	}

	if c.LogLevel, err = parseLevel(os.Getenv("TRESTLE_LOG_LEVEL")); err != nil {
		return c, err
	}
	c.LogFormat = strings.ToLower(strings.TrimSpace(os.Getenv("TRESTLE_LOG_FORMAT")))
	if c.LogFormat == "" {
		c.LogFormat = "json"
	}
	if c.LogFormat != "json" && c.LogFormat != "text" {
		return c, fmt.Errorf("config: TRESTLE_LOG_FORMAT %q is not json or text", c.LogFormat)
	}

	return c, nil
}

// parseBaseURL insists on scheme+host and nothing else, because the upload
// response builds every public URL by appending "/m/…" to it: a trailing
// slash or a path would be baked into URLs that get pasted into tickets.
func parseBaseURL(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", fmt.Errorf("config: TRESTLE_PUBLIC_BASE_URL is required")
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("config: TRESTLE_PUBLIC_BASE_URL %q is not an http(s) URL with a host", v)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("config: TRESTLE_PUBLIC_BASE_URL %q must be scheme and host only, with no path or trailing slash", v)
	}
	return v, nil
}

// ParseTokens parses `name=sha256hex,name=sha256hex,…`.
//
// Names must be unique because the name is the actor in every log line and
// the owner on every record; two consumers sharing one would be
// indistinguishable. Hashes must be unique because one secret mapping to two
// names makes the caller's identity depend on iteration order.
func ParseTokens(raw string) ([]Token, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, fmt.Errorf("config: TRESTLE_TOKENS is required (name=sha256hex, comma-separated; see `trestle token mint`)")
	}
	var out []Token
	names := map[string]bool{}
	hashes := map[[sha256.Size]byte]bool{}
	for i, entry := range strings.Split(v, ",") {
		name, hexHash, ok := strings.Cut(strings.TrimSpace(entry), "=")
		name, hexHash = strings.TrimSpace(name), strings.TrimSpace(hexHash)
		if !ok || !ValidTokenName(name) {
			return nil, fmt.Errorf("config: TRESTLE_TOKENS entry %d is not name=sha256hex with a name of letters, digits, '-', '_' or '.'", i+1)
		}
		var t Token
		t.Name = name
		b, err := hex.DecodeString(hexHash)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("config: TRESTLE_TOKENS entry %q does not carry a 64-character hex SHA-256 (the service holds hashes, not tokens)", name)
		}
		copy(t.Hash[:], b)
		if names[name] {
			return nil, fmt.Errorf("config: TRESTLE_TOKENS names %q twice", name)
		}
		if hashes[t.Hash] {
			return nil, fmt.Errorf("config: TRESTLE_TOKENS entry %q repeats another entry's hash", name)
		}
		names[name], hashes[t.Hash] = true, true
		out = append(out, t)
	}
	return out, nil
}

// ValidTokenName keeps names to a charset that survives the TRESTLE_TOKENS
// syntax, a JSON record and a log line without quoting surprises.
func ValidTokenName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

func positiveBytes(name, raw string, def int64) (int64, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("config: %s %q is not a positive byte count", name, v)
	}
	return n, nil
}

func positiveDuration(name, raw string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("config: %s %q is not a positive duration", name, v)
	}
	return d, nil
}

func parseLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("config: TRESTLE_LOG_LEVEL %q is not debug/info/warn/error", raw)
	}
}

// Logger builds the process logger: structured, always. JSON by default
// because that is what Dozzle and Datadog parse; text is for a terminal.
func (c Config) Logger(w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: c.LogLevel}
	if c.LogFormat == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}
