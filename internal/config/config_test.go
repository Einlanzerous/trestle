package config

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const goodHash = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"

// setEnv clears every TRESTLE_ variable config.go reads, then applies kv.
func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	src, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`os\.Getenv\("(TRESTLE_[A-Z_]+)"\)`).FindAllStringSubmatch(string(src), -1) {
		t.Setenv(m[1], "")
	}
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func required() map[string]string {
	return map[string]string{
		"TRESTLE_DATA_DIR":        "/data",
		"TRESTLE_PUBLIC_BASE_URL": "https://media.example.test",
		"TRESTLE_TOKENS":          "agent=" + goodHash,
	}
}

func TestLoadDefaults(t *testing.T) {
	setEnv(t, required())
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":4014" || c.MaxImageBytes != 10<<20 || c.MaxVideoBytes != 100<<20 ||
		c.QuotaBytesPerToken != 2<<30 || c.SweepInterval != time.Hour || c.ShutdownGrace != 20*time.Second ||
		c.LogFormat != "json" || len(c.Tokens) != 1 || c.Tokens[0].Name != "agent" {
		t.Fatalf("defaults = %+v", c)
	}
}

func TestLoadRefusalsNameTheVariable(t *testing.T) {
	for variable, value := range map[string]string{
		"TRESTLE_DATA_DIR":              "",
		"TRESTLE_PUBLIC_BASE_URL":       "https://media.example.test/",
		"TRESTLE_TOKENS":                "agent=nothex",
		"TRESTLE_PORT":                  "99999",
		"TRESTLE_MAX_IMAGE_BYTES":       "0",
		"TRESTLE_MAX_VIDEO_BYTES":       "lots",
		"TRESTLE_QUOTA_BYTES_PER_TOKEN": "-1",
		"TRESTLE_SWEEP_INTERVAL":        "hourly",
		"TRESTLE_SHUTDOWN_GRACE":        "0s",
		"TRESTLE_LOG_LEVEL":             "loud",
		"TRESTLE_LOG_FORMAT":            "xml",
	} {
		t.Run(variable, func(t *testing.T) {
			env := required()
			env[variable] = value
			setEnv(t, env)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), variable) {
				t.Fatalf("Load() = %v, want an error naming %s", err, variable)
			}
		})
	}
}

// A value near MaxInt64 would wrap the API's cap-plus-headroom sum negative
// and refuse every upload, so each byte count is bounded.
func TestByteCountsAreBounded(t *testing.T) {
	for _, variable := range []string{"TRESTLE_MAX_IMAGE_BYTES", "TRESTLE_MAX_VIDEO_BYTES", "TRESTLE_QUOTA_BYTES_PER_TOKEN"} {
		t.Run(variable, func(t *testing.T) {
			env := required()
			env[variable] = "9223372036854775000"
			setEnv(t, env)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), variable) {
				t.Fatalf("Load() = %v, want an error naming %s", err, variable)
			}
			env[variable] = "1099511627776"
			setEnv(t, env)
			if _, err := Load(); err != nil {
				t.Fatalf("1 TiB refused: %v", err)
			}
		})
	}
}

func TestPublicBaseURL(t *testing.T) {
	for _, bad := range []string{"media.example.test", "ftp://x", "https://x/path", "https://x?q=1", "https://"} {
		if _, err := parseBaseURL(bad); err == nil {
			t.Errorf("parseBaseURL(%q) accepted", bad)
		}
	}
	if got, err := parseBaseURL("http://127.0.0.1:4014"); err != nil || got != "http://127.0.0.1:4014" {
		t.Errorf("good URL = %q, %v", got, err)
	}
}

func TestParseTokens(t *testing.T) {
	other := strings.Repeat("a", 64)
	toks, err := ParseTokens(" a=" + goodHash + " , b.c-d_e=" + other)
	if err != nil || len(toks) != 2 || toks[1].Name != "b.c-d_e" {
		t.Fatalf("ParseTokens = %+v, %v", toks, err)
	}
	for _, bad := range []string{
		"a=" + goodHash + ",a=" + other, // duplicate name
		"a=" + goodHash + ",b=" + goodHash,
		"=" + goodHash,
		"a b=" + goodHash,
		"a=" + goodHash[:10],
		goodHash,
	} {
		_, err := ParseTokens(bad)
		if err == nil {
			t.Errorf("ParseTokens(%q) accepted", bad)
			continue
		}
		if strings.Contains(err.Error(), goodHash) {
			t.Errorf("ParseTokens error echoes a hash: %v", err)
		}
	}
}
