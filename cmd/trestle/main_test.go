package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Einlanzerous/trestle/internal/config"
	"github.com/Einlanzerous/trestle/internal/index"
)

func TestRunRejectsUnknownSubcommand(t *testing.T) {
	if err := run([]string{"nope"}); err == nil {
		t.Fatal("unknown subcommand accepted")
	}
}

func TestBuildVersionAndCommit(t *testing.T) {
	v, c := version, commit
	t.Cleanup(func() { version, commit = v, c })

	version, commit = "", ""
	if buildVersion() != "dev" || buildCommit() != "" {
		t.Fatalf("unstamped = %q %q", buildVersion(), buildCommit())
	}
	version, commit = "0.1.0", strings.Repeat("a1", 20)
	if buildVersion() != "0.1.0" || buildCommit() != commit {
		t.Fatalf("stamped = %q %q", buildVersion(), buildCommit())
	}
	for _, bad := range []string{"abc1234", strings.Repeat("A1", 20), strings.Repeat("zz", 20)} {
		commit = bad
		if buildCommit() != "" {
			t.Errorf("buildCommit accepted %q", bad)
		}
	}
}

// TestUsageNamesEveryEnvVar scans config.go for the variables Load reads,
// so a variable added there without a line in the help text fails here:
// env-only configuration is documented or it is folklore.
func TestUsageNamesEveryEnvVar(t *testing.T) {
	src, err := os.ReadFile("../../internal/config/config.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, m := range regexp.MustCompile(`os\.Getenv\("([A-Z_]+)"\)`).FindAllStringSubmatch(string(src), -1) {
		seen[m[1]] = true
	}
	if len(seen) < 11 {
		t.Fatalf("found only %d os.Getenv calls in config.go; the scan is broken", len(seen))
	}
	read := make([]string, 0, len(seen))
	for v := range seen {
		read = append(read, v)
	}
	sort.Strings(read)
	got := usageText()
	for _, v := range append(read, "TRESTLE_URL", "TRESTLE_TOKEN") {
		if !strings.Contains(got, v) {
			t.Errorf("%s is read and `trestle --help` does not name it", v)
		}
	}
}

func TestTokenMintAndHash(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := runToken([]string{"mint", "--name", "catenary-agent"}, nil, &out, &errOut); err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(out.String())
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) != 32 || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("stdout %q is not exactly one base64url 32-byte token", out.String())
	}
	sum := sha256.Sum256([]byte(tok))
	if errOut.String() != "catenary-agent="+hex.EncodeToString(sum[:])+"\n" {
		t.Fatalf("stderr = %q", errOut.String())
	}
	if strings.Contains(errOut.String(), tok) {
		t.Fatal("the plaintext reached stderr")
	}
	if _, err := config.ParseTokens(strings.TrimSpace(errOut.String())); err != nil {
		t.Fatalf("mint's stderr line is not a valid TRESTLE_TOKENS entry: %v", err)
	}

	var h bytes.Buffer
	if err := runToken([]string{"hash"}, strings.NewReader(tok+"\n"), &h, nil); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(h.String()) != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash = %q", h.String())
	}

	if err := runToken([]string{"mint"}, nil, &out, &errOut); err == nil {
		t.Fatal("mint without --name accepted")
	}
	if err := runToken([]string{"mint", "--name", "a=b"}, nil, &out, &errOut); err == nil {
		t.Fatal("mint accepted a name that breaks TRESTLE_TOKENS syntax")
	}
}

const agentTok = "agent-plaintext-token"

func testDeps(t *testing.T) deps {
	t.Helper()
	sum := sha256.Sum256([]byte(agentTok))
	tokens, err := config.ParseTokens("agent=" + hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		DataDir:            t.TempDir(),
		PublicBaseURL:      "https://media.example.test",
		Tokens:             tokens,
		MaxImageBytes:      1 << 20,
		MaxVideoBytes:      1 << 20,
		QuotaBytesPerToken: 1 << 30,
		SweepInterval:      time.Hour,
		ShutdownGrace:      5 * time.Second,
		LogFormat:          "json",
	}
	d, err := setup(cfg, cfg.Logger(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var png = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00")

func TestUploadClient(t *testing.T) {
	d := testDeps(t)
	srv := httptest.NewServer(d.router)
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "shot.png")
	if err := os.WriteFile(path, png, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(png)
	want := "https://media.example.test/m/" + hex.EncodeToString(sum[:]) + ".png"

	t.Setenv("TRESTLE_URL", srv.URL+"/")
	t.Setenv("TRESTLE_TOKEN", agentTok)
	var out bytes.Buffer
	if err := runUpload([]string{path, "--ttl", "30d"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != want {
		t.Fatalf("upload printed %q, want %q", out.String(), want)
	}
	rec, ok := d.index.Get(hex.EncodeToString(sum[:]), time.Now())
	if !ok || rec.ExpiresAt == nil || rec.ExpiresAt.Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("--ttl 30d not applied: %+v", rec)
	}

	t.Setenv("TRESTLE_TOKEN", "wrong-token")
	err := runUpload([]string{path}, &out)
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("wrong token error = %v", err)
	}
	t.Setenv("TRESTLE_URL", "")
	if err := runUpload([]string{path}, &out); err == nil || !strings.Contains(err.Error(), "TRESTLE_URL") {
		t.Fatalf("missing TRESTLE_URL error = %v", err)
	}
}

func TestSweepDeletesExpiredBlobs(t *testing.T) {
	d := testDeps(t)
	srv := httptest.NewServer(d.router)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/uploads?ttl=1h", bytes.NewReader(png))
	req.Header.Set("Authorization", "Bearer "+agentTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %v %v", err, resp)
	}
	_ = resp.Body.Close()
	sum := sha256.Sum256(png)
	h := hex.EncodeToString(sum[:])
	blobPath := filepath.Join(d.cfg.DataDir, "blobs", h[:2], h)

	if err := sweepOnce(context.Background(), d, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(blobPath); err != nil {
		t.Fatal("sweep removed a live blob")
	}
	if err := sweepOnce(context.Background(), d, time.Now().Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(blobPath); !os.IsNotExist(err) {
		t.Fatal("expired blob survived the sweep")
	}
	if _, err := os.Stat(filepath.Join(d.cfg.DataDir, "index", h+".json")); !os.IsNotExist(err) {
		t.Fatal("expired record survived the sweep")
	}
	// A fresh index from disk agrees.
	ix, err := index.Open(filepath.Join(d.cfg.DataDir, "index"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ix.Get(h, time.Now()); ok {
		t.Fatal("swept record reloaded")
	}
}

func TestServeShutsDownOnCancel(t *testing.T) {
	d := testDeps(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, d, ln) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %v", err, resp)
	}
	_ = resp.Body.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not return after cancel")
	}
}

func TestDataDirLockExcludesASecondProcess(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockDataDir(dir); !errors.Is(err, errLocked) {
		t.Fatalf("second lock = %v, want errLocked", err)
	}

	// runSweep refuses while serve holds the lock.
	sum := sha256.Sum256([]byte(agentTok))
	t.Setenv("TRESTLE_DATA_DIR", dir)
	t.Setenv("TRESTLE_PUBLIC_BASE_URL", "https://media.example.test")
	t.Setenv("TRESTLE_TOKENS", "agent="+hex.EncodeToString(sum[:]))
	if err := runSweep(); err == nil || !strings.Contains(err.Error(), "serve is running") {
		t.Fatalf("sweep beside a held lock = %v", err)
	}

	unlock()
	if err := runSweep(); err != nil {
		t.Fatalf("sweep after release = %v", err)
	}
}

func TestReconcileAtBoot(t *testing.T) {
	d := testDeps(t)
	orphan := strings.Repeat("ab", 32)
	orphanPath := filepath.Join(d.cfg.DataDir, "blobs", orphan[:2], orphan)
	if err := os.MkdirAll(filepath.Dir(orphanPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(orphanPath, png, 0o600); err != nil {
		t.Fatal(err)
	}
	blobless := strings.Repeat("cd", 32)
	rec := `{"sha256":"` + blobless + `","bytes":1,"content_type":"image/png","ext":"png","created_at":"2026-09-22T00:00:00Z","expires_at":null,"owners":["agent"]}`
	if err := os.WriteFile(filepath.Join(d.cfg.DataDir, "index", blobless+".json"), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}

	// Boot again over the planted state.
	var logs bytes.Buffer
	d, err := setup(d.cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcile(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphanPath); !os.IsNotExist(err) {
		t.Fatal("orphan blob survived reconcile")
	}
	if _, ok := d.index.Get(blobless, time.Now()); !ok {
		t.Fatal("reconcile dropped a record")
	}
	for _, h := range []string{orphan, blobless} {
		if !strings.Contains(logs.String(), h) {
			t.Errorf("no warning naming %s in:\n%s", h, logs.String())
		}
	}
}

func TestReadyzProbesTheIndexDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	d := testDeps(t)
	probe := func() int {
		rec := httptest.NewRecorder()
		d.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec.Code
	}
	if code := probe(); code != http.StatusOK {
		t.Fatalf("readyz = %d", code)
	}
	indexDir := filepath.Join(d.cfg.DataDir, "index")
	if err := os.Chmod(indexDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(indexDir, 0o750) })
	if code := probe(); code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with an unwritable index = %d, want 503", code)
	}
}

func TestCheckWritable(t *testing.T) {
	if err := checkWritable(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := checkWritable(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing dir reported writable")
	}
}
