// Command trestle is Trestle's single static binary: the server, its ops
// subcommands and the agent-facing upload client.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Einlanzerous/trestle/internal/api"
	"github.com/Einlanzerous/trestle/internal/blob"
	"github.com/Einlanzerous/trestle/internal/config"
	"github.com/Einlanzerous/trestle/internal/index"
	"github.com/Einlanzerous/trestle/internal/sniff"
)

// version is stamped at build time with -ldflags "-X main.version=...".
//
// It defaults to EMPTY, not to "dev": an -X flag passed with an empty value
// overwrites whatever default is written here, so the fallback has to live
// in code. buildVersion() is the only reader.
var version = ""

// commit is the full 40-char git SHA, stamped the same way.
var commit = ""

func buildVersion() string {
	if version == "" {
		return "dev"
	}
	return version
}

// buildCommit reports the stamped sha only if it is a full 40-hex one: the
// delivery ledger compares by equality, so an abbreviated sha is a wrong
// claim and null is the honest answer (PRINCIPLES §4).
func buildCommit() string {
	if len(commit) != 40 {
		return ""
	}
	if _, err := hex.DecodeString(commit); err != nil || strings.ToLower(commit) != commit {
		return ""
	}
	return commit
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "trestle: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("no subcommand given")
	}
	switch args[0] {
	case "serve":
		return runServe()
	case "sweep":
		return runSweep()
	case "token":
		return runToken(args[1:], os.Stdin, os.Stdout, os.Stderr)
	case "upload":
		return runUpload(args[1:], os.Stdout)
	case "version":
		fmt.Println(buildVersion())
		if c := buildCommit(); c != "" {
			fmt.Println(c)
		}
		return nil
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func usage() { fmt.Fprint(os.Stderr, usageText()) }

// usageText is the help text and the only documentation of the environment
// surface. A test asserts it names every variable config.Load reads.
func usageText() string {
	return `trestle — upload bytes, get a stable public URL

usage:
  trestle serve                         run the HTTP server
  trestle sweep                         one sweep pass on a stopped service; refuses while serve runs
  trestle token mint --name <consumer>  print a new token to stdout, name=sha256 to stderr
  trestle token hash                    read a token on stdin, print its sha256 hex
  trestle upload <file> [--ttl 30d]     upload a file, print its public URL
  trestle version                       print the build version and commit

` + "`trestle token mint --name x > token`" + ` captures only the secret; the
name=hash line on stderr is what goes into TRESTLE_TOKENS.

server configuration is env-only, TRESTLE_-prefixed. There are no config files.

  TRESTLE_PORT                   listen port. Default 4014.
  TRESTLE_DATA_DIR               where blobs, index and tmp live. Required.
  TRESTLE_PUBLIC_BASE_URL        scheme+host that /m/ URLs are built on, no
                                 trailing slash. Required.
  TRESTLE_TOKENS                 name=sha256hex,… — hashes, never tokens. Required.
  TRESTLE_MAX_IMAGE_BYTES        cap for png/jpeg/webp/gif/svg. Default 10485760.
  TRESTLE_MAX_VIDEO_BYTES        cap for mp4/webm. Default 104857600.
  TRESTLE_QUOTA_BYTES_PER_TOKEN  bytes a token may own. Default 2147483648.
  TRESTLE_SWEEP_INTERVAL         how often serve reclaims expired blobs. Default 1h.
  TRESTLE_LOG_LEVEL              debug | info | warn | error. Default info.
  TRESTLE_LOG_FORMAT             json | text. Default json.
  TRESTLE_SHUTDOWN_GRACE         how long in-flight requests get on SIGTERM. Default 20s.

the upload client reads:

  TRESTLE_URL                    the API base, e.g. http://127.0.0.1:4014
  TRESTLE_TOKEN                  the plaintext bearer token
`
}

// deps is what setup() produces.
type deps struct {
	cfg    config.Config
	logger *slog.Logger
	blobs  *blob.Local
	index  *index.Index
	router http.Handler
}

// setup is the composition root: config → store → index → handlers. Nothing
// below it reads the environment.
func setup(cfg config.Config, logger *slog.Logger) (deps, error) {
	blobs, err := blob.NewLocal(cfg.DataDir)
	if err != nil {
		return deps{}, fmt.Errorf("TRESTLE_DATA_DIR %q: %w", cfg.DataDir, err)
	}
	indexDir := filepath.Join(cfg.DataDir, "index")
	ix, err := index.Open(indexDir)
	if err != nil {
		return deps{}, fmt.Errorf("TRESTLE_DATA_DIR %q: %w", cfg.DataDir, err)
	}
	router := api.NewRouter(api.Deps{
		Logger:        logger,
		Index:         ix,
		Blobs:         blobs,
		Tokens:        cfg.Tokens,
		PublicBaseURL: cfg.PublicBaseURL,
		Caps:          sniff.Caps{Image: cfg.MaxImageBytes, Video: cfg.MaxVideoBytes},
		Quota:         cfg.QuotaBytesPerToken,
		Version:       buildVersion(),
		Commit:        buildCommit(),
		Ready:         func() error { return ready(blobs.TempDir(), indexDir) },
		Now:           time.Now,
	})
	return deps{cfg: cfg, logger: logger, blobs: blobs, index: ix, router: router}, nil
}

// ready is /readyz's probe. An upload writes to tmp and then to index, and
// one that commits its blob but cannot write its record answers 500, so both
// have to be writable for the process to be ready.
func ready(dirs ...string) error {
	for _, d := range dirs {
		if err := checkWritable(d); err != nil {
			return err
		}
	}
	return nil
}

func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, "readyz-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_, err = f.Write([]byte("ok"))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if rerr := os.Remove(name); err == nil {
		err = rerr
	}
	return err
}

func runServe() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := cfg.Logger(os.Stdout)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Held for the process lifetime, and taken before the index loads: the
	// index lock is per-process, so this is what keeps a second process off
	// the data dir. Released by the kernel when the process exits.
	unlock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	defer unlock()

	d, err := setup(cfg, logger)
	if err != nil {
		return err
	}
	// With the lock held nothing in tmp belongs to a live upload.
	if err := d.blobs.PurgeTemp(); err != nil {
		return fmt.Errorf("TRESTLE_DATA_DIR %q: %w", cfg.DataDir, err)
	}
	if err := reconcile(ctx, d); err != nil {
		return fmt.Errorf("TRESTLE_DATA_DIR %q: %w", cfg.DataDir, err)
	}

	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("serve: TRESTLE_PORT: %w", err)
	}
	return serve(ctx, d, ln)
}

// serve runs until ctx is cancelled, then drains within TRESTLE_SHUTDOWN_GRACE.
// Split from runServe so a test can cancel ctx instead of sending a signal.
func serve(ctx context.Context, d deps, ln net.Listener) error {
	srv := &http.Server{
		Handler:           d.router,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sweepCtx, stopSweep := context.WithCancel(context.Background())
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		t := time.NewTicker(d.cfg.SweepInterval)
		defer t.Stop()
		for {
			select {
			case <-sweepCtx.Done():
				return
			case <-t.C:
				_ = sweepOnce(sweepCtx, d, time.Now())
			}
		}
	}()

	d.logger.Info("serving", "addr", ln.Addr().String(), "version", buildVersion())
	var serveErr error
	select {
	case serveErr = <-errCh:
	case <-ctx.Done():
	}
	stopSweep()
	<-sweepDone
	if serveErr != nil {
		return fmt.Errorf("serve: %w", serveErr)
	}

	d.logger.Info("shutting down", "grace", d.cfg.ShutdownGrace)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), d.cfg.ShutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	d.logger.Info("stopped")
	return nil
}

// sweepOnce deletes every record expired at now and its blob. Expiry is
// already enforced on every read path; this only reclaims disk.
func sweepOnce(ctx context.Context, d deps, now time.Time) error {
	removed, err := d.index.Sweep(now, func(hash string) error { return d.blobs.Delete(ctx, hash) })
	for _, r := range removed {
		d.logger.Info("swept", "sha256", r.SHA256, "bytes", r.Bytes, "owners", r.Owners)
	}
	if err != nil {
		d.logger.Error("sweep failed", "error", err)
	}
	return err
}

// runSweep is for a stopped service; a running serve sweeps on its own timer.
// Two processes sweeping and uploading the same data dir race: a sweep can
// delete a blob a live upload just deduplicated against.
func runSweep() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if errors.Is(err, errLocked) {
		return errors.New("sweep: serve is running and sweeps on its own timer (TRESTLE_SWEEP_INTERVAL); stop it to sweep by hand")
	}
	if err != nil {
		return fmt.Errorf("sweep: %w", err)
	}
	defer unlock()
	d, err := setup(cfg, cfg.Logger(os.Stdout))
	if err != nil {
		return err
	}
	return sweepOnce(context.Background(), d, time.Now())
}

var errLocked = errors.New("the data dir is locked by another trestle process")

// lockDataDir takes an exclusive flock on <data>/.lock without waiting.
// flock locks belong to the open file description, so a second call in the
// same process conflicts too, which is what the test relies on.
func lockDataDir(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("TRESTLE_DATA_DIR %q: %w", dir, err)
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		return nil, fmt.Errorf("TRESTLE_DATA_DIR %q: %w", dir, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errLocked
		}
		return nil, fmt.Errorf("TRESTLE_DATA_DIR %q: lock: %w", dir, err)
	}
	return func() { _ = f.Close() }, nil
}

// reconcile runs at serve boot, under the data-dir lock and before the
// listener opens. A crash between a record's removal and its blob's (the
// order Disown and Sweep use on purpose) leaves an orphan blob that nothing
// would ever reclaim, so orphans are deleted. A record whose blob is gone
// cannot be repaired here (the bytes are the key), so it is only reported:
// /m/ answers 404 for it and a re-upload of the same bytes restores it.
func reconcile(ctx context.Context, d deps) error {
	onDisk, err := d.blobs.Hashes()
	if err != nil {
		return err
	}
	recorded := map[string]bool{}
	for _, h := range d.index.Hashes() {
		recorded[h] = true
	}
	present := map[string]bool{}
	var orphans []string
	for _, h := range onDisk {
		present[h] = true
		if !recorded[h] {
			orphans = append(orphans, h)
		}
	}
	// An orphan is normally one or two blobs left by a crash between a record
	// removal and its blob delete. A whole tree of them is not that: it is an
	// index that failed to mount or a restore that brought back blobs/ alone,
	// and deleting the bytes would turn a recoverable state into a permanent
	// one. Refuse to boot rather than guess.
	if len(orphans) > 0 && (len(recorded) == 0 || (len(onDisk) >= 4 && len(orphans)*2 > len(onDisk))) {
		return fmt.Errorf("reconcile: %d of %d blobs under TRESTLE_DATA_DIR have no record; refusing to delete them — restore index/ or clear blobs/ deliberately", len(orphans), len(onDisk))
	}
	for _, h := range orphans {
		d.logger.Warn("deleting orphan blob with no record", "sha256", h)
		if err := d.blobs.Delete(ctx, h); err != nil {
			return err
		}
	}
	for h := range recorded {
		if !present[h] {
			d.logger.Warn("record has no blob; /m/ will answer 404 until the bytes are uploaded again", "sha256", h)
		}
	}
	return nil
}

func runToken(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("token: expected mint or hash")
	}
	switch args[0] {
	case "mint":
		fs := flag.NewFlagSet("token mint", flag.ContinueOnError)
		fs.SetOutput(stderr)
		name := fs.String("name", "", "the consumer this token is for")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return mintToken(*name, stdout, stderr)
	case "hash":
		b, err := io.ReadAll(io.LimitReader(stdin, 4096))
		if err != nil {
			return fmt.Errorf("token hash: %w", err)
		}
		// Trimmed because the usual source is `echo` or a file with a
		// trailing newline; a minted token is base64url and has no spaces.
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return errors.New("token hash: no token on stdin")
		}
		_, err = fmt.Fprintln(stdout, tokenHash(tok))
		return err
	default:
		return fmt.Errorf("token: unknown subcommand %q (expected mint or hash)", args[0])
	}
}

// mintToken writes the plaintext to stdout and nothing else, so `> token`
// captures only the secret; the name=hash line for TRESTLE_TOKENS goes to
// stderr.
func mintToken(name string, stdout, stderr io.Writer) error {
	if !config.ValidTokenName(name) {
		return errors.New("token mint: --name is required: letters, digits, '-', '_' or '.', at most 64")
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Errorf("token mint: %w", err)
	}
	tok := base64.RawURLEncoding.EncodeToString(raw[:])
	if _, err := fmt.Fprintln(stdout, tok); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stderr, "%s=%s\n", name, tokenHash(tok))
	return err
}

func tokenHash(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func runUpload(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	ttl := fs.String("ttl", "", "expire after this long: a Go duration or Nd days (default: never)")
	// flag stops at the first positional, and `upload shot.png --ttl 30d` is
	// the natural order, so parse around each positional.
	var files []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		files = append(files, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(files) != 1 {
		return errors.New("upload: expected exactly one file")
	}
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("TRESTLE_URL")), "/")
	if base == "" {
		return errors.New("upload: TRESTLE_URL is required (e.g. http://127.0.0.1:4014)")
	}
	token := strings.TrimSpace(os.Getenv("TRESTLE_TOKEN"))
	if token == "" {
		return errors.New("upload: TRESTLE_TOKEN is required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	u, err := upload(ctx, http.DefaultClient, base, token, files[0], *ttl)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, u)
	return err
}

// upload POSTs the file's raw bytes and returns the public URL. Errors quote
// the server's error body, never the token.
func upload(ctx context.Context, client *http.Client, base, token, path, ttl string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}

	target := base + "/v1/uploads"
	if ttl != "" {
		target += "?" + url.Values{"ttl": {ttl}}.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, f)
	if err != nil {
		return "", fmt.Errorf("upload: TRESTLE_URL: %w", err)
	}
	req.ContentLength = st.Size()
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("upload: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		var e struct{ Error, Message string }
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return "", fmt.Errorf("upload: %d %s: %s", resp.StatusCode, e.Error, e.Message)
		}
		return "", fmt.Errorf("upload: unexpected status %s", resp.Status)
	}
	var ok struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &ok); err != nil || ok.URL == "" {
		return "", errors.New("upload: response carried no url")
	}
	return ok.URL, nil
}
