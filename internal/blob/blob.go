// Package blob stores content-addressed bytes.
//
// The key is the SHA-256 of the bytes, hex, and nothing else ever is: names,
// extensions and owners live in the index, never in a blob path (IDEA-51 §A1).
// A name in the key would weld a mutable thing to an immutable one.
package blob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/Einlanzerous/trestle/internal/durable"
)

// ErrNotFound is returned by Open for a hash the store does not hold.
var ErrNotFound = errors.New("blob: not found")

// Store is the seam R2 slots in behind (deferred, see the design doc).
type Store interface {
	// NewWriter streams to a temp location; Commit(hash) moves it into place
	// (idempotent if the hash already exists), Abort discards it.
	NewWriter(ctx context.Context) (Writer, error)
	Open(ctx context.Context, hash string) (io.ReadSeekCloser, int64, error)
	Delete(ctx context.Context, hash string) error
}

// Writer is an in-flight upload. Exactly one of Commit or Abort ends it;
// Abort after Commit is a no-op so callers can defer it unconditionally.
type Writer interface {
	io.Writer
	Commit(hash string) error
	Abort() error
}

// ValidHash reports whether s is a lowercase hex SHA-256. Every path this
// package builds goes through it, so a caller-supplied id can never become a
// path traversal.
func ValidHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Local keeps blobs on disk:
//
//	<root>/blobs/<hh>/<sha256>
//	<root>/tmp/<random>
//
// A committed blob is durable: its file, its directory entry in blobs/<hh>/
// and that shard's entry in blobs/ are all on stable storage before Commit
// returns (GENZO-30).
type Local struct {
	blobs string
	tmp   string
	fs    durable.FS

	mu sync.Mutex
	// shards holds every blobs/<hh> whose entry in blobs/ this process has
	// fsynced. A shard found on disk may have been created by a process that
	// died before syncing blobs/, so the first commit into each shard in a
	// process syncs blobs/ once: at most 256 extra fsyncs per process.
	shards map[string]bool
}

// NewLocal creates the directories it needs under root.
func NewLocal(root string) (*Local, error) { return NewLocalFS(root, durable.OS{}) }

// NewLocalFS is NewLocal with the filesystem calls that order durability
// going through fsys; tests pass a recorder.
func NewLocalFS(root string, fsys durable.FS) (*Local, error) {
	l := &Local{blobs: filepath.Join(root, "blobs"), tmp: filepath.Join(root, "tmp"), fs: fsys, shards: map[string]bool{}}
	for _, d := range []string{l.blobs, l.tmp} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, fmt.Errorf("blob: %w", err)
		}
	}
	// blobs/ may have just been created; its entry in root must be durable
	// before a blob below it can be.
	if err := fsys.SyncDir(root); err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	return l, nil
}

// PurgeTemp removes every in-flight upload. Only `serve` calls it, at boot
// and holding the data-dir lock, so anything in tmp belongs to a process that
// no longer exists.
func (l *Local) PurgeTemp() error {
	entries, err := os.ReadDir(l.tmp)
	if err != nil {
		return fmt.Errorf("blob: %w", err)
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(l.tmp, e.Name())); err != nil {
			return fmt.Errorf("blob: %w", err)
		}
	}
	return nil
}

// TempDir is where in-flight uploads live; /readyz probes writability there.
func (l *Local) TempDir() string { return l.tmp }

// Hashes lists every blob on disk, for serve's boot-time reconcile. Files
// whose names are not a hash are not Trestle's and are left alone.
func (l *Local) Hashes() ([]string, error) {
	shards, err := os.ReadDir(l.blobs)
	if err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	var out []string
	for _, s := range shards {
		if !s.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(l.blobs, s.Name()))
		if err != nil {
			return nil, fmt.Errorf("blob: %w", err)
		}
		for _, e := range entries {
			if h := e.Name(); ValidHash(h) && h[:2] == s.Name() && e.Type().IsRegular() {
				out = append(out, h)
			}
		}
	}
	return out, nil
}

func (l *Local) path(hash string) string {
	return filepath.Join(l.blobs, hash[:2], hash)
}

func (l *Local) NewWriter(_ context.Context) (Writer, error) {
	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(l.tmp, hex.EncodeToString(rnd[:])), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	return &localWriter{l: l, f: f}, nil
}

func (l *Local) Open(_ context.Context, hash string) (io.ReadSeekCloser, int64, error) {
	if !ValidHash(hash) {
		return nil, 0, ErrNotFound
	}
	f, err := os.Open(l.path(hash))
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, ErrNotFound
	}
	if err != nil {
		return nil, 0, fmt.Errorf("blob: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("blob: %w", err)
	}
	return f, st.Size(), nil
}

// Delete unlinks the blob and does not fsync its shard. Every caller removes
// the record first and makes that removal durable before calling Delete, so a
// lost unlink brings back a record-less blob, which serve's boot reconcile
// reclaims; it can never bring back a record whose blob is gone.
func (l *Local) Delete(_ context.Context, hash string) error {
	if !ValidHash(hash) {
		return nil
	}
	if err := l.fs.Remove(l.path(hash)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("blob: %w", err)
	}
	return nil
}

type localWriter struct {
	l    *Local
	f    *os.File
	done bool
}

func (w *localWriter) Write(p []byte) (int, error) { return w.f.Write(p) }

// Commit is temp-file + rename, so a reader can only ever find a whole blob.
// The fsync before the rename makes the bytes durable; the fsync of the shard
// after it makes the name durable, and the fsync of blobs/ the shard's own
// name. Only then does Commit return, so a caller that answers after it never
// reports a blob a power loss can take back (GENZO-30).
func (w *localWriter) Commit(hash string) error {
	if w.done {
		return errors.New("blob: writer already finished")
	}
	w.done = true
	name := w.f.Name()
	if !ValidHash(hash) {
		_ = w.f.Close()
		_ = os.Remove(name)
		return fmt.Errorf("blob: invalid hash")
	}
	if err := w.l.fs.SyncFile(w.f); err != nil {
		_ = w.f.Close()
		_ = os.Remove(name)
		return fmt.Errorf("blob: %w", err)
	}
	if err := w.f.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("blob: %w", err)
	}
	dst := w.l.path(hash)
	shard := filepath.Dir(dst)
	if err := w.l.ensureShard(shard); err != nil {
		_ = os.Remove(name)
		return err
	}
	// Same hash, same bytes: an existing blob is already the answer, and
	// leaving it alone keeps open readers on the inode they started with. It
	// may have been renamed by a process that died before syncing, so the
	// shard is synced either way.
	if _, err := os.Stat(dst); err == nil {
		// The temp file is in tmp/, which serve purges at boot: its unlink
		// needs no fsync.
		if err := os.Remove(name); err != nil {
			return fmt.Errorf("blob: %w", err)
		}
	} else if err := w.l.fs.Rename(name, dst); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("blob: %w", err)
	}
	if err := w.l.fs.SyncDir(shard); err != nil {
		return fmt.Errorf("blob: %w", err)
	}
	return nil
}

// ensureShard creates blobs/<hh> if needed and, the first time this process
// uses it, makes its entry in blobs/ durable.
func (l *Local) ensureShard(shard string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.shards[shard] {
		return nil
	}
	if err := l.fs.Mkdir(shard, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("blob: %w", err)
	}
	if err := l.fs.SyncDir(l.blobs); err != nil {
		return fmt.Errorf("blob: %w", err)
	}
	l.shards[shard] = true
	return nil
}

func (w *localWriter) Abort() error {
	if w.done {
		return nil
	}
	w.done = true
	_ = w.f.Close()
	if err := os.Remove(w.f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("blob: %w", err)
	}
	return nil
}
