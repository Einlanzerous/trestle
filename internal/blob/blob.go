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
type Local struct {
	blobs string
	tmp   string
}

// NewLocal creates the directories it needs under root.
func NewLocal(root string) (*Local, error) {
	l := &Local{blobs: filepath.Join(root, "blobs"), tmp: filepath.Join(root, "tmp")}
	for _, d := range []string{l.blobs, l.tmp} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, fmt.Errorf("blob: %w", err)
		}
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

func (l *Local) Delete(_ context.Context, hash string) error {
	if !ValidHash(hash) {
		return nil
	}
	if err := os.Remove(l.path(hash)); err != nil && !errors.Is(err, os.ErrNotExist) {
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
// The fsync before the rename is what makes that true across a crash, not
// just across a process exit.
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
	if err := w.f.Sync(); err != nil {
		_ = w.f.Close()
		_ = os.Remove(name)
		return fmt.Errorf("blob: %w", err)
	}
	if err := w.f.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("blob: %w", err)
	}
	dst := w.l.path(hash)
	// Same hash, same bytes: an existing blob is already the answer, and
	// leaving it alone keeps open readers on the inode they started with.
	if _, err := os.Stat(dst); err == nil {
		return os.Remove(name)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("blob: %w", err)
	}
	if err := os.Rename(name, dst); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("blob: %w", err)
	}
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
