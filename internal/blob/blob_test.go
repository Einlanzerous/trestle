package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func put(t *testing.T, s *Local, data string) string {
	t.Helper()
	w, err := s.NewWriter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, data); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(data))
	hash := hex.EncodeToString(sum[:])
	if err := w.Commit(hash); err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestCommitOpenDelete(t *testing.T) {
	root := t.TempDir()
	s, err := NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hash := put(t, s, "hello")

	if _, err := os.Stat(filepath.Join(root, "blobs", hash[:2], hash)); err != nil {
		t.Fatalf("blob not at <data>/blobs/<hh>/<sha256>: %v", err)
	}
	if left, _ := os.ReadDir(filepath.Join(root, "tmp")); len(left) != 0 {
		t.Fatalf("tmp not empty after commit: %v", left)
	}

	// Committing the same bytes again is idempotent and cleans its temp file.
	if again := put(t, s, "hello"); again != hash {
		t.Fatal("hash changed")
	}
	if left, _ := os.ReadDir(filepath.Join(root, "tmp")); len(left) != 0 {
		t.Fatalf("tmp not empty after duplicate commit: %v", left)
	}

	f, size, err := s.Open(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	_ = f.Close()
	if string(b) != "hello" || size != 5 {
		t.Fatalf("read %q size %d", b, size)
	}

	if err := s.Delete(ctx, hash); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, hash); err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if _, _, err := s.Open(ctx, hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open after delete = %v, want ErrNotFound", err)
	}
}

func TestAbortAndPurge(t *testing.T) {
	root := t.TempDir()
	s, err := NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := s.NewWriter(context.Background())
	_, _ = io.WriteString(w, "x")
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := w.Abort(); err != nil {
		t.Fatalf("second abort: %v", err)
	}
	if left, _ := os.ReadDir(filepath.Join(root, "tmp")); len(left) != 0 {
		t.Fatalf("tmp not empty after abort: %v", left)
	}

	// A crashed upload's temp file is purged at boot.
	stale, _ := s.NewWriter(context.Background())
	_, _ = io.WriteString(stale, "partial")
	if err := s.PurgeTemp(); err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(filepath.Join(root, "tmp")); len(left) != 0 {
		t.Fatalf("tmp not empty after purge: %v", left)
	}
}

func TestInvalidHashNeverBecomesAPath(t *testing.T) {
	s, _ := NewLocal(t.TempDir())
	for _, h := range []string{"", "../../etc/passwd", "ABCDEF" + string(make([]byte, 58))} {
		if _, _, err := s.Open(context.Background(), h); !errors.Is(err, ErrNotFound) {
			t.Errorf("Open(%q) = %v, want ErrNotFound", h, err)
		}
	}
	w, _ := s.NewWriter(context.Background())
	if err := w.Commit("../escape"); err == nil {
		t.Fatal("Commit accepted a non-hash key")
	}
}
