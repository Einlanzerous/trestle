package index

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

func hash(c byte) string { return strings.Repeat(string(c), 64) }

func at(d time.Duration) *time.Time { t := t0.Add(d); return &t }

func noop() error { return nil }

func add(t *testing.T, ix *Index, h, owner string, bytes int64, exp *time.Time, now time.Time) (Record, bool) {
	t.Helper()
	r, existed, err := ix.Add(Upload{SHA256: h, Bytes: bytes, ContentType: "image/png", Ext: "png", Owner: owner, ExpiresAt: exp}, 1<<30, now, noop)
	if err != nil {
		t.Fatal(err)
	}
	return r, existed
}

func TestRecordsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	ix, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	add(t, ix, hash('a'), "alice", 10, nil, t0)
	add(t, ix, hash('b'), "bob", 20, at(time.Hour), t0)
	add(t, ix, hash('b'), "alice", 20, at(2*time.Hour), t0)

	// A temp file from a write that crashed before its rename is ignored and
	// removed.
	if err := os.WriteFile(filepath.Join(dir, "."+hash('c')+".123"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := again.Get(hash('a'), t0)
	if !ok || a.Bytes != 10 || a.ExpiresAt != nil || a.Owners[0] != "alice" {
		t.Fatalf("a after restart = %+v, %v", a, ok)
	}
	b, ok := again.Get(hash('b'), t0)
	if !ok || len(b.Owners) != 2 || !b.ExpiresAt.Equal(*at(2 * time.Hour)) {
		t.Fatalf("b after restart = %+v, %v", b, ok)
	}
	if _, err := os.Stat(filepath.Join(dir, "."+hash('c')+".123")); !os.IsNotExist(err) {
		t.Fatal("stale temp file survived Open")
	}
}

func TestOpenRefusesACorruptRecord(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, hash('a')+".json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("Open accepted a corrupt record")
	}
}

func TestExpiryOnlyExtends(t *testing.T) {
	ix, _ := Open(t.TempDir())
	h := hash('a')

	r, existed := add(t, ix, h, "alice", 1, at(48*time.Hour), t0)
	if existed || !r.ExpiresAt.Equal(*at(48 * time.Hour)) {
		t.Fatalf("first = %+v existed=%v", r, existed)
	}
	// A shorter ttl from a stranger does not bring it in.
	r, existed = add(t, ix, h, "mallory", 1, at(time.Hour), t0)
	if !existed || !r.ExpiresAt.Equal(*at(48 * time.Hour)) {
		t.Fatalf("shorter = %+v existed=%v", r, existed)
	}
	// A longer one pushes it out.
	r, _ = add(t, ix, h, "bob", 1, at(72*time.Hour), t0)
	if !r.ExpiresAt.Equal(*at(72 * time.Hour)) {
		t.Fatalf("longer = %+v", r)
	}
	// No ttl makes it permanent, and a later ttl cannot undo that.
	r, _ = add(t, ix, h, "carol", 1, nil, t0)
	if r.ExpiresAt != nil {
		t.Fatalf("permanent = %+v", r)
	}
	r, _ = add(t, ix, h, "dave", 1, at(time.Hour), t0)
	if r.ExpiresAt != nil {
		t.Fatalf("after permanent = %+v", r)
	}
}

func TestExpiredIsGoneEverywhere(t *testing.T) {
	ix, _ := Open(t.TempDir())
	add(t, ix, hash('a'), "alice", 5, at(time.Hour), t0)
	later := t0.Add(time.Hour)
	if _, ok := ix.Get(hash('a'), later); ok {
		t.Fatal("Get returned an expired record")
	}
	if got := ix.Owned("alice", later); len(got) != 0 {
		t.Fatalf("Owned returned expired records: %+v", got)
	}
	if err := ix.Disown(hash('a'), "alice", later, noop); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Disown of expired = %v", err)
	}
	// Re-uploading expired bytes starts a fresh record: old owners do not
	// carry over.
	r, existed := add(t, ix, hash('a'), "bob", 5, nil, later)
	if existed || len(r.Owners) != 1 || r.Owners[0] != "bob" || !r.CreatedAt.Equal(later) {
		t.Fatalf("re-upload after expiry = %+v existed=%v", r, existed)
	}
}

func TestQuota(t *testing.T) {
	ix, _ := Open(t.TempDir())
	up := func(h, owner string, n int64) error {
		_, _, err := ix.Add(Upload{SHA256: h, Bytes: n, ContentType: "image/png", Ext: "png", Owner: owner}, 100, t0, noop)
		return err
	}
	if err := up(hash('a'), "alice", 60); err != nil {
		t.Fatal(err)
	}
	committed := false
	_, _, err := ix.Add(Upload{SHA256: hash('b'), Bytes: 50, Owner: "alice"}, 100, t0, func() error { committed = true; return nil })
	if !errors.Is(err, ErrQuota) || committed {
		t.Fatalf("over quota: err=%v committed=%v", err, committed)
	}
	// Re-uploading bytes it already owns costs nothing.
	if err := up(hash('a'), "alice", 60); err != nil {
		t.Fatalf("re-upload at quota: %v", err)
	}
	// A shared blob counts fully against each owner.
	if err := up(hash('a'), "bob", 60); err != nil {
		t.Fatal(err)
	}
	if err := up(hash('c'), "bob", 50); !errors.Is(err, ErrQuota) {
		t.Fatalf("bob over quota via shared blob: %v", err)
	}
}

func TestDisownAndSweep(t *testing.T) {
	dir := t.TempDir()
	ix, _ := Open(dir)
	add(t, ix, hash('a'), "alice", 1, nil, t0)
	add(t, ix, hash('a'), "bob", 1, nil, t0)

	if err := ix.Disown(hash('a'), "mallory", t0, noop); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-owner disown = %v", err)
	}
	last := 0
	onLast := func() error { last++; return nil }
	if err := ix.Disown(hash('a'), "alice", t0, onLast); err != nil || last != 0 {
		t.Fatalf("first disown: err=%v last=%d", err, last)
	}
	if err := ix.Disown(hash('a'), "bob", t0, onLast); err != nil || last != 1 {
		t.Fatalf("last disown: err=%v last=%d", err, last)
	}
	if _, err := os.Stat(filepath.Join(dir, hash('a')+".json")); !os.IsNotExist(err) {
		t.Fatal("record file survived its last owner")
	}

	add(t, ix, hash('b'), "alice", 1, at(time.Minute), t0)
	add(t, ix, hash('c'), "alice", 1, nil, t0)
	var deleted []string
	removed, err := ix.Sweep(t0.Add(time.Minute), func(h string) error { deleted = append(deleted, h); return nil })
	if err != nil || len(removed) != 1 || len(deleted) != 1 || deleted[0] != hash('b') {
		t.Fatalf("sweep: removed=%v deleted=%v err=%v", removed, deleted, err)
	}
	if _, err := os.Stat(filepath.Join(dir, hash('b')+".json")); !os.IsNotExist(err) {
		t.Fatal("swept record file survived")
	}
}
