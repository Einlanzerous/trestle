package index

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Einlanzerous/trestle/internal/blob"
	"github.com/Einlanzerous/trestle/internal/durable/durabletest"
)

// store is a data dir wired as serve wires it, with every durability-relevant
// filesystem call recorded.
type store struct {
	rec   *durabletest.Recorder
	blobs *blob.Local
	ix    *Index
}

func newStore(t *testing.T) *store {
	t.Helper()
	root := t.TempDir()
	rec := durabletest.New(root)
	blobs, err := blob.NewLocalFS(root, rec)
	if err != nil {
		t.Fatal(err)
	}
	ix, err := OpenFS(filepath.Join(root, "index"), rec)
	if err != nil {
		t.Fatal(err)
	}
	rec.Reset()
	return &store{rec: rec, blobs: blobs, ix: ix}
}

// upload is the handler's path: stream to a writer, then Add with Commit as
// the callback, exactly as internal/api's upload does.
func (s *store) upload(t *testing.T, data, owner string, exp *time.Time, now time.Time) (string, error) {
	t.Helper()
	w, err := s.blobs.NewWriter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Abort() }()
	if _, err := io.WriteString(w, data); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(data))
	h := hex.EncodeToString(sum[:])
	_, _, err = s.ix.Add(Upload{SHA256: h, Bytes: int64(len(data)), ContentType: "image/png", Ext: "png", Owner: owner, ExpiresAt: exp},
		1<<30, now, func() error { return w.Commit(h) })
	return h, err
}

func (s *store) del(h string) error { return s.blobs.Delete(context.Background(), h) }

func expectOps(t *testing.T, rec *durabletest.Recorder, h string, want ...string) {
	t.Helper()
	got := rec.Ops()
	for i := range want {
		want[i] = strings.NewReplacer("<hh>", h[:2], "<h>", h).Replace(want[i])
	}
	if !slices.Equal(got, want) {
		t.Fatalf("filesystem calls:\n  got  %q\n  want %q", got, want)
	}
	rec.Reset()
}

// TestDurabilityOrder pins the order GENZO-30 rests on: a 201 is answered
// after Add returns, and by then the blob's bytes, its name in blobs/<hh>/,
// the shard's name in blobs/, the record's bytes and its name in index/ are
// all fsynced, in that order. A removal makes the record's absence durable
// before the blob is touched.
func TestDurabilityOrder(t *testing.T) {
	s := newStore(t)

	// A first upload into a shard this process has not used: the shard's own
	// entry in blobs/ is synced before the blob is renamed into it.
	h, err := s.upload(t, "first bytes", "alice", nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	expectOps(t, s.rec, h,
		"fsync tmp/<tmp>",
		"mkdir blobs/<hh>",
		"fsyncdir blobs",
		"rename tmp/<tmp> -> blobs/<hh>/<h>",
		"fsyncdir blobs/<hh>",
		"fsync index/<tmp>",
		"rename index/<tmp> -> index/<h>.json",
		"fsyncdir index",
	)

	// An owner update: the blob is already there (its temp copy is dropped,
	// the shard is synced anyway in case a dead process renamed it there
	// without syncing), and the record is rewritten durably.
	if _, err := s.upload(t, "first bytes", "bob", nil, t0); err != nil {
		t.Fatal(err)
	}
	expectOps(t, s.rec, h,
		"fsync tmp/<tmp>",
		"fsyncdir blobs/<hh>",
		"fsync index/<tmp>",
		"rename index/<tmp> -> index/<h>.json",
		"fsyncdir index",
	)

	// The same owner again changes no record, so nothing is written to index/.
	if _, err := s.upload(t, "first bytes", "bob", nil, t0); err != nil {
		t.Fatal(err)
	}
	expectOps(t, s.rec, h,
		"fsync tmp/<tmp>",
		"fsyncdir blobs/<hh>",
	)

	// Disown, not the last owner: a durable record rewrite and no blob call.
	if err := s.ix.Disown(h, "alice", t0, func() error { return s.del(h) }); err != nil {
		t.Fatal(err)
	}
	expectOps(t, s.rec, h,
		"fsync index/<tmp>",
		"rename index/<tmp> -> index/<h>.json",
		"fsyncdir index",
	)

	// Disown, the last owner: the record's unlink is durable before the blob
	// is unlinked. The blob unlink is not synced (a lost one is an orphan the
	// boot reconcile reclaims).
	if err := s.ix.Disown(h, "bob", t0, func() error { return s.del(h) }); err != nil {
		t.Fatal(err)
	}
	expectOps(t, s.rec, h,
		"unlink index/<h>.json",
		"fsyncdir index",
		"unlink blobs/<hh>/<h>",
	)
}

func TestSweepSyncsIndexOnceBeforeAnyBlob(t *testing.T) {
	s := newStore(t)
	a, err := s.upload(t, "expires a", "alice", at(time.Minute), t0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.upload(t, "expires b", "alice", at(time.Minute), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.upload(t, "stays", "alice", nil, t0); err != nil {
		t.Fatal(err)
	}
	s.rec.Reset()

	removed, err := s.ix.Sweep(t0.Add(time.Minute), s.del)
	if err != nil || len(removed) != 2 {
		t.Fatalf("sweep: removed=%d err=%v", len(removed), err)
	}
	first, second := min(a, b), max(a, b)
	got := s.rec.Ops()
	// The record unlinks come in map order; everything after them is fixed.
	unlinks := []string{"unlink index/" + a + ".json", "unlink index/" + b + ".json"}
	if len(got) != 5 || !slices.Contains(unlinks, got[0]) || !slices.Contains(unlinks, got[1]) || got[0] == got[1] {
		t.Fatalf("sweep calls: %q", got)
	}
	want := []string{
		"fsyncdir index",
		"unlink blobs/" + first[:2] + "/" + first,
		"unlink blobs/" + second[:2] + "/" + second,
	}
	if !slices.Equal(got[2:], want) {
		t.Fatalf("sweep calls after the unlinks:\n  got  %q\n  want %q", got[2:], want)
	}
}

// A first commit into each shard syncs blobs/ once per process, not per blob.
func TestShardEntrySyncedOncePerProcess(t *testing.T) {
	s := newStore(t)
	h, err := s.upload(t, "one", "alice", nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	// Find other bytes in the same shard.
	var other string
	for i := 0; ; i++ {
		d := "other " + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
		sum := sha256.Sum256([]byte(d))
		if hex.EncodeToString(sum[:])[:2] == h[:2] {
			other = d
			break
		}
	}
	s.rec.Reset()
	h2, err := s.upload(t, other, "alice", nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range s.rec.Ops() {
		if op == "fsyncdir blobs" || strings.HasPrefix(op, "mkdir") {
			t.Fatalf("second blob in shard %s repeated the shard setup: %q", h2[:2], s.rec.Ops())
		}
	}
}

// A failed directory fsync fails the upload and leaves memory at the old
// state, so the retry writes and syncs again instead of finding an "unchanged"
// record and skipping the write.
func TestFailedIndexSyncIsRetried(t *testing.T) {
	s := newStore(t)
	h, err := s.upload(t, "bytes", "alice", nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	s.rec.FailSyncDir = map[string]error{"index": errors.New("EIO")}
	if _, err := s.upload(t, "bytes", "bob", nil, t0); err == nil {
		t.Fatal("upload succeeded with index/ unsynced")
	}
	if r, _ := s.ix.Get(h, t0); r.Owns("bob") {
		t.Fatal("memory took an owner whose record is not durable")
	}
	s.rec.FailSyncDir = nil
	s.rec.Reset()
	if _, err := s.upload(t, "bytes", "bob", nil, t0); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.rec.Ops(), "fsyncdir index") {
		t.Fatalf("retry did not sync index/: %q", s.rec.Ops())
	}
	if r, _ := s.ix.Get(h, t0); !r.Owns("bob") {
		t.Fatal("retry did not record the owner")
	}

	// The same for a last-owner Disown: no blob is deleted while the record's
	// removal is not durable.
	if err := s.ix.Disown(h, "alice", t0, func() error { return s.del(h) }); err != nil {
		t.Fatal(err)
	}
	s.rec.FailSyncDir = map[string]error{"index": errors.New("EIO")}
	s.rec.Reset()
	if err := s.ix.Disown(h, "bob", t0, func() error { return s.del(h) }); err == nil {
		t.Fatal("last disown succeeded with index/ unsynced")
	}
	for _, op := range s.rec.Ops() {
		if strings.HasPrefix(op, "unlink blobs/") {
			t.Fatalf("blob deleted before its record's removal was durable: %q", s.rec.Ops())
		}
	}
	if _, ok := s.ix.Get(h, t0); !ok {
		t.Fatal("record dropped from memory before its removal was durable")
	}
	// The retry unlinks nothing new, syncs, and only then deletes the blob.
	s.rec.FailSyncDir = nil
	s.rec.Reset()
	if err := s.ix.Disown(h, "bob", t0, func() error { return s.del(h) }); err != nil {
		t.Fatal(err)
	}
	expectOps(t, s.rec, h,
		"unlink index/<h>.json",
		"fsyncdir index",
		"unlink blobs/<hh>/<h>",
	)
}

// A sweep whose index/ sync fails deletes no blob and keeps the records, so
// the next sweep tries again.
func TestSweepWithFailedSyncDeletesNothing(t *testing.T) {
	s := newStore(t)
	h, err := s.upload(t, "expires", "alice", at(time.Minute), t0)
	if err != nil {
		t.Fatal(err)
	}
	s.rec.FailSyncDir = map[string]error{"index": errors.New("EIO")}
	s.rec.Reset()
	if removed, err := s.ix.Sweep(t0.Add(time.Minute), s.del); err == nil || len(removed) != 0 {
		t.Fatalf("sweep with index/ unsynced: removed=%d err=%v", len(removed), err)
	}
	for _, op := range s.rec.Ops() {
		if strings.HasPrefix(op, "unlink blobs/") {
			t.Fatalf("blob deleted before its record's removal was durable: %q", s.rec.Ops())
		}
	}
	s.rec.FailSyncDir = nil
	s.rec.Reset()
	if removed, err := s.ix.Sweep(t0.Add(time.Minute), s.del); err != nil || len(removed) != 1 {
		t.Fatalf("retried sweep: removed=%d err=%v", len(removed), err)
	}
	expectOps(t, s.rec, h,
		"unlink index/<h>.json",
		"fsyncdir index",
		"unlink blobs/<hh>/<h>",
	)
}

// Open syncs index/ (a dead process may have left a renamed but unsynced
// record that the index will now answer from) and its parent.
func TestOpenSyncsWhatItLoads(t *testing.T) {
	root := t.TempDir()
	rec := durabletest.New(root)
	if _, err := OpenFS(filepath.Join(root, "index"), rec); err != nil {
		t.Fatal(err)
	}
	if got, want := rec.Ops(), []string{"fsyncdir index", "fsyncdir ."}; !slices.Equal(got, want) {
		t.Fatalf("Open calls = %q, want %q", got, want)
	}
}

// After an index/ fsync fails behind a removal or a rewrite, memory and disk
// may disagree. A re-upload that would leave memory unchanged must still
// rewrite and sync the record, or it answers 201 for a record the next boot
// does not have (and reconcile then deletes the blob).
func TestReuploadAfterFailedSyncRewritesTheRecord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		owners []string // uploaders, in order
		disown string
	}{
		{"last owner removed", []string{"alice"}, "alice"},
		{"one of two owners removed", []string{"alice", "bob"}, "alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			var h string
			for _, o := range tc.owners {
				var err error
				if h, err = s.upload(t, "only copy", o, nil, t0); err != nil {
					t.Fatal(err)
				}
			}
			s.rec.FailSyncDir = map[string]error{"index": errors.New("EMFILE")}
			if err := s.ix.Disown(h, tc.disown, t0, func() error { return s.del(h) }); err == nil {
				t.Fatal("disown succeeded with index/ unsynced")
			}
			s.rec.FailSyncDir = nil
			s.rec.Reset()

			// Memory still has the old record, so this upload changes nothing
			// there; it must write anyway.
			if _, err := s.upload(t, "only copy", tc.disown, nil, t0); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(s.rec.Ops(), "fsyncdir index") {
				t.Fatalf("re-upload of a stale record answered from memory: %q", s.rec.Ops())
			}

			again, err := Open(s.ix.dir)
			if err != nil {
				t.Fatal(err)
			}
			r, ok := again.Get(h, t0)
			if !ok || !slices.Equal(r.Owners, tc.owners) {
				t.Fatalf("after reboot: record=%+v ok=%v, want owners %v", r, ok, tc.owners)
			}

			// Once synced, the hash is no longer stale: an unchanged re-upload
			// writes nothing again.
			s.rec.Reset()
			if _, err := s.upload(t, "only copy", tc.disown, nil, t0); err != nil {
				t.Fatal(err)
			}
			if slices.Contains(s.rec.Ops(), "fsyncdir index") {
				t.Fatalf("stale mark not cleared by the sync: %q", s.rec.Ops())
			}
		})
	}
}
