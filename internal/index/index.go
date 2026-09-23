// Package index is the flat-file record index: one JSON file per blob under
// <data>/index/, all of it held in memory, every change written atomically.
//
// Flat files rather than SQLite because the only queries are "by hash" and
// "by owner" over thousands of rows, and a backup is `tar` of the data dir.
package index

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNotFound covers unknown, expired and not-yours alike: the API does
	// not confirm who else uploaded what.
	ErrNotFound = errors.New("index: not found")
	// ErrQuota is an upload that would take its owner past the quota.
	ErrQuota = errors.New("index: quota exceeded")
)

// Record is the on-disk and in-memory shape of one blob's metadata.
type Record struct {
	SHA256      string     `json:"sha256"`
	Bytes       int64      `json:"bytes"`
	ContentType string     `json:"content_type"`
	Ext         string     `json:"ext"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Owners      []string   `json:"owners"`
}

// Expired is what every read path checks, so an expired blob is gone the
// moment it expires; the sweep only reclaims the disk.
func (r Record) Expired(now time.Time) bool {
	return r.ExpiresAt != nil && !now.Before(*r.ExpiresAt)
}

// Owns reports whether name is among the tokens that uploaded these bytes.
func (r Record) Owns(name string) bool { return slices.Contains(r.Owners, name) }

func (r Record) clone() Record {
	r.Owners = slices.Clone(r.Owners)
	if r.ExpiresAt != nil {
		t := *r.ExpiresAt
		r.ExpiresAt = &t
	}
	return r
}

// Upload is what one POST contributes to a record.
type Upload struct {
	SHA256      string
	Bytes       int64
	ContentType string
	Ext         string
	Owner       string
	ExpiresAt   *time.Time // nil: permanent
}

// Index is safe for concurrent use. One mutex covers the map, the files and
// the blob side-effects passed in as callbacks, so an upload, a delete and a
// sweep of the same hash are serialised end to end.
type Index struct {
	dir  string
	mu   sync.Mutex
	recs map[string]*Record
}

// Open creates dir if needed and loads every record in it. A record that
// does not parse refuses the boot rather than being skipped: writes are
// atomic, so a bad file was put there by hand, and silently dropping it
// would drop someone's ownership.
func Open(dir string) (*Index, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	ix := &Index{dir: dir, recs: map[string]*Record{}}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			// A temp file from a write that never reached its rename.
			_ = os.Remove(filepath.Join(dir, name))
			continue
		}
		hash, ok := strings.CutSuffix(name, ".json")
		if !ok || e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("index: %w", err)
		}
		var r Record
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("index: %s: %w", name, err)
		}
		if r.SHA256 != hash {
			return nil, fmt.Errorf("index: %s holds a record for %q", name, r.SHA256)
		}
		ix.recs[hash] = &r
	}
	return ix, nil
}

// Get returns the live record for hash.
func (ix *Index) Get(hash string, now time.Time) (Record, bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	r, ok := ix.recs[hash]
	if !ok || r.Expired(now) {
		return Record{}, false
	}
	return r.clone(), true
}

// Hashes returns every record's hash, expired or not: an expired record's
// blob is the sweep's to delete, not an orphan.
func (ix *Index) Hashes() []string {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	out := make([]string, 0, len(ix.recs))
	for h := range ix.recs {
		out = append(out, h)
	}
	return out
}

// Owned returns owner's live records, newest first.
func (ix *Index) Owned(owner string, now time.Time) []Record {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	var out []Record
	for _, r := range ix.recs {
		if r.Owns(owner) && !r.Expired(now) {
			out = append(out, r.clone())
		}
	}
	slices.SortFunc(out, func(a, b Record) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.SHA256, b.SHA256)
	})
	return out
}

// Add merges u into the index and reports whether a live record already
// existed. commit runs under the lock after the quota check passes and before
// the record is written, so the blob is only moved into place for an upload
// that will be recorded, and never races a delete or sweep of the same hash.
func (ix *Index) Add(u Upload, quota int64, now time.Time, commit func() error) (Record, bool, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()

	cur, existed := ix.recs[u.SHA256]
	if existed && cur.Expired(now) {
		// Expired is gone, whether or not the sweep has run: the old owners
		// and dates must not carry over to bytes someone uploads afresh.
		existed = false
	}

	var next Record
	if existed {
		next = cur.clone()
	} else {
		next = Record{
			SHA256:      u.SHA256,
			Bytes:       u.Bytes,
			ContentType: u.ContentType,
			Ext:         u.Ext,
			CreatedAt:   now.UTC().Truncate(time.Second),
			ExpiresAt:   u.ExpiresAt,
		}
	}

	if !next.Owns(u.Owner) {
		// A shared blob counts fully against each owner, deliberately; an
		// owner re-uploading its own bytes adds nothing, so extending an
		// expiry works even at the quota.
		if ix.usedLocked(u.Owner, now)+next.Bytes > quota {
			return Record{}, false, ErrQuota
		}
		next.Owners = append(next.Owners, u.Owner)
	}
	if existed {
		next.ExpiresAt = laterExpiry(next.ExpiresAt, u.ExpiresAt)
	}

	if err := commit(); err != nil {
		return Record{}, false, err
	}
	if existed && sameRecord(*cur, next) {
		return next.clone(), true, nil
	}
	if err := ix.writeLocked(next); err != nil {
		return Record{}, false, err
	}
	ix.recs[next.SHA256] = &next
	return next.clone(), existed, nil
}

// laterExpiry enforces "expiry only ever extends": nil is permanent and
// beats any time, otherwise the later time wins. A URL already pasted
// somewhere must not be shortened by a stranger re-uploading the same bytes.
func laterExpiry(a, b *time.Time) *time.Time {
	if a == nil || b == nil {
		return nil
	}
	if b.After(*a) {
		return b
	}
	return a
}

func sameRecord(a, b Record) bool {
	if !slices.Equal(a.Owners, b.Owners) {
		return false
	}
	if (a.ExpiresAt == nil) != (b.ExpiresAt == nil) {
		return false
	}
	return a.ExpiresAt == nil || a.ExpiresAt.Equal(*b.ExpiresAt)
}

func (ix *Index) usedLocked(owner string, now time.Time) int64 {
	var n int64
	for _, r := range ix.recs {
		if r.Owns(owner) && !r.Expired(now) {
			n += r.Bytes
		}
	}
	return n
}

// Disown removes owner from hash's record. When the last owner goes, the
// record file is removed and then onLast runs (under the lock) to delete the
// blob: a crash between the two leaves an orphan blob, which costs disk,
// rather than a record pointing at nothing.
func (ix *Index) Disown(hash, owner string, now time.Time, onLast func() error) error {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	cur, ok := ix.recs[hash]
	if !ok || cur.Expired(now) || !cur.Owns(owner) {
		return ErrNotFound
	}
	next := cur.clone()
	next.Owners = slices.DeleteFunc(next.Owners, func(o string) bool { return o == owner })
	if len(next.Owners) > 0 {
		if err := ix.writeLocked(next); err != nil {
			return err
		}
		ix.recs[hash] = &next
		return nil
	}
	if err := ix.removeLocked(hash); err != nil {
		return err
	}
	return onLast()
}

// Sweep removes every record expired at now, calling del for each blob under
// the lock so an upload of the same bytes cannot land in between. It keeps
// going past a failing del and returns the first error with what it removed.
func (ix *Index) Sweep(now time.Time, del func(hash string) error) ([]Record, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	var removed []Record
	var first error
	for hash, r := range ix.recs {
		if !r.Expired(now) {
			continue
		}
		if err := ix.removeLocked(hash); err != nil {
			first = firstErr(first, err)
			continue
		}
		removed = append(removed, r.clone())
		if err := del(hash); err != nil {
			first = firstErr(first, err)
		}
	}
	return removed, first
}

func firstErr(first, err error) error {
	if first != nil {
		return first
	}
	return err
}

func (ix *Index) file(hash string) string { return filepath.Join(ix.dir, hash+".json") }

// writeLocked is temp-file + fsync + rename, so a crash leaves either the old
// record or the new one, never half of either.
func (ix *Index) writeLocked(r Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("index: %w", err)
	}
	f, err := os.CreateTemp(ix.dir, "."+r.SHA256+".*")
	if err != nil {
		return fmt.Errorf("index: %w", err)
	}
	tmp := f.Name()
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, ix.file(r.SHA256))
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("index: %w", err)
	}
	return nil
}

func (ix *Index) removeLocked(hash string) error {
	if err := os.Remove(ix.file(hash)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("index: %w", err)
	}
	delete(ix.recs, hash)
	return nil
}
