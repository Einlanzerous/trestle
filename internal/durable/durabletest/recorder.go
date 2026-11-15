// Package durabletest records the calls a store makes through a durable.FS,
// so a test can assert which renames, unlinks and fsyncs happen and in what
// order.
package durabletest

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Einlanzerous/trestle/internal/durable"
)

// Recorder performs every call on the real filesystem (through durable.OS)
// and logs it as "op path" or "op old -> new", with paths relative to Root
// and every random temp name replaced by "<tmp>".
type Recorder struct {
	Root string

	mu  sync.Mutex
	ops []string
	// FailSyncDir, when set, is returned by SyncDir for the directory with
	// that (Root-relative) name instead of syncing it.
	FailSyncDir map[string]error
}

var _ durable.FS = (*Recorder)(nil)

// New records calls under root.
func New(root string) *Recorder { return &Recorder{Root: root} }

// Ops returns the calls so far.
func (r *Recorder) Ops() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ops...)
}

// Reset forgets the calls so far.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = nil
}

func (r *Recorder) log(op string, paths ...string) {
	rel := make([]string, len(paths))
	for i, p := range paths {
		rel[i] = r.rel(p)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, op+" "+strings.Join(rel, " -> "))
}

// rel makes p relative to Root and hides temp names: an upload's temp file
// under tmp/ and an index record's ".<hash>.*" temp file are random.
func (r *Recorder) rel(p string) string {
	rp, err := filepath.Rel(r.Root, p)
	if err != nil || strings.HasPrefix(rp, "..") {
		return p
	}
	rp = filepath.ToSlash(rp)
	if rp == "." {
		return rp
	}
	dir, base := filepath.Split(rp)
	if dir == "tmp/" || strings.HasPrefix(base, ".") {
		return dir + "<tmp>"
	}
	return rp
}

func (r *Recorder) SyncFile(f *os.File) error {
	r.log("fsync", f.Name())
	return durable.OS{}.SyncFile(f)
}

func (r *Recorder) Rename(oldpath, newpath string) error {
	r.log("rename", oldpath, newpath)
	return durable.OS{}.Rename(oldpath, newpath)
}

func (r *Recorder) Remove(name string) error {
	r.log("unlink", name)
	return durable.OS{}.Remove(name)
}

func (r *Recorder) Mkdir(name string, perm os.FileMode) error {
	r.log("mkdir", name)
	return durable.OS{}.Mkdir(name, perm)
}

func (r *Recorder) SyncDir(dir string) error {
	r.log("fsyncdir", dir)
	r.mu.Lock()
	err := r.FailSyncDir[r.rel(dir)]
	r.mu.Unlock()
	if err != nil {
		return err
	}
	return durable.OS{}.SyncDir(dir)
}
