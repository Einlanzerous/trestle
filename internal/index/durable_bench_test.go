package index

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Einlanzerous/trestle/internal/blob"
	"github.com/Einlanzerous/trestle/internal/durable"
)

// noDirSync is v0.2.0's behaviour: file fsyncs, no directory fsyncs.
type noDirSync struct{ durable.OS }

func (noDirSync) SyncDir(string) error { return nil }

// BenchmarkUpload measures a whole new upload (blob commit plus record write)
// with and without the directory fsyncs GENZO-30 adds. Run it on the disk the
// data dir lives on (TMPDIR decides where b.TempDir() is), not on a tmpfs:
//
//	TMPDIR=/path/on/the/data/disk go test -run '^$' -bench Upload ./internal/index/
func BenchmarkUpload(b *testing.B) {
	for _, size := range []int{64 << 10, 4 << 20} {
		for _, mode := range []struct {
			name string
			fs   durable.FS
		}{{"v0.2.0-no-dirsync", noDirSync{}}, {"dirsync", durable.OS{}}} {
			b.Run(fmt.Sprintf("%dKiB/%s", size>>10, mode.name), func(b *testing.B) {
				root := b.TempDir()
				blobs, err := blob.NewLocalFS(root, mode.fs)
				if err != nil {
					b.Fatal(err)
				}
				ix, err := OpenFS(filepath.Join(root, "index"), mode.fs)
				if err != nil {
					b.Fatal(err)
				}
				data := make([]byte, size)
				b.SetBytes(int64(size))
				n := uint64(0)
				for b.Loop() {
					n++
					binary.LittleEndian.PutUint64(data, n) // new bytes, new hash, every time
					sum := sha256.Sum256(data)
					h := hex.EncodeToString(sum[:])
					w, err := blobs.NewWriter(context.Background())
					if err != nil {
						b.Fatal(err)
					}
					if _, err := w.Write(data); err != nil {
						b.Fatal(err)
					}
					if _, _, err := ix.Add(Upload{SHA256: h, Bytes: int64(size), ContentType: "image/png", Ext: "png", Owner: "bench"},
						1<<62, t0, func() error { return w.Commit(h) }); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
