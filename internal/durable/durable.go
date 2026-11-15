// Package durable is the one seam between Trestle's storage and the
// filesystem calls whose order decides what survives a power loss.
//
// A rename or an unlink changes a directory, and the change is only on stable
// storage once that directory has been fsynced: fsyncing the file that was
// renamed is not enough (on ext4 with default mount options the unsynced
// window is usually a few seconds). Every call that changes a directory Trestle
// relies on, and every fsync that makes it durable, goes through an FS, so a
// test can record the calls and assert their order (GENZO-30).
package durable

import (
	"fmt"
	"os"
)

// FS is the filesystem as far as durability is concerned. Paths are absolute
// or relative to the process's working directory, as with package os.
type FS interface {
	// SyncFile flushes f's contents to stable storage.
	SyncFile(f *os.File) error
	// Rename is os.Rename.
	Rename(oldpath, newpath string) error
	// Remove is os.Remove.
	Remove(name string) error
	// Mkdir is os.Mkdir.
	Mkdir(name string, perm os.FileMode) error
	// SyncDir flushes the directory dir, making the renames, unlinks and
	// creations of its entries durable.
	SyncDir(dir string) error
}

// OS is the real filesystem.
type OS struct{}

func (OS) SyncFile(f *os.File) error                 { return f.Sync() }
func (OS) Rename(oldpath, newpath string) error      { return os.Rename(oldpath, newpath) }
func (OS) Remove(name string) error                  { return os.Remove(name) }
func (OS) Mkdir(name string, perm os.FileMode) error { return os.Mkdir(name, perm) }

// SyncDir opens dir read-only and fsyncs it. Linux (ext4, xfs, btrfs) honours
// an fsync on a directory descriptor; that is the platform Trestle ships on.
func (OS) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sync dir: %w", err)
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return fmt.Errorf("sync dir %s: %w", dir, err)
	}
	return d.Close()
}
