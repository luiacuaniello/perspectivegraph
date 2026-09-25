// Package atomicfile writes files so that a crash, or a power cut, leaves either the old
// contents or the new ones - never neither.
//
// The file-backed governance stores (suppressions, tickets, history, validations, the
// KEV holdout) wrote a temp file and renamed it over the real one, which is atomic
// against other processes but not against the machine stopping: neither the file's data
// nor the rename was forced to disk, and after a crash a filesystem may keep the rename
// and lose the data behind it - an empty or truncated file where a triage board was.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write replaces path with data: a uniquely named temp file in the same directory,
// written and synced, renamed over path, and the directory synced so the rename is
// durable too.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tf, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := tf.Name()
	fail := func(err error) error {
		_ = tf.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := tf.Write(data); err != nil {
		return fail(err)
	}
	if err := tf.Chmod(perm); err != nil {
		return fail(err)
	}
	if err := tf.Sync(); err != nil {
		return fail(err)
	}
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return SyncDir(dir)
}

// SyncDir forces a directory's entries - a rename, a new file - to disk.
func SyncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the directory of an operator-configured store path
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
