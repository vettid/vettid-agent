package run

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The batch-run path check (batch_windows.go, batchPathText) reads the
// code page with GetACP, which gives the system's, the one a program the
// batch starts uses, only while the connector has no activeCodePage
// manifest: with a UTF-8 one it would answer 65001 and pass every path.
// This fails if a manifest, a compiled resource (.syso) or an
// activeCodePage element (as a manifest would declare it) is added to the
// repository.
func TestNoActiveCodePageManifest(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("the repository root isn't %s: %v", root, err)
	}
	self, _ := filepath.Abs("manifest_test.go")
	// The element, not the word: comments name it.
	needle := []byte(strings.ToLower("<" + "activeCodePage"))
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".manifest", ".syso":
			t.Errorf("%s: a Windows manifest or resource; check its activeCodePage first (batchPathText)", p)
			return nil
		}
		if p == self {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if bytes.Contains(bytes.ToLower(b), needle) {
			t.Errorf("%s declares an activeCodePage; batchPathText relies on there being none", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
