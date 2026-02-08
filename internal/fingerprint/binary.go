package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func BinaryFingerprint() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable path: %w", err)
	}

	f, err := os.Open(exe)
	if err != nil {
		return "", fmt.Errorf("open binary: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash binary: %w", err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
