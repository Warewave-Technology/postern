package record

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Store owns the on-disk layout of recordings.
type Store struct {
	dir string
	re  *regexp.Regexp
}

// NewStore prepares the recordings root.
func NewStore(dir string) (*Store, error) {
	err := os.MkdirAll(dir, 0o700)
	if err != nil {
		return nil, fmt.Errorf("record.store.NewStore: %w", err)
	}

	fileNamePattern := `^[a-zA-Z0-9_-]+$`
	re := regexp.MustCompile(fileNamePattern)

	return &Store{dir: dir, re: re}, nil
}

// Create opens a new .cast file for sessionID and returns it with its path.
func (s *Store) Create(sessionID string) (*os.File, string, error) {
	if !s.re.MatchString(sessionID) {
		return nil, "", fmt.Errorf("record.store.Create: invalid session id")
	}

	path := filepath.Join(s.dir, time.Now().Format("2006-01-02"))
	fullPath := filepath.Join(path, fmt.Sprintf("%s.cast", sessionID))
	err := os.MkdirAll(path, 0o700)
	if err != nil {
		return nil, "", fmt.Errorf("record.store.Create: %w", err)
	}

	f, err := os.OpenFile(fullPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, "", fmt.Errorf("record.store.Create: %w", err)
	}

	return f, fullPath, nil
}

// NewSessionID returns a random, filesystem-safe session identifier.
func NewSessionID() (string, error) {
	sessionID := make([]byte, 16)
	_, err := rand.Read(sessionID)
	if err != nil {
		return "", fmt.Errorf("record.store.NewSessionID: %w", err)
	}

	return hex.EncodeToString(sessionID), nil
}
