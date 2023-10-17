package util

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/coinbase/baseca/internal/types"
)

var BackoffSchedule = []time.Duration{
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
}

func LockfileBackoff(lockfilePath string) error {
	_, err := os.OpenFile(filepath.Clean(lockfilePath), os.O_RDONLY, 0400)
	if err == nil {
		// Backoff Until Lock File Removed
		for _, backoff := range BackoffSchedule {
			_, err = os.OpenFile(filepath.Clean(lockfilePath), os.O_RDONLY, 0400)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			time.Sleep(backoff)
		}
		return errors.New("subordinate ca lockfile present")
	}
	return nil
}

func GenerateLockfile(service string) error {
	// Lock Subordinate CA SSL
	lockfilePath := fmt.Sprintf("%s/%s/%s.lock", types.SubordinatePath, service, service)
	_, err := os.Create(filepath.Clean(lockfilePath))
	if err != nil {
		return fmt.Errorf("error generating lockfile [%s]", service)
	}
	return nil
}

func RemoveLockfile(service string) error {
	lockfilePath := fmt.Sprintf("%s/%s/%s.lock", types.SubordinatePath, service, service)
	err := os.Remove(filepath.Clean(lockfilePath))
	if err != nil {
		return fmt.Errorf("error removing lock file [%s]", service)
	}
	return nil
}
