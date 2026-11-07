package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestIsDomainInListConcurrentLookups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte("example.com\n.example.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadDomainList(path); err != nil {
		t.Fatal(err)
	}

	const workers, lookups = 16, 500
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range lookups {
				if _, ok := isDomainInList("example.com"); !ok {
					t.Error("example.com not matched")
					return
				}
				if _, ok := isDomainInList("not-listed.net"); ok {
					t.Error("not-listed.net matched")
					return
				}
			}
		}()
	}
	wg.Wait()

	if count, _ := isDomainInList("example.com"); count != workers*lookups+1 {
		t.Errorf("count = %d, want %d", count, workers*lookups+1)
	}
}
