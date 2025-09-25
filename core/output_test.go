package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutputSkipsDuplicateWrites(t *testing.T) {
	dir := t.TempDir()

	out := NewOutput(dir, "out.txt")
	t.Cleanup(func() { out.Close() })

	out.WriteToFile("alpha")
	out.WriteToFile("alpha")
	out.WriteToFile("ALPHA")
	out.WriteToFile("beta")
	out.Close()

	data, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "alpha" || lines[1] != "beta" {
		t.Fatalf("unexpected lines: %v", lines)
	}
}

func TestOutputLoadsExistingEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(path, []byte("gamma\n"), 0o600); err != nil {
		t.Fatalf("failed to seed file: %v", err)
	}

	out := NewOutput(dir, "existing.txt")
	t.Cleanup(func() { out.Close() })

	out.WriteToFile("gamma")
	out.WriteToFile("delta")
	out.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{"gamma", "delta"}
	if len(got) != len(want) {
		t.Fatalf("expected %d lines, got %d: %v", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d mismatch: want %q, got %q", i, want[i], got[i])
		}
	}
}
