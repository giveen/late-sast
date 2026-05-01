//go:build windows

package main

func redirectStdoutStderrToFile(_ string) error {
	// Intentionally a no-op on Windows for now. This preserves cross-platform
	// builds without relying on Unix-only syscall.Dup2.
	return nil
}
