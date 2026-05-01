//go:build !windows

package main

import (
	"os"
	"syscall"
)

func redirectStdoutStderrToFile(logPath string) error {
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer lf.Close()

	if err := syscall.Dup2(int(lf.Fd()), 1); err != nil {
		return err
	}
	if err := syscall.Dup2(int(lf.Fd()), 2); err != nil {
		return err
	}
	return nil
}
