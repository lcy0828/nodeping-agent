//go:build !linux

package main

import "os/exec"

func configureMTRCommand(_ *exec.Cmd) {}
