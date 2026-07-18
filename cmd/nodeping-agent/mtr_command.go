package main

import (
	"context"
	"os/exec"
	"time"
)

func mtrCommandContext(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = time.Second
	configureMTRCommand(cmd)
	return cmd
}
