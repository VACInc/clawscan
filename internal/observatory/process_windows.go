//go:build windows

package observatory

import (
	"os"
	"os/exec"
	"time"
)

func configureCommandProcessGroup(command *exec.Cmd) {
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return command.Process.Kill()
	}
	command.WaitDelay = 5 * time.Second
}
