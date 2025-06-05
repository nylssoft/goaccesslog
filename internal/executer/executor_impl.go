package executer

import (
	"os/exec"
)

type executor_impl struct{}

func (e *executor_impl) Exec(cmdName string, args ...string) ([]byte, error) {
	return exec.Command(cmdName, args...).CombinedOutput()
}
