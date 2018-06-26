package tools

import (
	"os/exec"
)

// Command is Func
func Command(cmd string) (stdout []byte, err error) {
	result := exec.Command("bash", "-c", cmd)
	stdout, err = result.CombinedOutput()
	return
}
