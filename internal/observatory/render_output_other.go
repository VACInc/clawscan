//go:build !linux

package observatory

import (
	"errors"
	"os"
)

var errLinuxControlHostRequired = errors.New("secure site rendering requires a Linux control host")

func openRenderOutputDirectory(_ string, _ os.FileMode) (*os.File, error) {
	return nil, errLinuxControlHostRequired
}

func openRenderOutputFile(_ *os.File, _ string, _ os.FileMode) (*os.File, error) {
	return nil, errLinuxControlHostRequired
}
