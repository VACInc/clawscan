//go:build !linux

package main

import (
	"errors"

	"github.com/openclaw/clawscan/internal/observatory"
)

func writeMatrixOutput(string, observatory.MatrixResult) error {
	return errors.New("secure matrix output requires a Linux control host")
}
