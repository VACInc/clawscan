//go:build !linux

package observatory

import (
	"fmt"
	"io/fs"
	"os"
)

func walkTargetTree(_ string, _ int, _ targetWalkFunc) error {
	return fmt.Errorf("secure target staging and inspection require a Linux control host")
}

func sameTargetFileSnapshot(before fs.FileInfo, after fs.FileInfo) bool {
	return before != nil && after != nil && before.Mode().IsRegular() && after.Mode().IsRegular() &&
		os.SameFile(before, after) && before.Size() == after.Size() && before.Mode() == after.Mode() &&
		before.ModTime().Equal(after.ModTime())
}
