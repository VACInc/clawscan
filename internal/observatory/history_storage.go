package observatory

import (
	"errors"
	"io/fs"
)

const (
	historyDirectoryMode fs.FileMode = 0o700
	historyFileMode      fs.FileMode = 0o600
)

var (
	errHistoryPathExist    = errors.New("history path already exists")
	errHistoryPathNotExist = errors.New("history path does not exist")
)
