//go:build !linux

package observatory

import "errors"

var errSecureGradeOutputRequiresLinux = errors.New("secure create-only grade output requires a Linux control host; use stdout on this platform")

// A portable os.OpenFile(O_EXCL) protects only the final component. It cannot
// pin and no-follow every ancestor, so silently falling back would violate the
// grade export contract and reintroduce path-swap/clobber risk. Stdout remains
// cross-platform; file export fails closed until an equivalent platform-native
// descriptor walk exists.
func WriteGradeFile(_ string, _ Grade) error {
	return errSecureGradeOutputRequiresLinux
}

func CheckGradeOutputAvailable(_ string) error {
	return errSecureGradeOutputRequiresLinux
}
