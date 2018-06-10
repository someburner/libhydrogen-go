package hydrogen

// #cgo CFLAGS: -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lhydrogen
// #include <hydrogen.h>
import "C"

import (
	"fmt"
	"runtime"
)

// VersionMajor returns the libhydrogen major version value
func VersionMajor() int {
	return C.HYDRO_VERSION_MAJOR
}

// VersionMinor returns the libhydrogen minor version value
func VersionMinor() int {
	return C.HYDRO_VERSION_MINOR
}

func VersionString() string {
	return fmt.Sprintf("%d.%d", VersionMajor(), VersionMinor())
}

func VersionVerbose() string {
	return fmt.Sprintf("libhydrogen v%s - (built with %s)", VersionString(), runtime.Version())
}
