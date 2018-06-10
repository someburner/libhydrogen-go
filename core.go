package hydrogen

// #cgo CFLAGS: -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lhydrogen
// #include <hydrogen.h>
import "C"

import (
	"fmt"
)

func init() {
	result := int(C.hydro_init())
	if result != 0 {
		panic(fmt.Sprintf("hydrogen initialization failed, result code %d.", result))
	}
	fmt.Println("libhydrogen initialized")
}
