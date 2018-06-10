package hydrogen

// #cgo CFLAGS: -Ilibhydrogen
// #cgo LDFLAGS: -Llibhydrogen -lhydrogen
// #include <stdlib.h>
// #include <hydrogen.h>
import "C"

import (
	"fmt"
	"unsafe"
)

func init() {
	result := int(C.hydro_init())
	if result != 0 {
		panic(fmt.Sprintf("hydrogen initialization failed, result code %d.", result))
	}
	// fmt.Println("libhydrogen initialized")
}

func CheckCtx(ctx string, wantlen int) {
	if len(ctx) != wantlen {
		panic(fmt.Sprintf("Bad context len. Want (%d), got (%d).", wantlen, len(ctx)))
	}
}

// CheckSize checks if the length of a byte slice is equal to the expected length,
// and panics when this is not the case.
func CheckSize(buf []byte, expected int, descrip string) {
	if len(buf) != expected {
		panic(fmt.Sprintf("Invalid \"%s\" size. Want (%d), got (%d).", descrip, expected, len(buf)))
	}
}

// CheckIntInRange checks if the size of an integer is between a lower and upper boundaries.
func CheckIntInRange(n int, min int, max int, descrip string) {
	if n < min || n > max {
		panic(fmt.Sprintf("Invalid \"%s\" size. Want (%d - %d), got (%d).", descrip, min, max, n))
	}
}

// CheckIntGt checks if n is > lower
func CheckIntGt(n int, lower int, descrip string) {
	if !(n > lower) {
		panic(fmt.Sprintf("%s is not > %d", descrip, lower))
	}
}

// CheckIntMin checks if n is > lower
func CheckIntGtOrEq(n int, lower int, descrip string) {
	if !(n >= lower) {
		panic(fmt.Sprintf("%s is not >= %d", descrip, lower))
	}
}

//MemZero sets the buffer to zero
func MemZero(buf []byte) {
	if len(buf) > 0 {
		C.hydro_memzero(unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	}
}

// NOTE: not a lexicographic comparator, not a replacement for memcmp
func MemEqual(buff1, buff2 []byte, length int) bool {
	if length >= len(buff1) || length >= len(buff2) {
		panic(fmt.Sprintf("Attempt to compare more bytes (%d) than provided "+
			"(%d, %d)", length, len(buff1), len(buff2)))
	}
	// bool hydro_equal(const void *b1_, const void *b2_, size_t len);
	return bool(C.hydro_equal(unsafe.Pointer(&buff1[0]), unsafe.Pointer(&buff2[0]), C.size_t(length)))
}

func Bin2hex(bin []byte) string {
	maxlen := len(bin)*2 + 1
	binPtr := (*C.uchar)(unsafe.Pointer(&bin[0]))
	buf := (*C.char)(C.malloc(C.size_t(maxlen)))
	defer C.free(unsafe.Pointer(buf))

	C.hydro_bin2hex(buf, C.size_t(maxlen), binPtr, C.size_t(len(bin)))

	return C.GoString(buf)
}

// AlignedSlice returns a memory aligned slice
func AlignedSlice(size, alignment int) []byte {
	slice := make([]byte, size+alignment)
	offset := alignment - int(uintptr(unsafe.Pointer(&slice[0])))%alignment
	return slice[offset : offset+size]
}

//
// eof
//
