package hydrogen

// #cgo LDFLAGS: -lhydrogen
// #include <stdlib.h>
// #include <hydrogen.h>
import "C"

import (
	"unsafe"
)

const (
	RandomSeedBytes int = C.hydro_random_SEEDBYTES
)

// returns an unpredicatable value from 0 - 0xffffffff (included)
// Prototype:
// uint32_t hydro_random_u32(void);
func RandomU32() uint32 {
	return uint32(C.hydro_random_u32())
}

// returns an unpredictable value between 0 and upper_bound (excluded)
// Prototype:
// uint32_t hydro_random_uniform(const uint32_t upper_bound);
func RandomUniform(upper_bound uint32) uint32 {
	return uint32(C.hydro_random_uniform(C.uint(upper_bound)))
}

// Prototype:
// void hydro_random_buf(void *buf, size_t len);
func RandomBuf(l int) []byte {
	CheckIntGt(l, 0, "random buf size")
	out := make([]byte, l)
	C.hydro_random_buf(unsafe.Pointer(&out[0]), C.size_t(l))
	return out
}

// Prototype:
// void hydro_random_buf_deterministic(void *buf, size_t len, const uint8_t seed[hydro_random_SEEDBYTES]);
func RandomBufDeterministic(l int, seed []byte) []byte {
	CheckSize(seed, RandomSeedBytes, "seed")
	CheckIntGt(l, 0, "random buf det size")
	out := make([]byte, l)

	C.hydro_random_buf_deterministic(
		unsafe.Pointer(&out[0]),
		C.size_t(l),
		(*C.uint8_t)(&seed[0]))

	return out
}

// Prototype:
// void hydro_random_ratchet(void);
func RandomRatchet() {
	C.hydro_random_ratchet()
}

// Prototype:
// void hydro_random_reseed(void);
func RandomReseed() {
	C.hydro_random_reseed()
}
