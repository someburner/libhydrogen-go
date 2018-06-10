package hydrogen

// #cgo CFLAGS: -Ilibhydrogen
// #cgo LDFLAGS: -Llibhydrogen -lhydrogen
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
func RandomU32() uint32 {
	// uint32_t hydro_random_u32(void);
	return uint32(C.hydro_random_u32())
}

// returns an unpredictable value between 0 and upper_bound (excluded)
// uint32_t hydro_random_uniform(const uint32_t upper_bound);
func RandomUniform(upper_bound uint32) uint32 {
	// uint32_t hydro_random_u32(void);
	return uint32(C.hydro_random_uniform( C.uint(upper_bound) ))
}

func RandomBuf(l int) []byte {
	CheckIntGreater(l, 0, "random buf size")
	// void hydro_random_buf(void *buf, size_t len);
	out := make([]byte, l)
	C.hydro_random_buf(unsafe.Pointer(&out[0]), C.size_t(l))
	return out
}

func RandomBufDeterministic(l int, seed []byte) []byte {
	CheckSize(seed, RandomSeedBytes, "seed")
	CheckIntGreater(l, 0, "random buf det size")
	out := make([]byte, l)
	// void hydro_random_buf_deterministic(void *buf, size_t len, const uint8_t seed[hydro_random_SEEDBYTES]);
	C.hydro_random_buf_deterministic(
		unsafe.Pointer(&out[0]),
		C.size_t(l),
		(*C.uchar)(&seed[0]))
	return out
}

func RandomRatchet() {
	// void hydro_random_ratchet(void);
	C.hydro_random_ratchet()
}

func RandomReseed() {
	// void hydro_random_reseed(void);
	C.hydro_random_reseed()
}


//
// eof
//
