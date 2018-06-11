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
	HashBytes        int = C.hydro_hash_BYTES
	HashBytesMax     int = C.hydro_hash_BYTES_MAX
	HashBytesMin     int = C.hydro_hash_BYTES_MIN
	HashContextBytes int = C.hydro_hash_CONTEXTBYTES
	HashKeyBytes     int = C.hydro_hash_KEYBYTES
)

// void hydro_hash_keygen(uint8_t *key);
func HashKeygen() []byte {
	out := make([]byte, HashKeyBytes)
	C.hydro_hash_keygen((*C.uchar)(&out[0]))
	return out
}

// int hydro_hash_hash(uint8_t *out, size_t out_len, const void *in_, size_t in_len, const char ctx[hydro_hash_CONTEXTBYTES], const uint8_t *key);
func HashHash(out_len int, data []byte, ctx string, key []byte) ([]byte, int) {
	CheckCtx(ctx, HashContextBytes)
	CheckIntGtOrEq(out_len, HashBytes, "hash out_len")
	data_len := len(data)
	out := make([]byte, out_len)
	var exit int
	if key != nil {
		exit = int(C.hydro_hash_hash(
			(*C.uchar)(&out[0]),
			(C.size_t)(out_len),
			unsafe.Pointer(&data[0]),
			(C.size_t)(data_len),
			C.CString(ctx),
			(*C.uchar)(&key[0])))
	} else {
		exit = int(C.hydro_hash_hash(
			(*C.uchar)(&out[0]),
			(C.size_t)(out_len),
			unsafe.Pointer(&data[0]),
			(C.size_t)(data_len),
			C.CString(ctx),
			nil))
	}
	return out, exit
}

type HashState struct {
	inner *C.hydro_hash_state
}

type HashHelper struct {
	state   HashState
	context string
}

//
// TODO
//

// int hydro_hash_init(hydro_hash_state *state, const char ctx[hydro_hash_CONTEXTBYTES], const uint8_t *key);

// int hydro_hash_update(hydro_hash_state *state, const void *in_, size_t in_len);

// int hydro_hash_final(hydro_hash_state *state, uint8_t *out, size_t out_len);

//
// eof
//
