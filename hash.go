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

// Prototype:
// void hydro_hash_keygen(uint8_t *key);
func HashKeygen() []byte {
	out := make([]byte, HashKeyBytes)
	C.hydro_hash_keygen((*C.uint8_t)(&out[0]))
	return out
}

// Prototype:
// int hydro_hash_hash(uint8_t *out, size_t out_len, const void *in_, size_t in_len, const char ctx[hydro_hash_CONTEXTBYTES], const uint8_t *key);
func HashHash(out_len int, data []byte, ctx string, key []byte) ([]byte, int) {
	CheckCtx(ctx, HashContextBytes)
	CheckIntInRange(out_len, HashBytesMin, HashBytesMax, "hash out_len")
	data_len := len(data)
	cCtx := []byte(ctx)
	out := make([]byte, out_len)

	var exit int
	if key != nil {
		exit = int(C.hydro_hash_hash(
			(*C.uint8_t)(&out[0]),
			(C.size_t)(out_len),
			unsafe.Pointer(&data[0]),
			(C.size_t)(data_len),
			(*C.char)(unsafe.Pointer(&cCtx[0])),
			(*C.uint8_t)(&key[0])))
	} else {
		exit = int(C.hydro_hash_hash(
			(*C.uint8_t)(&out[0]),
			(C.size_t)(out_len),
			unsafe.Pointer(&data[0]),
			(C.size_t)(data_len),
			(*C.char)(unsafe.Pointer(&cCtx[0])),
			nil))
	}
	return out, exit
}

/* --------------------------------- Multi ---------------------------------- */

//
// TODO: detached methods
//

type HashState struct {
	inner *C.hydro_hash_state
}

type HashHelper struct {
	state   HashState
	context string
}

// Create a new HashState object. Does not initialize it.
func NewHashState() HashState {
	buf := new(C.hydro_hash_state)
	out := HashState{buf}
	return out
}

// Prototype:
// int hydro_hash_init(hydro_hash_state *state, const char ctx[hydro_hash_CONTEXTBYTES], const uint8_t key[hydro_hash_KEYBYTES]);
func NewHashHelper(ctx string, key []byte) HashHelper {
	CheckCtx(ctx, HashContextBytes)
	cCtx := []byte(ctx)
	st := NewHashState()
	if key != nil {
		CheckSize(key, HashKeyBytes, "hashkey")
		C.hydro_hash_init(
			st.inner,
			(*C.char)(unsafe.Pointer(&cCtx[0])),
			(*C.uint8_t)(&key[0]))
	} else {
		C.hydro_hash_init(
			st.inner,
			(*C.char)(unsafe.Pointer(&cCtx[0])),
			nil)
	}
	return HashHelper{
		state:   st,
		context: ctx,
	}
}

// Prototype:
// int hydro_hash_update(hydro_hash_state *state, const void *in_, size_t in_len);
func (h *HashHelper) Update(m []byte) {
	mlen := len(m)
	C.hydro_hash_update(
		h.state.inner,
		unsafe.Pointer(&m[0]),
		(C.size_t)(mlen))
}

// Prototype:
// int hydro_hash_final(hydro_hash_state *state, uint8_t *out, size_t out_len);
func (h *HashHelper) Final(out_len int) []byte {
	CheckIntInRange(out_len, HashBytesMin, HashBytesMax, "hash out_len")
	out := make([]byte, out_len)
	C.hydro_hash_final(
		h.state.inner,
		(*C.uint8_t)(&out[0]),
		(C.size_t)(out_len))
	return out
}
