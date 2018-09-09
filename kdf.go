package hydrogen

// #cgo CFLAGS: -Ilibhydrogen
// #cgo LDFLAGS: -Llibhydrogen -lhydrogen
// #include <stdlib.h>
// #include <hydrogen.h>
import "C"

const (
	KdfContextBytes int = C.hydro_kdf_CONTEXTBYTES
	KdfKeyBytes     int = C.hydro_kdf_KEYBYTES
	KdfMaxBytes     int = C.hydro_kdf_BYTES_MAX
	KdfMinBytes     int = C.hydro_kdf_BYTES_MIN
)

// Prototype:
// void hydro_kdf_keygen(uint8_t key[hydro_kdf_KEYBYTES]);
func KdfKeygen() []byte {
	buf := make([]byte, KdfKeyBytes)
	C.hydro_kdf_keygen((*C.uint8_t)(&buf[0]))
	return buf
}

// Prototype:
// int hydro_kdf_derive_from_key(uint8_t *subkey, size_t subkey_len, uint64_t subkey_id, const char ctx[hydro_kdf_CONTEXTBYTES], const uint8_t key[hydro_kdf_KEYBYTES]);
func KdfDeriveFromKey(subkey_len int, id uint64, ctx string, master_key []byte) ([]byte, int) {
	CheckSize(master_key, KdfKeyBytes, "kdf-master_key")
	CheckCtx(ctx, KdfContextBytes)
	CheckIntInRange(subkey_len, KdfMinBytes, KdfMaxBytes, "kdf-subkey_len")
	out := make([]byte, subkey_len)

	exit := int(C.hydro_kdf_derive_from_key(
		(*C.uint8_t)(&out[0]),
		(C.size_t)(subkey_len),
		(C.uint64_t)(id),
		C.CString(ctx),
		(*C.uint8_t)(&master_key[0])))

	return out, exit
}

//
// eof
//
