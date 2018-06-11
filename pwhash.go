package hydrogen

// #cgo CFLAGS: -Ilibhydrogen
// #cgo LDFLAGS: -Llibhydrogen -lhydrogen
// #include <stdlib.h>
// #include <hydrogen.h>
import "C"

// import (
// 	"unsafe"
// )

const (
	PwHashContextBytes   int = C.hydro_pwhash_CONTEXTBYTES
	PwHashMasterKeyBytes int = C.hydro_pwhash_MASTERKEYBYTES
	PwHashStoredBytes    int = C.hydro_pwhash_STOREDBYTES
)

// Prototype:
// void hydro_pwhash_keygen(uint8_t master_key[hydro_pwhash_MASTERKEYBYTES]);
func PwHashKeygen() []byte {
	out := make([]byte, PwHashMasterKeyBytes)
	C.hydro_pwhash_keygen((*C.uchar)(&out[0]))
	return out
}

//
// TODO
//

// int hydro_pwhash_deterministic(uint8_t *h, size_t h_len, const char *passwd, size_t passwd_len, const char ctx[hydro_pwhash_CONTEXTBYTES], const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES], uint64_t opslimit, size_t memlimit, uint8_t threads);

// int hydro_pwhash_create(uint8_t stored[hydro_pwhash_STOREDBYTES], const char *passwd, size_t passwd_len, const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES], uint64_t opslimit, size_t memlimit, uint8_t threads);

// int hydro_pwhash_verify(const uint8_t stored[hydro_pwhash_STOREDBYTES], const char *passwd, size_t passwd_len, const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES], uint64_t opslimit_max, size_t memlimit_max, uint8_t threads_max);

// int hydro_pwhash_derive_static_key(uint8_t *static_key, size_t static_key_len, const uint8_t stored[hydro_pwhash_STOREDBYTES], const char *passwd, size_t passwd_len, const char ctx[hydro_pwhash_CONTEXTBYTES], const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES], uint64_t opslimit_max, size_t memlimit_max, uint8_t threads_max);

// int hydro_pwhash_reencrypt(uint8_t stored[hydro_pwhash_STOREDBYTES], const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES], const uint8_t new_master_key[hydro_pwhash_MASTERKEYBYTES]);

// int hydro_pwhash_upgrade(uint8_t stored[hydro_pwhash_STOREDBYTES], const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES], uint64_t opslimit, size_t memlimit, uint8_t threads);

//
// eof
//
