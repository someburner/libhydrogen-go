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
	PwHashContextBytes   int = C.hydro_pwhash_CONTEXTBYTES
	PwHashMasterKeyBytes int = C.hydro_pwhash_MASTERKEYBYTES
	PwHashStoredBytes    int = C.hydro_pwhash_STOREDBYTES

	PwHashDeterministicMemLimit int = 0
	PwHashDeterministicThreads  int = 1
)

// Prototype:
// void hydro_pwhash_keygen(uint8_t master_key[hydro_pwhash_MASTERKEYBYTES]);
func PwHashKeygen() []byte {
	out := make([]byte, PwHashMasterKeyBytes)
	C.hydro_pwhash_keygen((*C.uint8_t)(&out[0]))
	return out
}

// Prototype:
// int hydro_pwhash_deterministic(uint8_t *h, size_t h_len, const char *passwd,
//     size_t passwd_len, const char ctx[hydro_pwhash_CONTEXTBYTES],
//     const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES],
//     uint64_t opslimit, size_t memlimit, uint8_t threads);
func PwHashDeterministic(h_len int, passwd string, ctx string, master_key []byte, opslimit uint64) ([]byte, int) {
	CheckIntGt(h_len, 0, "h_len")
	CheckIntGt(len(passwd), 0, "len(passwd)")
	CheckCtx(ctx, PwHashContextBytes)
	CheckSize(master_key, PwHashMasterKeyBytes, "len(master_key)")
	cCtx := []byte(ctx)
	cPasswd := []byte(passwd)
	out := make([]byte, h_len)

	exit := int(C.hydro_pwhash_deterministic(
		(*C.uint8_t)(&out[0]),
		C.size_t(h_len),
		(*C.char)(unsafe.Pointer(&cPasswd[0])),
		C.size_t(len(passwd)),
		(*C.char)(unsafe.Pointer(&cCtx[0])),
		(*C.uint8_t)(&master_key[0]),
		C.size_t(opslimit),
		C.ulonglong(PwHashDeterministicMemLimit),
		C.uint8_t(PwHashDeterministicThreads)))

	return out, exit
}

// Prototype:
// int hydro_pwhash_create(uint8_t stored[hydro_pwhash_STOREDBYTES],
//     const char *passwd, size_t passwd_len,
//     const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES], uint64_t opslimit,
//     size_t memlimit, uint8_t threads);
func PwHashCreate(passwd string, master_key []byte, opslimit uint64, memlimit int, threads uint8) ([]byte, int) {
	CheckIntGt(len(passwd), 0, "len(passwd)")
	CheckSize(master_key, PwHashMasterKeyBytes, "master_key len")
	cPasswd := []byte(passwd)
	out := make([]byte, PwHashStoredBytes)

	exit := int(C.hydro_pwhash_create(
		(*C.uint8_t)(&out[0]),
		(*C.char)(unsafe.Pointer(&cPasswd[0])),
		C.size_t(len(passwd)),
		(*C.uint8_t)(&master_key[0]),
		C.uint64_t(opslimit),
		C.size_t(memlimit),
		C.uint8_t(threads)))

	return out, exit
}

// Prototype:
// int hydro_pwhash_verify(const uint8_t stored[hydro_pwhash_STOREDBYTES],
//     const char *passwd, size_t passwd_len,
//     const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES],
//     uint64_t opslimit_max, size_t memlimit_max, uint8_t threads_max);
func PwHashVerify(stored []byte, passwd string, master_key []byte, opslimit_max uint64, memlimit_max int, threads_max uint8) int {
	CheckIntGt(len(passwd), 0, "len(passwd)")
	CheckSize(stored, PwHashStoredBytes, "stored len")
	CheckSize(master_key, PwHashMasterKeyBytes, "master_key len")
	cPasswd := []byte(passwd)

	exit := int(C.hydro_pwhash_verify(
		(*C.uint8_t)(&stored[0]),
		(*C.char)(unsafe.Pointer(&cPasswd[0])),
		C.size_t(len(passwd)),
		(*C.uint8_t)(&master_key[0]),
		C.uint64_t(opslimit_max),
		C.size_t(memlimit_max),
		C.uint8_t(threads_max)))

	return exit
}

// Prototype:
// int hydro_pwhash_derive_static_key(uint8_t *static_key,
//     size_t static_key_len, const uint8_t stored[hydro_pwhash_STOREDBYTES],
//     const char *passwd, size_t passwd_len,
//     const char ctx[hydro_pwhash_CONTEXTBYTES],
//     const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES],
//     uint64_t opslimit_max, size_t memlimit_max, uint8_t threads_max);
func PwHashDeriveStaticKey(static_key_len int, stored []byte, passwd string, ctx string, master_key []byte, opslimit_max uint64, memlimit_max int, threads_max uint8) ([]byte, int) {
	CheckIntGt(static_key_len, 0, "len(static_key_len)")
	CheckSize(stored, PwHashStoredBytes, "stored len")
	CheckIntGt(len(passwd), 0, "len(passwd)")
	CheckCtx(ctx, PwHashContextBytes)
	CheckSize(master_key, PwHashMasterKeyBytes, "master_key len")
	cPasswd := []byte(passwd)
	cCtx := []byte(ctx)
	static_key := make([]byte, static_key_len)

	exit := int(C.hydro_pwhash_derive_static_key(
		(*C.uint8_t)(&static_key[0]),
		(C.size_t)(static_key_len),
		(*C.uint8_t)(&stored[0]),
		(*C.char)(unsafe.Pointer(&cPasswd[0])),
		C.size_t(len(passwd)),
		(*C.char)(unsafe.Pointer(&cCtx[0])),
		(*C.uint8_t)(&master_key[0]),
		C.uint64_t(opslimit_max),
		C.size_t(memlimit_max),
		C.uint8_t(threads_max)))

	return static_key, exit
}

// Prototype:
// int hydro_pwhash_reencrypt(uint8_t stored[hydro_pwhash_STOREDBYTES],
//     const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES],
//     const uint8_t new_master_key[hydro_pwhash_MASTERKEYBYTES]);
func PwHashReEncrypt(stored []byte, master_key []byte, new_master_key []byte) int {
	CheckSize(stored, PwHashStoredBytes, "stored len")
	CheckSize(master_key, PwHashMasterKeyBytes, "master_key len")
	CheckSize(new_master_key, PwHashMasterKeyBytes, "new_master_key len")

	exit := int(C.hydro_pwhash_reencrypt(
		(*C.uint8_t)(&stored[0]),
		(*C.uint8_t)(&master_key[0]),
		(*C.uint8_t)(&new_master_key[0])))

	return exit
}

// Prototype:
// int hydro_pwhash_upgrade(uint8_t stored[hydro_pwhash_STOREDBYTES],
//     const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES], uint64_t opslimit,
//     size_t memlimit, uint8_t threads);
func PwHashUpgrade(stored []byte, master_key []byte, opslimit uint64, memlimit int, threads uint8) int {
	CheckSize(stored, PwHashStoredBytes, "stored len")
	CheckSize(master_key, PwHashMasterKeyBytes, "master_key len")

	exit := int(C.hydro_pwhash_upgrade(
		(*C.uint8_t)(&stored[0]),
		(*C.uint8_t)(&master_key[0]),
		C.uint64_t(opslimit),
		C.size_t(memlimit),
		C.uint8_t(threads)))

	return exit
}
