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
	SecretboxContextBytes int = C.hydro_secretbox_CONTEXTBYTES
	SecretboxHeaderBytes  int = C.hydro_secretbox_HEADERBYTES
	SecretboxKeyBytes     int = C.hydro_secretbox_KEYBYTES
	SecretboxProbeBytes   int = C.hydro_secretbox_PROBEBYTES
)

// Prototype:
// void hydro_secretbox_keygen(uint8_t key[hydro_secretbox_KEYBYTES]);
func SecretboxKeygen() []byte {
	buf := make([]byte, SecretboxKeyBytes)
	C.hydro_secretbox_keygen((*C.uint8_t)(&buf[0]))
	return buf
}

// Prototype:
// int hydro_secretbox_encrypt(uint8_t *c, const void *m_, size_t mlen, uint64_t msg_id, const char ctx[hydro_secretbox_CONTEXTBYTES], const uint8_t key[hydro_secretbox_KEYBYTES]);
func SecretboxEncrypt(m []byte, mid uint64, ctx string, sk []byte) ([]byte, int) {
	CheckCtx(ctx, SecretboxContextBytes)
	CheckSize(sk, SecretboxKeyBytes, "sk")
	mlen := len(m)
	CheckIntGt(mlen, 0, "secretbox-enc-mlen")
	cCtx := []byte(ctx)
	out := make([]byte, mlen+SecretboxHeaderBytes)

	exit := int(C.hydro_secretbox_encrypt(
		(*C.uint8_t)(&out[0]),
		unsafe.Pointer(&m[0]),
		(C.size_t)(mlen),
		(C.uint64_t)(mid),
		(*C.char)(unsafe.Pointer(&cCtx[0])),
		(*C.uint8_t)(&sk[0])))

	return out, exit
}

// Prototype:
// int hydro_secretbox_decrypt(void *m_, const uint8_t *c, size_t clen, uint64_t msg_id, const char ctx[hydro_secretbox_CONTEXTBYTES], const uint8_t key[hydro_secretbox_KEYBYTES]) __attribute__((warn_unused_result));
func SecretboxDecrypt(c []byte, mid uint64, ctx string, sk []byte) ([]byte, int) {
	CheckCtx(ctx, SecretboxContextBytes)
	CheckSize(sk, SecretboxKeyBytes, "sk")
	clen := len(c)
	CheckIntGt(clen, SecretboxHeaderBytes, "secretbox-dec-clen")
	cCtx := []byte(ctx)
	out := make([]byte, clen-SecretboxHeaderBytes)

	exit := int(C.hydro_secretbox_decrypt(
		unsafe.Pointer(&out[0]),
		(*C.uint8_t)(&c[0]),
		(C.size_t)(clen),
		(C.uint64_t)(mid),
		(*C.char)(unsafe.Pointer(&cCtx[0])),
		(*C.uint8_t)(&sk[0])))

	return out, exit
}

// Prototype:
// void hydro_secretbox_probe_create(uint8_t probe[hydro_secretbox_PROBEBYTES], const uint8_t *c, size_t c_len, const char ctx[hydro_secretbox_CONTEXTBYTES], const uint8_t key[hydro_secretbox_KEYBYTES]);
func SecretboxProbeCreate(c []byte, ctx string, sk []byte) []byte {
	CheckCtx(ctx, SecretboxContextBytes)
	CheckSize(sk, SecretboxKeyBytes, "sk")
	clen := len(c)
	CheckIntGt(clen, 0, "probe-create-clen")
	cCtx := []byte(ctx)
	probe := make([]byte, SecretboxProbeBytes)

	C.hydro_secretbox_probe_create(
		(*C.uint8_t)(&probe[0]),
		(*C.uint8_t)(&c[0]),
		(C.size_t)(clen),
		(*C.char)(unsafe.Pointer(&cCtx[0])),
		(*C.uint8_t)(&sk[0]))

	return probe
}

// Prototype:
// int hydro_secretbox_probe_verify(const uint8_t probe[hydro_secretbox_PROBEBYTES], const uint8_t *c, size_t c_len, const char ctx[hydro_secretbox_CONTEXTBYTES], const uint8_t key[hydro_secretbox_KEYBYTES]) __attribute__((warn_unused_result));
func SecretboxProbeVerify(probe []byte, c []byte, ctx string, sk []byte) bool {
	CheckSize(probe, SecretboxProbeBytes, "probe")
	CheckCtx(ctx, SecretboxContextBytes)
	CheckSize(sk, SecretboxKeyBytes, "sk")
	clen := len(c)
	CheckIntGt(clen, 0, "probe-verify-clen")
	cCtx := []byte(ctx)

	result := int(C.hydro_secretbox_probe_verify(
		(*C.uint8_t)(&probe[0]),
		(*C.uint8_t)(&c[0]),
		(C.size_t)(clen),
		(*C.char)(unsafe.Pointer(&cCtx[0])),
		(*C.uint8_t)(&sk[0])))

	return bool(result == 0)
}
