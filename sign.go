package hydrogen

// #cgo CFLAGS: -I/usr/local/include
// #cgo LDFLAGS: -L/usr/local/lib -lhydrogen
// #include <stdlib.h>
// #include <hydrogen.h>
import "C"

import (
	"unsafe"
)

const (
	SignBytes int = C.hydro_sign_BYTES
	SignContextBytes int = C.hydro_sign_CONTEXTBYTES
	SignPublicKeyBytes int = C.hydro_sign_PUBLICKEYBYTES
	SignSecretKeyBytes int = C.hydro_sign_SECRETKEYBYTES
	SignSeedBytes int = C.hydro_sign_SEEDBYTES
)

// Reprentation of hydro_sign_keypair
type SignKeypair struct {
	Pk []byte // uint8_t pk[hydro_sign_PUBLICKEYBYTES];
	Sk []byte // uint8_t sk[hydro_sign_SECRETKEYBYTES];
} // hydro_sign_keypair

// void hydro_sign_keygen(hydro_sign_keypair *kp);
func SignKeygen() SignKeypair {
	kp := new(C.struct_hydro_sign_keypair)
	C.hydro_sign_keygen(kp)
	return SignKeypair{
		Pk: C.GoBytes(unsafe.Pointer(&kp.pk), C.hydro_sign_PUBLICKEYBYTES),
		Sk: C.GoBytes(unsafe.Pointer(&kp.sk), C.hydro_sign_SECRETKEYBYTES),
	}
}

// int hydro_sign_create(uint8_t csig[hydro_sign_BYTES], const void *m_, size_t mlen, const char ctx[hydro_sign_CONTEXTBYTES], const uint8_t sk[hydro_sign_SECRETKEYBYTES]);
// int hydro_sign_verify(const uint8_t csig[hydro_sign_BYTES], const void *m_, size_t mlen, const char ctx[hydro_sign_CONTEXTBYTES], const uint8_t pk[hydro_sign_PUBLICKEYBYTES]) _hydro_attr_warn_unused_result_;

type SignState struct {
	inner *C.hydro_sign_state
}

type SignHelper struct {
	state SignState
	context string
}

// Create a new SignState object. Does not initialize it.
func NewSignState() SignState {
	buf := new(C.hydro_sign_state)
	out := SignState{buf}
	return out
}

func NewSignHelper(ctx string) SignHelper {
	CheckCtx(ctx, SignContextBytes)
	st := NewSignState()
	C.hydro_sign_init(st.inner, C.CString(ctx))
	return SignHelper{
		state: st,
		context: ctx,
	}
}

// int hydro_sign_update(hydro_sign_state *state, const void *m_, size_t mlen);
func (s *SignHelper) Update(m []byte) {
	mlen := len(m)
	C.hydro_sign_update(
		s.state.inner,
		unsafe.Pointer(&m[0]),
		(C.size_t)(mlen))
}

// int hydro_sign_final_create(hydro_sign_state *state, uint8_t csig[hydro_sign_BYTES], const uint8_t sk[hydro_sign_SECRETKEYBYTES]);
func (s *SignHelper) FinalCreate(sk []byte, wipe bool) []byte {
	CheckSize(sk, SignSecretKeyBytes, "sk")
	out := make([]byte, SignBytes)
	C.hydro_sign_final_create(
		s.state.inner,
		(*C.uchar)(&out[0]),
		(*C.uchar)(&sk[0]))
	return out
}

// int hydro_sign_final_verify(hydro_sign_state *state, const uint8_t csig[hydro_sign_BYTES], const uint8_t pk[hydro_sign_PUBLICKEYBYTES]) _hydro_attr_warn_unused_result_;
func (s *SignHelper) FinalVerify(sig []byte, pk []byte) bool {
	CheckSize(sig, SignBytes, "sig")
	CheckSize(pk, SignPublicKeyBytes, "pk")
	exit := int(C.hydro_sign_final_verify(
		s.state.inner,
		(*C.uchar)(&sig[0]),
		(*C.uchar)(&pk[0])))
	return bool(exit == 0)
}

//
// eof
//
