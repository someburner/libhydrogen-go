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
	SignBytes          int = C.hydro_sign_BYTES
	SignContextBytes   int = C.hydro_sign_CONTEXTBYTES
	SignPublicKeyBytes int = C.hydro_sign_PUBLICKEYBYTES
	SignSecretKeyBytes int = C.hydro_sign_SECRETKEYBYTES
	SignSeedBytes      int = C.hydro_sign_SEEDBYTES
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

// void hydro_sign_keygen_deterministic(hydro_sign_keypair *kp, const uint8_t seed[hydro_sign_SEEDBYTES]);
func SignKeygenDeterministic(seed []byte) SignKeypair {
	CheckSize(seed, SignSeedBytes, "seed")
	kp := new(C.struct_hydro_sign_keypair)
	C.hydro_sign_keygen_deterministic(kp, (*C.uchar)(&seed[0]))
	return SignKeypair{
		Pk: C.GoBytes(unsafe.Pointer(&kp.pk), C.hydro_sign_PUBLICKEYBYTES),
		Sk: C.GoBytes(unsafe.Pointer(&kp.sk), C.hydro_sign_SECRETKEYBYTES),
	}
}

// int hydro_sign_create(uint8_t csig[hydro_sign_BYTES], const void *m_, size_t mlen, const char ctx[hydro_sign_CONTEXTBYTES], const uint8_t sk[hydro_sign_SECRETKEYBYTES]);
func SignCreate(m []byte, ctx string, sk []byte) ([]byte, int) {
	CheckCtx(ctx, SignContextBytes)
	CheckSize(sk, SignSecretKeyBytes, "sign sk")
	mlen := len(m)
	out := make([]byte, SignBytes)

	// Returns 0 on success
	exit := int(C.hydro_sign_create(
		(*C.uchar)(&out[0]),
		unsafe.Pointer(&m[0]),
		(C.size_t)(mlen),
		C.CString(ctx),
		(*C.uchar)(&sk[0])))

	return out, exit
}

// int hydro_sign_verify(const uint8_t csig[hydro_sign_BYTES], const void *m_, size_t mlen, const char ctx[hydro_sign_CONTEXTBYTES], const uint8_t pk[hydro_sign_PUBLICKEYBYTES]) _hydro_attr_warn_unused_result_;
func SignVerify(sig []byte, m []byte, ctx string, pk []byte) bool {
	CheckSize(sig, SignBytes, "sign sig")
	CheckCtx(ctx, SignContextBytes)
	CheckSize(pk, SignPublicKeyBytes, "sign pk")
	mlen := len(m)

	// Returns 0 on success
	exit := int(C.hydro_sign_verify(
		(*C.uchar)(&sig[0]),
		unsafe.Pointer(&m[0]),
		(C.size_t)(mlen),
		C.CString(ctx),
		(*C.uchar)(&pk[0])))

	return bool(exit == 0)
}

type SignState struct {
	inner *C.hydro_sign_state
}

type SignHelper struct {
	state   SignState
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
		state:   st,
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
	CheckSize(sk, SignSecretKeyBytes, "sign sk")
	out := make([]byte, SignBytes)
	C.hydro_sign_final_create(
		s.state.inner,
		(*C.uchar)(&out[0]),
		(*C.uchar)(&sk[0]))
	return out
}

// int hydro_sign_final_verify(hydro_sign_state *state, const uint8_t csig[hydro_sign_BYTES], const uint8_t pk[hydro_sign_PUBLICKEYBYTES]) _hydro_attr_warn_unused_result_;
func (s *SignHelper) FinalVerify(sig []byte, pk []byte) bool {
	CheckSize(sig, SignBytes, "sign sig")
	CheckSize(pk, SignPublicKeyBytes, "sign pk")
	exit := int(C.hydro_sign_final_verify(
		s.state.inner,
		(*C.uchar)(&sig[0]),
		(*C.uchar)(&pk[0])))
	return bool(exit == 0)
}

//
// eof
//
