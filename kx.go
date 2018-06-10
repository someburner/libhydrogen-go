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
	// n
	KxNPacket1Bytes   int = C.hydro_kx_N_PACKET1BYTES
	// kk
	KxKKPacket1Bytes  int = C.hydro_kx_KK_PACKET1BYTES
	KxKKPacket2Bytes  int = C.hydro_kx_KK_PACKET2BYTES
	// xx
	KxXXPacket1Bytes  int = C.hydro_kx_XX_PACKET1BYTES
	KxXXPacket2Bytes  int = C.hydro_kx_XX_PACKET2BYTES
	KxXXPacket3Bytes  int = C.hydro_kx_XX_PACKET3BYTES
	// keys
	KxPublicKeyBytes  int = C.hydro_kx_PUBLICKEYBYTES
	KxSecretKeyBytes  int = C.hydro_kx_SECRETKEYBYTES
	KxSessionKeyBytes int = C.hydro_kx_SESSIONKEYBYTES
	KxSeedBytes       int = C.hydro_kx_SEEDBYTES
	KxPskBytes        int = C.hydro_kx_PSKBYTES
)

/* -------------------------------- KxKeyPair ------------------------------- */
// Reprentation of hydro_kx_keypair
type KxKeyPair struct {
	inner *C.hydro_kx_keypair
}
func (kp * KxKeyPair) Pk() []byte {
	return C.GoBytes(unsafe.Pointer(&kp.inner.pk), C.hydro_kx_PUBLICKEYBYTES)
}
func (kp * KxKeyPair) Sk() []byte {
	return C.GoBytes(unsafe.Pointer(&kp.inner.sk), C.hydro_kx_SECRETKEYBYTES)
}

/* ---------------------------- KxSessionKeyPair ---------------------------- */
// Reprentation of hydro_kx_session_keypair
type KxSessionKeyPair struct {
	inner *C.hydro_kx_session_keypair
}
func (kp * KxSessionKeyPair) Rx() []byte {
	return C.GoBytes(unsafe.Pointer(&kp.inner.rx), C.hydro_kx_SESSIONKEYBYTES)
}
func (kp * KxSessionKeyPair) Tx() []byte {
	return C.GoBytes(unsafe.Pointer(&kp.inner.tx), C.hydro_kx_SESSIONKEYBYTES)
}

/* --------------------------------- Keygen --------------------------------- */
// void hydro_kx_keygen(hydro_kx_keypair *static_kp);
func KxKeygen() KxKeyPair {
	cKxKeypair := new(C.struct_hydro_kx_keypair)
	C.hydro_kx_keygen(cKxKeypair)
	return KxKeyPair{cKxKeypair}
}

// void hydro_kx_keygen_deterministic(hydro_kx_keypair *static_kp, const uint8_t seed[hydro_kx_SEEDBYTES]);
func KxKeygenDeterministic(seed []byte) KxKeyPair {
	CheckSize(seed, KxSeedBytes, "seed")
	cKxKeypair := new(C.struct_hydro_kx_keypair)
	C.hydro_kx_keygen_deterministic(cKxKeypair, (*C.uchar)(&seed[0]))
	return KxKeyPair{cKxKeypair}
}

/* ----------------------------------- Kx ----------------------------------- */
// Reprentation of hydro_kx_state
type KxState struct {
	inner *C.hydro_kx_state
}

// Create a new KxState object
func NewKxState() KxState {
	buf := new(C.hydro_kx_state)
	return KxState{buf}
}

/* --------------------------------- Kx (N) --------------------------------- */
// KxN1: Client
// * Computes a key pair using the server's public key
// * Builds a packet packet that has to be sent to the server
// * Returns KxSessionKeyPair, pkt1 slice, 0/-1 (success/error)
// Prototype:
// int hydro_kx_n_1(hydro_kx_session_keypair *kp, uint8_t packet1[hydro_kx_N_PACKET1BYTES], const uint8_t psk[hydro_kx_PSKBYTES], const uint8_t peer_static_pk[hydro_kx_PUBLICKEYBYTES]);
func KxN1(psk []byte, server_pubkey []byte) (KxSessionKeyPair, []byte, int) {
	if psk != nil {
		CheckSize(psk, KxPskBytes, "psk")
	}
	CheckSize(server_pubkey, KxPublicKeyBytes, "server_pubkey")
	pkt1 := make([]byte, KxNPacket1Bytes)
	cSessionKp := new(C.struct_hydro_kx_session_keypair)

	var exit int
	if psk != nil {
		exit = int(C.hydro_kx_n_1(
			cSessionKp,
			(*C.uchar)(&pkt1[0]),
			(*C.uchar)(&psk[0]),
			(*C.uchar)(&server_pubkey[0])))
	} else {
		exit = int(C.hydro_kx_n_1(
			cSessionKp,
			(*C.uchar)(&pkt1[0]),
			nil,
			(*C.uchar)(&server_pubkey[0])))
	}
	return KxSessionKeyPair{cSessionKp}, pkt1, exit
}

// KxN2: Server
// * Process the initial request from the client (aka packet1)
// * Compute sessions keys
// * Returns KxSessionKeyPair, pkt1 slice, 0/-1 (success/error)
// Prototype:
// int hydro_kx_n_2(hydro_kx_session_keypair *kp, const uint8_t packet1[hydro_kx_N_PACKET1BYTES], const uint8_t psk[hydro_kx_PSKBYTES], const hydro_kx_keypair *static_kp);
func KxN2(pkt1 []byte, psk []byte, server_kp KxKeyPair) (KxSessionKeyPair, int) {
	if psk != nil {
		CheckSize(psk, KxPskBytes, "psk")
	}
	CheckSize(pkt1, KxNPacket1Bytes, "n2 - pkt1")
	cSessionKp := new(C.struct_hydro_kx_session_keypair)

	var exit int
	if psk != nil {
		exit = int(C.hydro_kx_n_2(
			cSessionKp,
			(*C.uchar)(&pkt1[0]),
			(*C.uchar)(&psk[0]),
			server_kp.inner))
	} else {
		exit = int(C.hydro_kx_n_2(
			cSessionKp,
			(*C.uchar)(&pkt1[0]),
			nil,
			server_kp.inner))
	}
	return KxSessionKeyPair{cSessionKp}, exit
}

/* -------------------------------- Kx (KK) --------------------------------- */
// KxKK1: Client -> Server
// * initializes the local state
// * compute ephemeral key pair + pkt1
// * Returns pkt1 slice, 0/-1 (success/error)
// Prototype:
// int hydro_kx_kk_1(hydro_kx_state *state, uint8_t packet1[hydro_kx_KK_PACKET1BYTES], const uint8_t peer_static_pk[hydro_kx_PUBLICKEYBYTES], const hydro_kx_keypair *static_kp);
func KxKK1(st_client KxState, server_pubkey []byte, client_kp KxKeyPair) ([]byte, int) {
	CheckSize(server_pubkey, KxPublicKeyBytes, "kk1 - server_pubkey")
	pkt1 := make([]byte, KxKKPacket1Bytes)

	exit := int(C.hydro_kx_kk_1(
		st_client.inner,
		(*C.uchar)(&pkt1[0]),
		(*C.uchar)(&server_pubkey[0]),
		client_kp.inner))

	return pkt1, exit
}

// KxKK2: Server -> Client
// * validates the initial request
// * compute ephemeral key pair + pkt2
// * Returns KxSessionKeyPair, pkt2 slice, 0/-1 (success/error)
// Prototype:
// int hydro_kx_kk_2(hydro_kx_session_keypair *kp, uint8_t packet2[hydro_kx_KK_PACKET2BYTES], const uint8_t packet1[hydro_kx_KK_PACKET1BYTES], const uint8_t peer_static_pk[hydro_kx_PUBLICKEYBYTES], const hydro_kx_keypair *static_kp);
func KxKK2(pkt1 []byte, client_pubkey []byte, server_kp KxKeyPair) (KxSessionKeyPair, []byte, int) {
	CheckSize(pkt1, KxKKPacket1Bytes, "kk2 - pkt1 bytes")
	CheckSize(client_pubkey, KxPublicKeyBytes, "kk2 - client_pubkey")
	pkt2 := make([]byte, KxKKPacket2Bytes)
	cSessionKp := new(C.struct_hydro_kx_session_keypair)

	exit := int(C.hydro_kx_kk_2(
		cSessionKp,
		(*C.uchar)(&pkt2[0]),
		(*C.uchar)(&pkt1[0]),
		(*C.uchar)(&client_pubkey[0]),
		server_kp.inner))

	return KxSessionKeyPair{cSessionKp}, pkt2, exit
}

// KxKK3: Client
// * compute session key pair using server pkt2
// * Returns KxSessionKeyPair, pkt2 slice, 0/-1 (success/error)
// Prototype:
// int hydro_kx_kk_3(hydro_kx_state *state, hydro_kx_session_keypair *kp, const uint8_t packet2[hydro_kx_KK_PACKET2BYTES], const uint8_t peer_static_pk[hydro_kx_PUBLICKEYBYTES]);
func KxKK3(st_client KxState, pkt2 []byte, server_pubkey []byte) (KxSessionKeyPair, int) {
	CheckSize(pkt2, KxKKPacket1Bytes, "kk3 - pkt2 bytes")
	CheckSize(server_pubkey, KxPublicKeyBytes, "kk3 - server_pubkey")
	cSessionKp := new(C.struct_hydro_kx_session_keypair)

	exit := int(C.hydro_kx_kk_3(
		st_client.inner,
		cSessionKp,
		(*C.uchar)(&pkt2[0]),
		(*C.uchar)(&server_pubkey[0])))

	return KxSessionKeyPair{cSessionKp}, exit
}

type KxHelperKK struct {
	state   KxState
	context string
}

/* -------------------------------- Kx (XX) --------------------------------- */
type KxHelperXX struct {
	state   KxState
	context string
}


//
// eof
//
