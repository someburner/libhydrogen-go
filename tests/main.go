package main

import (
	"fmt"
	hydro "github.com/someburner/libhydrogen-go"
	// "testing"
)

func main() {
	fmt.Println("start")
	fmt.Println(hydro.VersionVerbose())
	ExampleHash()
	ExampleKdf()
	ExampleKx()
	ExamplePwHash()
	ExampleRandom()
	ExampleSecretbox()
	ExampleSign()
	fmt.Println("\n\nOKAY\nAll Example methods ran to completion\n")
}

const GOOD_CTX = "goctx123"
const BAD_CTX = "goctx321"
const TEST_MID uint64 = 0

const TEST_MSG1 = "testing 123"
const TEST_MSG2 = "testing abc"

const PWHASH_PASSWD = "test"

func ExampleHash() {
	fmt.Printf("\n============= Hash =============\n")
	fmt.Printf("HashBytes = %d\n", hydro.HashBytes)
	fmt.Printf("HashBytesMax = %d\n", hydro.HashBytesMax)
	fmt.Printf("HashBytesMin = %d\n", hydro.HashBytesMin)
	fmt.Printf("HashContextBytes = %d\n", hydro.HashContextBytes)
	fmt.Printf("HashKeyBytes = %d\n", hydro.HashKeyBytes)

	fmt.Printf("\n--- HashKeygen ---\n")
	sk := hydro.HashKeygen()
	fmt.Printf("sk [%d] %s\n", len(sk), hydro.Bin2hex(sk))

	fmt.Printf("\n--- HashHash (w/ key) ---\n")
	h1, r1 := hydro.HashHash(hydro.HashBytes, []byte(TEST_MSG1), GOOD_CTX, sk)
	if r1 != 0 {
		panic("HashHash returned non-zero")
	}
	fmt.Printf("h1 [%d] %s\n", len(h1), hydro.Bin2hex(h1))

	fmt.Printf("\n--- HashHash (w/o key) ---\n")
	h2, r2 := hydro.HashHash(hydro.HashBytes, []byte(TEST_MSG1), GOOD_CTX, nil)
	if r2 != 0 {
		panic("HashHash returned non-zero")
	}
	fmt.Printf("h2 [%d] %s\n", len(h2), hydro.Bin2hex(h2))

	fmt.Printf("\n--- HashHelper (multi) ---\n")
	hh1 := hydro.NewHashHelper(GOOD_CTX, nil)
	hh1.Update([]byte(TEST_MSG1))
	hh1.Update([]byte(TEST_MSG2))
	hashmulti1 := hh1.Final(hydro.HashBytes)
	fmt.Printf("hashmulti1[%d]:\n%s\n", len(hashmulti1), hydro.Bin2hex(hashmulti1))

	fmt.Printf("\n--- HashHelper (multi, key) ---\n")
	hh2 := hydro.NewHashHelper(GOOD_CTX, sk)
	hh2.Update([]byte(TEST_MSG1))
	hh2.Update([]byte(TEST_MSG2))
	hashmulti2 := hh2.Final(hydro.HashBytes)
	fmt.Printf("hashmulti2 (key)[%d]:\n%s\n", len(hashmulti2), hydro.Bin2hex(hashmulti2))
}

func ExampleKdf() {
	fmt.Printf("\n============= Kdf =============\n")
	fmt.Printf("KdfContextBytes = %d\n", hydro.KdfContextBytes)
	fmt.Printf("KdfKeyBytes = %d\n", hydro.KdfKeyBytes)
	fmt.Printf("KdfMaxBytes = %d\n", hydro.KdfMaxBytes)
	fmt.Printf("KdfMinBytes = %d\n", hydro.KdfMinBytes)

	fmt.Printf("\n--- KdfKeygen ---\n")
	master := hydro.KdfKeygen()
	fmt.Printf("master [%d] %s\n", len(master), hydro.Bin2hex(master))

	fmt.Printf("\n--- KdfDeriveFromKey ---\n")
	var id uint64 = 0x0123456789ABCDEF
	subkey, _ := hydro.KdfDeriveFromKey(32, id, GOOD_CTX, master)
	fmt.Printf("subkey [%d] %s\n", len(subkey), hydro.Bin2hex(subkey))
}

func ExampleKxN() {
	fmt.Printf("\n============= Kx (N) =============\n")
	// long-term server kp
	server_kp := hydro.KxKeygen()

	fmt.Printf("\n--- KxN1 (client) ---\n")
	sessionKpClient, pkt1, ok := hydro.KxN1(nil, server_kp.Pk())
	if ok != 0 {
		panic("KxN1 returned non-zero")
	}
	fmt.Printf("sessionKpClient\n")
	fmt.Printf("[Rx] -> %s\n", hydro.Bin2hex(sessionKpClient.Rx()))
	fmt.Printf("[Tx] -> %s\n", hydro.Bin2hex(sessionKpClient.Tx()))
	fmt.Printf("[pkt1] -> %s\n", hydro.Bin2hex(pkt1))

	fmt.Printf("\n--- KxN2 (server) ---\n")
	sessionKpServer, ok := hydro.KxN2(pkt1, nil, server_kp)
	if ok != 0 {
		panic("KxN2 returned non-zero")
	}
	fmt.Printf("sessionKpServer\n")
	fmt.Printf("[Rx] -> %s\n", hydro.Bin2hex(sessionKpServer.Rx()))
	fmt.Printf("[Tx] -> %s\n", hydro.Bin2hex(sessionKpServer.Tx()))
}

func ExampleKxKK() {
	fmt.Printf("\n============= Kx (KK) =============\n")
	// long-term client, server kp
	client_kp := hydro.KxKeygen()
	server_kp := hydro.KxKeygen()

	fmt.Printf("\n--- KxKK1 (client) ---\n")
	client_st := hydro.NewKxState()
	pkt1, kk1res := hydro.KxKK1(client_st, server_kp.Pk(), client_kp)
	if kk1res != 0 {
		panic("KxKK1 returned non-zero")
	}
	fmt.Printf("[pkt1] -> %s\n", hydro.Bin2hex(pkt1))

	fmt.Printf("\n--- KxKK2 (server) ---\n")
	sessionKpServer, pkt2, kk2res := hydro.KxKK2(pkt1, client_kp.Pk(), server_kp)
	if kk2res != 0 {
		panic("KxKK2 returned non-zero")
	}
	fmt.Printf("sessionKpServer\n")
	fmt.Printf("[Rx] -> %s\n", hydro.Bin2hex(sessionKpServer.Rx()))
	fmt.Printf("[Tx] -> %s\n", hydro.Bin2hex(sessionKpServer.Tx()))
	fmt.Printf("\n[pkt2] -> %s\n", hydro.Bin2hex(pkt2))

	fmt.Printf("\n--- KxKK3 (client) ---\n")
	sessionKpClient, kk3res := hydro.KxKK3(client_st, pkt2, server_kp.Pk())
	if kk3res != 0 {
		panic("KxKK3 returned non-zero")
	}
	fmt.Printf("sessionKpClient\n")
	fmt.Printf("[Rx] -> %s\n", hydro.Bin2hex(sessionKpClient.Rx()))
	fmt.Printf("[Tx] -> %s\n", hydro.Bin2hex(sessionKpClient.Tx()))
}

func ExampleKxXX() {
	fmt.Printf("\n============= Kx (XX) =============\n")
	// long-term client/server keypairs
	client_kp := hydro.KxKeygen()
	server_kp := hydro.KxKeygen()

	fmt.Printf("\n--- KxXX1 (client) ---\n")
	// init client st
	client_st := hydro.NewKxState()
	pkt1, xx1res := hydro.KxXX1(client_st, nil)
	if xx1res != 0 {
		panic("KxXX1 returned non-zero")
	}
	fmt.Printf("\n[pkt1] -> %s\n", hydro.Bin2hex(pkt1))
	//
	// pkt1 --> server
	//
	fmt.Printf("\n--- KxXX2 (server) ---\n")
	// init server st
	server_st := hydro.NewKxState()
	pkt2, xx2res := hydro.KxXX2(server_st, pkt1, server_kp, nil)
	if xx2res != 0 {
		panic("KxXX2 returned non-zero")
	}
	fmt.Printf("\n[pkt2] -> %s\n", hydro.Bin2hex(pkt2))
	//
	// pkt2 -> client
	//
	fmt.Printf("\n--- KxXX3 (client) ---\n")
	// func KxXX3(st_client KxState, pkt2 []byte, client_kp KxKeyPair, psk []byte) (KxSessionKeyPair, []byte, []byte, int)
	sessionKpClient, pkt3, peerPkClient, xx3res := hydro.KxXX3(client_st, pkt2, client_kp, nil)
	if xx3res != 0 {
		panic("KxXX3 returned non-zero")
	}
	fmt.Printf("sessionKpClient:\n")
	fmt.Printf("[Rx] -> %s\n", hydro.Bin2hex(sessionKpClient.Rx()))
	fmt.Printf("[Tx] -> %s\n", hydro.Bin2hex(sessionKpClient.Tx()))
	fmt.Printf("[peerPk] -> %s\n", hydro.Bin2hex(peerPkClient))
	fmt.Printf("\n[pkt3] -> %s\n", hydro.Bin2hex(pkt3))
	//
	// pkt3 -> server
	//
	fmt.Printf("\n--- KxXX4 (server) ---\n")
	// func KxXX4(st_server KxState, pkt3 []byte, psk []byte) (KxSessionKeyPair, []byte, int)
	sessionKpServer, peerPkServer, xx4res := hydro.KxXX4(server_st, pkt3, nil)
	if xx4res != 0 {
		panic("KxXX4 returned non-zero")
	}
	fmt.Printf("sessionKpServer:\n")
	fmt.Printf("[Rx] -> %s\n", hydro.Bin2hex(sessionKpServer.Rx()))
	fmt.Printf("[Tx] -> %s\n", hydro.Bin2hex(sessionKpServer.Tx()))
	fmt.Printf("[peerPk] -> %s\n", hydro.Bin2hex(peerPkServer))

	fmt.Printf("\nESTABLISHED\n")
}

func ExampleKx() {
	fmt.Printf("\n============= Kx =============\n")
	fmt.Printf("KxPublicKeyBytes = %d\n", hydro.KxPublicKeyBytes)
	fmt.Printf("KxSecretKeyBytes = %d\n", hydro.KxSecretKeyBytes)
	fmt.Printf("KxSessionKeyBytes = %d\n", hydro.KxSessionKeyBytes)
	fmt.Printf("KxSeedBytes = %d\n", hydro.KxSeedBytes)

	fmt.Printf("\n--- KxKeygen ---\n")
	kp := hydro.KxKeygen()
	fmt.Printf("[Pk] -> %s\n", hydro.Bin2hex(kp.Pk()))
	fmt.Printf("[Sk] -> %s\n", hydro.Bin2hex(kp.Sk()))

	ExampleKxN()
	ExampleKxKK()
	ExampleKxXX()
}

func ExamplePwHash() {
	fmt.Printf("\n============= PwHash =============\n")
	fmt.Printf("PwHashContextBytes = %d\n", hydro.PwHashContextBytes)
	fmt.Printf("PwHashMasterKeyBytes = %d\n", hydro.PwHashMasterKeyBytes)
	fmt.Printf("PwHashStoredBytes = %d\n", hydro.PwHashStoredBytes)

	fmt.Printf("\n--- PwHashKeygen ---\n")
	master := hydro.PwHashKeygen()
	fmt.Printf("master [%d] %s\n", len(master), hydro.Bin2hex(master))

	var opslimit uint64 = 1
	var memlimit int = 0
	var threads uint8 = 1

	fmt.Printf("\n--- PwHashDeterministic ---\n")
	derived_key, res := hydro.PwHashDeterministic(32, PWHASH_PASSWD, GOOD_CTX, master, opslimit)
	if res != 0 {
		panic("PwHashDeterministic failed")
	}
	fmt.Printf("derived_key [%d] %s\n", len(derived_key), hydro.Bin2hex(derived_key))

	fmt.Printf("\n--- PwHashCreate ---\n")
	pwhash1, res := hydro.PwHashCreate(PWHASH_PASSWD, master, opslimit, memlimit, threads)
	if res != 0 {
		panic("PwHashCreate failed")
	} else {
		fmt.Printf("pwhash1 [%d] %s\n", len(pwhash1), hydro.Bin2hex(pwhash1))
	}

	fmt.Printf("\n--- PwHashVerify (good) ---\n")
	if hydro.PwHashVerify(pwhash1, PWHASH_PASSWD, master, opslimit, memlimit, threads) != 0 {
		panic("PwHashVerify failed")
	} else {
		fmt.Printf("PwHashVerify success\n")
	}
	fmt.Printf("\n--- PwHashVerify (bad) ---\n")
	if hydro.PwHashVerify(pwhash1, "wrong password", master, opslimit, memlimit, threads) != 0 {
		fmt.Printf("PwHashVerify failed - OK\n")
	} else {
		panic("PwHashVerify should have failed")
	}

	fmt.Printf("\n--- PwHashDeriveStaticKey ---\n")
	static_key, res := hydro.PwHashDeriveStaticKey(32, pwhash1, PWHASH_PASSWD, GOOD_CTX, master, opslimit, memlimit, threads)
	if res != 0 {
		panic("PwHashDeriveStaticKey failed")
	} else {
		fmt.Printf("PwHashDeriveStaticKey [%d] %s\n", len(static_key), hydro.Bin2hex(static_key))
	}

	fmt.Printf("\n--- PwHashReEncrypt ---\n")
	fmt.Printf("PwHashReEncrypt - Before [%d] %s\n", len(pwhash1), hydro.Bin2hex(pwhash1))
	new_master := hydro.PwHashKeygen()
	if hydro.PwHashReEncrypt(pwhash1, master, new_master) != 0 {
		panic("PwHashReEncrypt failed")
	} else {
		fmt.Printf("PwHashReEncrypt - After [%d] %s\n", len(pwhash1), hydro.Bin2hex(pwhash1))
		if hydro.PwHashVerify(pwhash1, PWHASH_PASSWD, new_master, opslimit, memlimit, threads) != 0 {
			panic("PwHashVerify failed after PwHashReEncrypt")
		} else {
			fmt.Printf("PwHashVerify success after PwHashReEncrypt\n")
		}
		if hydro.PwHashVerify(pwhash1, PWHASH_PASSWD, master, opslimit, memlimit, threads) != 0 {
			fmt.Printf("PwHashVerify failed (using old master) - OK\n")
		} else {
			panic("PwHashVerify success (using old master) - BAD")
		}
	}

	fmt.Printf("\n--- PwHashUpgrade ---\n")
	var opslimit_new uint64 = 2
	var memlimit_new int = 0
	var threads_new uint8 = 2
	if hydro.PwHashUpgrade(pwhash1, new_master, opslimit_new, memlimit_new, threads_new) != 0 {
		panic("PwHashUpgrade failed")
	} else {
		fmt.Printf("PwHashUpgrade [%d] %s\n", len(pwhash1), hydro.Bin2hex(pwhash1))
	}
}

func ExampleRandom() {
	fmt.Printf("\n============= Random =============\n")
	fmt.Printf("RandomSeedBytes = %d\n", hydro.RandomSeedBytes)

	fmt.Printf("\n--- RandomU32 ---\n")
	r32 := hydro.RandomU32()
	fmt.Printf("U32 -> 0x%X\n", r32)

	fmt.Printf("\n--- RandomUniform ---\n")
	var upper uint32
	var i uint
	for i = 2; i < 31; i++ {
		upper = 2 << i
		fmt.Printf("\t(%d)-> 0x%X\n", upper, hydro.RandomUniform(upper))
	}

	fmt.Printf("\n--- RandomBuf ---\n")
	buf := hydro.RandomBuf(32)
	fmt.Printf("bytes[%d]:\n%s\n", len(buf), hydro.Bin2hex(buf))
}

func ExampleSecretbox() {
	fmt.Printf("\n============= Secretbox =============\n")
	fmt.Printf("SecretboxContextBytes = %d\n", hydro.SecretboxContextBytes)
	fmt.Printf("SecretboxHeaderBytes = %d\n", hydro.SecretboxHeaderBytes)
	fmt.Printf("SecretboxKeyBytes = %d\n", hydro.SecretboxKeyBytes)
	fmt.Printf("SecretboxProbeBytes = %d\n", hydro.SecretboxProbeBytes)

	fmt.Printf("\n--- SecretboxKeygen ---\n")
	sk := hydro.SecretboxKeygen()
	fmt.Printf("sk bytes[%d]:\n%s\n", len(sk), hydro.Bin2hex(sk))

	fmt.Printf("\n--- SecretboxEncrypt ---\n")
	fmt.Printf("Original plaintext --> \"%s\" <--\n", TEST_MSG1)
	ctxt, _ := hydro.SecretboxEncrypt([]byte(TEST_MSG1), TEST_MID, GOOD_CTX, sk)
	fmt.Printf("CipherText [%d]:\n%s\n", len(ctxt), hydro.Bin2hex(ctxt))

	fmt.Printf("\n--- SecretboxDecrypt ---\n")
	ptxt, _ := hydro.SecretboxDecrypt(ctxt, TEST_MID, GOOD_CTX, sk)
	fmt.Printf("Deciphered plaintext --> \"%s\" <--\n", string(ptxt))

	fmt.Printf("\n--- SecretboxProbeCreate ---\n")
	probe := hydro.SecretboxProbeCreate(ctxt, GOOD_CTX, sk)
	fmt.Printf("probe bytes [%d]:\n%s\n", len(probe), hydro.Bin2hex(probe))

	fmt.Printf("\n--- SecretboxProbeCreate ---\n")
	probeOk := hydro.SecretboxProbeVerify(probe, ctxt, GOOD_CTX, sk)
	fmt.Print("Result = ")
	fmt.Println(probeOk)
}

func ExampleSign() {
	fmt.Printf("\n============= Sign =============\n")
	fmt.Printf("SignBytes = %d\n", hydro.SignBytes)
	fmt.Printf("SignContextBytes = %d\n", hydro.SignContextBytes)
	fmt.Printf("SignPublicKeyBytes = %d\n", hydro.SignPublicKeyBytes)
	fmt.Printf("SignSecretKeyBytes = %d\n", hydro.SignSecretKeyBytes)
	fmt.Printf("SignSeedBytes = %d\n", hydro.SignSeedBytes)

	fmt.Printf("\n--- SignKeygen ---\n")
	kp := hydro.SignKeygen()
	fmt.Printf("[Pk] -> %s\n", hydro.Bin2hex(kp.Pk()))
	fmt.Printf("[Sk] -> %s\n", hydro.Bin2hex(kp.Sk()))

	fmt.Printf("\n--- SignKeygenDeterministic ---\n")
	seed := hydro.RandomBuf(hydro.SignSeedBytes)
	kpDet := hydro.SignKeygenDeterministic(seed)
	fmt.Printf("[Pk] -> %s\n", hydro.Bin2hex(kpDet.Pk()))
	fmt.Printf("[Sk] -> %s\n", hydro.Bin2hex(kpDet.Sk()))

	fmt.Printf("\n--- SignCreate (single) ---\n")
	fmt.Printf("Create\n")
	sig, createErr := hydro.SignCreate([]byte(TEST_MSG1), GOOD_CTX, kp.Sk())
	if createErr != 0 {
		panic("SignCreate returned non-zero")
	}
	// fmt.Printf("sig[%d]:\n%s\n", len(sig), hydro.Bin2hex(sig))
	fmt.Printf("Verify\n")
	sigVerified := hydro.SignVerify(sig, []byte(TEST_MSG1), GOOD_CTX, kp.Pk())
	fmt.Print("sigVerified = ")
	fmt.Println(sigVerified)

	fmt.Printf("\n--- SignHelper (multi) ---\n")
	fmt.Printf("Create\n")
	ss1 := hydro.NewSignHelper(GOOD_CTX)
	ss1.Update([]byte(TEST_MSG1))
	ss1.Update([]byte(TEST_MSG2))
	sig1 := ss1.FinalCreate(kp.Sk(), false)
	// fmt.Printf("sig1[%d]:\n%s\n", len(sig1), hydro.Bin2hex(sig1))
	fmt.Printf("Verify\n")
	ss2 := hydro.NewSignHelper(GOOD_CTX)
	ss2.Update([]byte(TEST_MSG1))
	ss2.Update([]byte(TEST_MSG2))
	sig1Verified := ss2.FinalVerify(sig1, kp.Pk())
	fmt.Print("sig1Verified = ")
	fmt.Println(sig1Verified)
}

//
// eof
//
