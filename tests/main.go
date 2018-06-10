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
	fmt.Println("finish")
}

const GOOD_CTX = "goctx123"
const BAD_CTX = "goctx321"
const TEST_MID uint64 = 0

const TEST_MSG1 = "testing 123"
const TEST_MSG2 = "testing abc"

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
	clientSessionKp,pkt1,ok := hydro.KxN1(nil, server_kp.Pk())
	if ok != 0 {
		panic("KxN1 returned non-zero")
	}
	fmt.Printf("[Rx] -> %s\n", hydro.Bin2hex(clientSessionKp.Rx()))
	fmt.Printf("[Tx] -> %s\n", hydro.Bin2hex(clientSessionKp.Tx()))
	fmt.Printf("[Pkt1] -> %s\n", hydro.Bin2hex(pkt1))

	fmt.Printf("\n--- KxN2 (server) ---\n")
	serverSessionKp,ok := hydro.KxN2(pkt1, nil, server_kp)
	if ok != 0 {
		panic("KxN2 returned non-zero")
	}
	fmt.Printf("[Rx] -> %s\n", hydro.Bin2hex(serverSessionKp.Rx()))
	fmt.Printf("[Tx] -> %s\n", hydro.Bin2hex(serverSessionKp.Tx()))
}

func ExampleKxKK() {
	fmt.Printf("\n============= Kx (KK) =============\n")
}

func ExampleKxXX() {
	fmt.Printf("\n============= Kx (XX) =============\n")
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
}

func ExamplePwHash() {
	fmt.Printf("\n============= PwHash =============\n")
	fmt.Printf("PwHashContextBytes = %d\n", hydro.PwHashContextBytes)
	fmt.Printf("PwHashMasterKeyBytes = %d\n", hydro.PwHashMasterKeyBytes)
	fmt.Printf("PwHashStoredBytes = %d\n", hydro.PwHashStoredBytes)

	fmt.Printf("\n--- PwHashKeygen ---\n")
	master := hydro.PwHashKeygen()
	fmt.Printf("master [%d] %s\n", len(master), hydro.Bin2hex(master))
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
