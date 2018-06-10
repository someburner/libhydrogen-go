package main

import (
	"fmt"
	hydro "github.com/someburner/libhydrogen-go"
	// "testing"
)

func main() {
	fmt.Println("start")
	fmt.Println(hydro.VersionVerbose())
	fmt.Println("finish")
	ExampleKdf()
	ExampleSecretbox()
	ExampleSign()
}

const GOOD_CTX = "goctx123"
const BAD_CTX = "goctx321"
const TEST_MID uint64 = 0

const TEST_MSG1 = "testing 123"
const TEST_MSG2 = "testing abc"

func ExampleKdf() {
	fmt.Println("============= Kdf =============")
	fmt.Printf("KdfContextBytes = %d\n", hydro.KdfContextBytes)
	fmt.Printf("KdfKeyBytes = %d\n", hydro.KdfKeyBytes)
	fmt.Printf("KdfMaxBytes = %d\n", hydro.KdfMaxBytes)
	fmt.Printf("KdfMinBytes = %d\n", hydro.KdfMinBytes)
	fmt.Println("KdfKeygen:")
	master := hydro.KdfKeygen()
	fmt.Printf("master [%d] %s\n", len(master), hydro.Bin2hex(master))
	var id uint64 = 0x0123456789ABCDEF
	subkey, _ := hydro.KdfDeriveFromKey(32, id, GOOD_CTX, master)
	fmt.Printf("subkey [%d] %s\n", len(subkey), hydro.Bin2hex(subkey))
}

func ExampleSecretbox() {
	fmt.Println("============= Secretbox =============")
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
	ptxt, _ :=  hydro.SecretboxDecrypt(ctxt, TEST_MID, GOOD_CTX, sk)
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
	fmt.Println("============= Sign =============")
	fmt.Printf("SignBytes = %d\n", hydro.SignBytes)
	fmt.Printf("SignContextBytes = %d\n", hydro.SignContextBytes)
	fmt.Printf("SignPublicKeyBytes = %d\n", hydro.SignPublicKeyBytes)
	fmt.Printf("SignSecretKeyBytes = %d\n", hydro.SignSecretKeyBytes)
	fmt.Printf("SignSeedBytes = %d\n", hydro.SignSeedBytes)

	fmt.Printf("\n--- SignKeygen ---\n")
	kp := hydro.SignKeygen()
	fmt.Printf("pk[%d]:\n%s\n", len(kp.Pk), hydro.Bin2hex(kp.Pk))
	fmt.Printf("sk[%d]:\n%s\n", len(kp.Sk), hydro.Bin2hex(kp.Sk))

	fmt.Printf("\n--- SignHelper ---\n")
	fmt.Printf("Create\n")
	ss1 := hydro.NewSignHelper(GOOD_CTX)
	ss1.Update([]byte(TEST_MSG1))
	ss1.Update([]byte(TEST_MSG2))
	sig1 := ss1.FinalCreate(kp.Sk, false)
	fmt.Printf("sig1[%d]:\n%s\n", len(sig1), hydro.Bin2hex(sig1))

	fmt.Printf("Verify\n")
	ss2 := hydro.NewSignHelper(GOOD_CTX)
	ss2.Update([]byte(TEST_MSG1))
	ss2.Update([]byte(TEST_MSG2))
 	sig1Verified := ss2.FinalVerify(sig1, kp.Pk)
	fmt.Print("sig1Verified = ")
	fmt.Println(sig1Verified)
}





//
// eof
//
