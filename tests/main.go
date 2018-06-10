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
}

const GOOD_CTX = "goctx123"

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
