package main

import (
	"fmt"
	hydro "github.com/someburner/libhydrogen-go"
	"testing"
)

func main() {
	fmt.Println("start")
	fmt.Println(hydro.VersionVerbose())
	fmt.Println("finish")
}
