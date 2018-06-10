package main

import (
	"fmt"
	hydro "github.com/someburner/libhydrogen-go"
)

func main() {
	fmt.Println("start")
	fmt.Println(hydro.VersionVerbose())
	fmt.Println("finish")
}
