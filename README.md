# libhydrogen-go

Golang wrapper for [libhydrogen](https://github.com/jedisct1/libhydrogen).

## Usage

If libhydrogen is already installed system-wide, just `go get` the project
and import `libhydrogen-go` like anything else. Otherwise, you may build and
install `libhydrogen.a` from the submodule directory.

**Note**: `libhydrogen-go` is only tested to work against the version of
libhydrogen included as a submodule in this repo.

**Specifying libhydrogen location**: See the `make run_custom_ld` target in
Makefile for example.

**Note**: If editing / recompiling `libhydrogen` and then running tests, it may
be necessary to build with the `-a` flag to force a rebuild. See `make rebuild`
target in Makefile for example.

```sh
# add as go mod dependency
go get github.com/someburner/libhydrogen-go
```
<br>

```go
// and use in project
package main

import (
	"fmt"
	hydro "github.com/someburner/libhydrogen-go"
)

func main() {
	fmt.Println(hydro.VersionVerbose())
}
```

## Install libhydrogen

```sh
# to build inside submodule, or run the examples
git clone --recursive https://github.com/someburner/libhydrogen-go.git
cd libhydrogen-go

# build/install libhydrogen
cd libhydrogen
make
sudo make install
```

<br>

## Examples

See [example](tests/main.go). Or run with `make`.

```sh
make run
```

## Links

* cgo [reference](https://golang.org/cmd/cgo/)

## Credits

Several methods in `core.go` taken from `libsodium-go`.
