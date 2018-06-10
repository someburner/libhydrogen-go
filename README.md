# libhydrogen-go

Golang wrapper for [libhydrogen](https://github.com/jedisct1/libhydrogen).

## Usage

If libhydrogen is already installed system-wide, just `go get` the project
and import `libhydrogen-go` like anything else. Otherwise, you may build
`libhydrogen.a` inside the submodule directory.

```sh
go get github.com/someburner/libhydrogen-go

# to build inside submodule, or run the examples
cd github.com/someburner/libhydrogen-go
make libhydrogen

# go run tests/main.go
make run
```

<br>

## Examples

See [example](tests/main.go).

## Links

* cgo [reference](https://golang.org/cmd/cgo/)

## Credits

Several methods in `core.go` taken from `libsodium-go`.
