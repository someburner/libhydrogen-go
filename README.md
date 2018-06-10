# libhydrogen-go

Golang wrapper for [libhydrogen](https://github.com/jedisct1/libhydrogen).

## Usage

#### If libhydrogen is already installed:

```sh
go get github.com/someburner/libhydrogen-go
```

Then import and use in your project. See [example](tests/main.go).

<br>

#### To build the bindings inside `libhydrogen-go`:

```sh
git clone --recursive https://github.com/someburner/libhydrogen-go
cd libhydrogen-go
# build libhydrogen
make libhydrogen
```

<br>

## Examples

TODO: document.

```sh
# run tests/main.go
make run
```

## Links

* cgo [reference](https://golang.org/cmd/cgo/)
