#
# libhydrogen-go Makefile
#

SHELL :=/bin/bash

################################################################################
.PHONY: libhydrogen libhydrogen-clean
all:
	@echo "Help:"
	@echo "make libhydrogen        | build libhydrogen"
	@echo "make libhydrogen-clean  | clean libhydrogen"
	@echo "make run                | run examples"
	@echo "make run-locallib       | run examples"

libhydrogen:
	make -C libhydrogen

libhydrogen-clean:
	make -C libhydrogen clean

################################################################################
.PHONY: fmt run test run_custom_ld rerun
fmt:
	go fmt ./...;

test:
	env CGO_ENABLED=1 go test *_test.go

run:
	env CGO_ENABLED=1 go run tests/main.go

run-locallib:
	env CGO_ENABLED=1 CGO_LDFLAGS="-Llibhydrogen" CGO_CFLAGS="-Ilibhydrogen" go run tests/main.go

run_custom_ld:
	env CGO_ENABLED=1 CGO_LDFLAGS="-L/path/to/libhydrogen" CGO_CFLAGS="-I/path/to/libhydrogen" go run tests/main.go

rerun:
	env CGO_ENABLED=1 go run -a tests/main.go
################################################################################
.PHONY: race
race:
	env CGO_ENABLED=1 go run -race tests/main.go

#
# End
#
