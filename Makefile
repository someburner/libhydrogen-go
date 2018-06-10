#
# libhydrogen-go Makefile
#

SHELL :=/bin/bash

################################################################################
.PHONY: fmt run test

all: run

fmt:
	$(SHELL) scripts/cmd.sh "fmt"

test:
	env CGO_ENABLED=1 go test *_test.go

run:
	env CGO_ENABLED=1 go run tests/main.go

################################################################################
.PHONY: race
race:
	env CGO_ENABLED=1 go run -race tests/main.go

#
# End
#
