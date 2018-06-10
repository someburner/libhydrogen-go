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

libhydrogen:
	make -C libhydrogen

libhydrogen-clean:
	make -C libhydrogen clean

################################################################################
.PHONY: fmt run test
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
