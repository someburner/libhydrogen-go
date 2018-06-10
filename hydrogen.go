package hydrogen

import (
	// "fmt"
	"errors"
)

var (
	ErrAuth        = errors.New("hydrogen: Message forged")
	ErrOpenBox     = errors.New("hydrogen: Can't open box")
	ErrOpenSign    = errors.New("hydrogen: Signature forged")
	ErrDecryptAEAD = errors.New("hydrogen: Can't decrypt message")
	ErrPassword    = errors.New("hydrogen: Password not matched")
	ErrInvalidKey  = errors.New("hydrogen: Invalid key")
)
