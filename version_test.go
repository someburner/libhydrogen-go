package hydrogen

import (
	hydro "github.com/someburner/libhydrogen-go"
	"testing"
)

const VersionMajorExpect = 1
const VersionMinorExpect = 0

func TestVersionPair(t *testing.T) {
	maj, min := hydro.VersionPair()
	if maj != VersionMajorExpect {
		t.Errorf("VersionMajor: Got %d (expected %d).", maj, VersionMajorExpect)
	}
	if min != VersionMinorExpect {
		t.Errorf("VersionMinor: Got %d (expected %d).", min, VersionMinorExpect)
	}
}
