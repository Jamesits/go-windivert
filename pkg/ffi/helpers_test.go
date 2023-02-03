package ffi

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

var CompiledFilterPrefix = "@WinDiv"

// https://reqrypt.org/windivert-doc.html#filter_language
var CorrectFilters = [...]Filter{
	"inbound",
	"outbound and tcp.PayloadLength > 0 and tcp.DstPort == 80",
	"outbound and !loopback and (tcp.DstPort == 80 or udp.DstPort == 53)",
	"inbound and tcp.Syn",
	"true",
	"false",
}

var IncorrectFilters = [...]Filter{
	"",
	"!!!",
	"random invalid string",
}

func TestHelperCompileFiltersCorrect(t *testing.T) {
	l := LibraryReference{}
	err := l.Unmarshal(defaultDLLLookupPathForTesting)
	assert.NoError(t, err)

	for _, f0 := range CorrectFilters {
		// compile
		f1, pos, err := l.CompileFilter(f0, Network)
		assert.NoError(t, err)
		assert.EqualValues(t, uint(0), pos)
		assert.True(t, len(f1.String()) > 0)
		assert.True(t, strings.HasPrefix(f1.String(), CompiledFilterPrefix))

		// decompile
		f2, err := l.FormatFilter(f1, Network)
		assert.NoError(t, err)
		assert.True(t, len(f2.String()) > 0)
	}
}

func TestHelperFormatFilter(t *testing.T) {
	l := LibraryReference{}
	err := l.Unmarshal(defaultDLLLookupPathForTesting)
	assert.NoError(t, err)

	for _, f0 := range CorrectFilters {
		// format once
		f1, err := l.FormatFilter(f0, Network)
		assert.NoError(t, err)
		assert.True(t, len(f1.String()) > 0)

		// format twice
		f2, err := l.FormatFilter(f1, Network)
		assert.NoError(t, err)
		assert.True(t, len(f2.String()) > 0)

		assert.EqualValues(t, f1, f2)
	}
}

func TestHelperCompileFiltersIncorrect(t *testing.T) {
	l := LibraryReference{}
	err := l.Unmarshal(defaultDLLLookupPathForTesting)
	assert.NoError(t, err)

	for _, f0 := range IncorrectFilters {
		f1, _, err := l.CompileFilter(f0, Network)
		assert.Error(t, err)
		// note: we cannot guarantee f1 is empty
		assert.False(t, strings.HasPrefix(f1.String(), CompiledFilterPrefix))
	}
}
