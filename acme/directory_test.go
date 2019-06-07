package acme

import (
	"testing"

	"github.com/smallstep/assert"
)

func TestDirectoryGetLink(t *testing.T) {
	dns := "ca.smallstep.com"
	prefix := "acme"
	dir := newDirectory(dns, prefix)
	id := "1234"

	type newTest struct {
		actual, expected string
	}
	assert.Equals(t, dir.getLink(NewNonceLink, true), "https://ca.smallstep.com/acme/new-nonce")
	assert.Equals(t, dir.getLink(NewNonceLink, false), "https://ca.smallstep.com/acme/new-nonce")
}
