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
	assert.Equals(t, dir.getLink(NewNonceLink, false), "new-nonce")

	assert.Equals(t, dir.getLink(NewAccountLink, true), "https://ca.smallstep.com/acme/new-account")
	assert.Equals(t, dir.getLink(NewAccountLink, false), "new-account")

	assert.Equals(t, dir.getLink(AccountLink, true, id), "https://ca.smallstep.com/acme/account/1234")
	assert.Equals(t, dir.getLink(AccountLink, false, id), "account/1234")

	assert.Equals(t, dir.getLink(NewOrderLink, true), "https://ca.smallstep.com/acme/new-order")
	assert.Equals(t, dir.getLink(NewOrderLink, false), "new-order")

	assert.Equals(t, dir.getLink(OrderLink, true, id), "https://ca.smallstep.com/acme/order/1234")
	assert.Equals(t, dir.getLink(OrderLink, false, id), "order/1234")

	assert.Equals(t, dir.getLink(OrdersByAccountLink, true, id), "https://ca.smallstep.com/acme/account/1234/orders")
	assert.Equals(t, dir.getLink(OrdersByAccountLink, false, id), "account/1234/orders")

	assert.Equals(t, dir.getLink(FinalizeLink, true, id), "https://ca.smallstep.com/acme/order/1234/finalize")
	assert.Equals(t, dir.getLink(FinalizeLink, false, id), "order/1234/finalize")

	assert.Equals(t, dir.getLink(NewAuthzLink, true), "https://ca.smallstep.com/acme/new-authz")
	assert.Equals(t, dir.getLink(NewAuthzLink, false), "new-authz")

	assert.Equals(t, dir.getLink(AuthzLink, true, id), "https://ca.smallstep.com/acme/authz/1234")
	assert.Equals(t, dir.getLink(AuthzLink, false, id), "authz/1234")

	assert.Equals(t, dir.getLink(DirectoryLink, true), "https://ca.smallstep.com/acme/directory")
	assert.Equals(t, dir.getLink(DirectoryLink, false), "directory")

	assert.Equals(t, dir.getLink(RevokeCertLink, true, id), "https://ca.smallstep.com/acme/revoke-cert/1234")
	assert.Equals(t, dir.getLink(RevokeCertLink, false, id), "revoke-cert/1234")

	assert.Equals(t, dir.getLink(KeyChangeLink, true), "https://ca.smallstep.com/acme/key-change")
	assert.Equals(t, dir.getLink(KeyChangeLink, false), "key-change")

	assert.Equals(t, dir.getLink(ChallengeLink, true, id), "https://ca.smallstep.com/acme/challenge/1234")
	assert.Equals(t, dir.getLink(ChallengeLink, false, id), "challenge/1234")

	assert.Equals(t, dir.getLink(CertificateLink, true, id), "https://ca.smallstep.com/acme/certificate/1234")
	assert.Equals(t, dir.getLink(CertificateLink, false, id), "certificate/1234")
}
