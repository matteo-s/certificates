package acme

import (
	"crypto/x509"
	"net"
	"net/http"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/nosql"
)

// Interface is the acme authority interface.
type Interface interface {
	DeactivateAccount(string) (*Account, error)
	FinalizeOrder(string, string, *x509.CertificateRequest) (*Order, error)
	GetAccount(string) (*Account, error)
	GetAccountByKeyID(string) (*Account, error)
	GetAuthz(string, string) (*Authz, error)
	GetChallenge(string, string) (*Challenge, error)
	GetCertificate(string, string) ([]byte, error)
	GetDirectory() *Directory
	GetLink(Link, bool, ...string) string
	GetOrder(string, string) (*Order, error)
	GetOrdersByAccount(string) ([]string, error)
	NewAccount(AccountOptions) (*Account, error)
	NewNonce() (string, error)
	NewOrder(OrderOptions) (*Order, error)
	UpdateAccount(string, []string) (*Account, error)
	UseNonce(string) error
	ValidateChallenge(string, string, *jose.JSONWebKey) (*Challenge, error)
}

// Authority is the layer that handles all ACME interactions.
type Authority struct {
	db       nosql.DB
	dir      *directory
	signAuth SignAuthority
}

// NewAuthority returns a new Authority that implements the ACME interface.
func NewAuthority(db nosql.DB, dns, prefix string, signAuth SignAuthority) *Authority {
	return &Authority{
		db: db, dir: newDirectory(dns, prefix), signAuth: signAuth,
	}
}

// GetLink returns the requested link from the directory.
func (a *Authority) GetLink(typ Link, abs bool, inputs ...string) string {
	return a.dir.getLink(typ, abs, inputs...)
}

// GetDirectory returns the ACME directory object.
func (a *Authority) GetDirectory() *Directory {
	return &Directory{
		NewNonce:   a.dir.getLink(NewNonceLink, true),
		NewAccount: a.dir.getLink(NewAccountLink, true),
		NewOrder:   a.dir.getLink(NewOrderLink, true),
		RevokeCert: a.dir.getLink(RevokeCertLink, true),
		KeyChange:  a.dir.getLink(KeyChangeLink, true),
	}
}

// NewNonce generates, stores, and returns a new ACME nonce.
func (a *Authority) NewNonce() (string, error) {
	n, err := newNonce(a.db)
	if err != nil {
		return "", err
	}
	return n.ID, nil
}

// UseNonce consumes the given nonce if it is valid, returns error otherwise.
func (a *Authority) UseNonce(nonce string) error {
	return useNonce(a.db, nonce)
}

// NewAccount creates, stores, and returns a new ACME account.
func (a *Authority) NewAccount(ao AccountOptions) (*Account, error) {
	acc, err := newAccount(a.db, ao)
	if err != nil {
		return nil, err
	}
	return acc.toACME(a.db, a.dir)
}

// UpdateAccount updates an ACME account.
func (a *Authority) UpdateAccount(id string, contact []string) (*Account, error) {
	acc, err := getAccountByID(a.db, id)
	if err != nil {
		return nil, ServerInternalErr(err)
	}
	if acc, err = acc.update(a.db, contact); err != nil {
		return nil, err
	}
	return acc.toACME(a.db, a.dir)
}

// GetAccount returns an ACME account.
func (a *Authority) GetAccount(id string) (*Account, error) {
	acc, err := getAccountByID(a.db, id)
	if err != nil {
		return nil, err
	}
	return acc.toACME(a.db, a.dir)
}

// DeactivateAccount deactivates an ACME account.
func (a *Authority) DeactivateAccount(id string) (*Account, error) {
	acc, err := getAccountByID(a.db, id)
	if err != nil {
		return nil, err
	}
	if acc, err = acc.deactivate(a.db); err != nil {
		return nil, err
	}
	return acc.toACME(a.db, a.dir)
}

// GetAccountByKeyID returns the ACME associated with the jwk id.
func (a *Authority) GetAccountByKeyID(kid string) (*Account, error) {
	acc, err := getAccountByKeyID(a.db, kid)
	if err != nil {
		return nil, err
	}
	return acc.toACME(a.db, a.dir)
}

// GetOrder returns an ACME order.
func (a *Authority) GetOrder(accID, orderID string) (*Order, error) {
	order, err := getOrder(a.db, orderID)
	if err != nil {
		return nil, err
	}
	if accID != order.AccountID {
		return nil, UnauthorizedErr(errors.New("account does not own order"))
	}
	return order.toACME(a.db, a.dir)
}

// GetOrdersByAccount returns the list of order urls owned by the account.
func (a *Authority) GetOrdersByAccount(id string) ([]string, error) {
	oids, err := getOrderIDsByAccount(a.db, id)
	if err != nil {
		return nil, err
	}

	var ret = []string{}
	for _, oid := range oids {
		o, err := getOrder(a.db, oid)
		if err != nil {
			return nil, ServerInternalErr(err)
		}
		if o.Status == StatusInvalid {
			continue
		}
		ret = append(ret, a.dir.getLink(OrderLink, true, o.ID))
	}
	return ret, nil
}

// NewOrder generates, stores, and returns a new ACME order.
func (a *Authority) NewOrder(ops OrderOptions) (*Order, error) {
	order, err := newOrder(a.db, ops)
	if err != nil {
		return nil, Wrap(err, "error creating order")
	}
	return order.toACME(a.db, a.dir)
}

// FinalizeOrder attempts to finalize an order and generate a new certificate.
func (a *Authority) FinalizeOrder(accID, orderID string, csr *x509.CertificateRequest) (*Order, error) {
	o, err := getOrder(a.db, orderID)
	if err != nil {
		return nil, err
	}
	if accID != o.AccountID {
		return nil, UnauthorizedErr(errors.New("account does not own order"))
	}
	o, err = o.finalize(a.db, csr, a.signAuth)
	if err != nil {
		return nil, Wrap(err, "error finalizing order")
	}
	return o.toACME(a.db, a.dir)
}

// GetAuthz retrieves and attempts to update the status on an ACME authz
// before returning.
func (a *Authority) GetAuthz(accID, authzID string) (*Authz, error) {
	authz, err := getAuthz(a.db, authzID)
	if err != nil {
		return nil, err
	}
	if accID != authz.getAccountID() {
		return nil, UnauthorizedErr(errors.New("account does not own authz"))
	}
	authz, err = authz.updateStatus(a.db)
	if err != nil {
		return nil, Wrap(err, "error updating authz status")
	}
	return authz.toACME(a.db, a.dir)
}

// GetChallenge retrieves the ACME challenge by ID.
func (a *Authority) GetChallenge(accID, chID string) (*Challenge, error) {
	ch, err := getChallenge(a.db, chID)
	if err != nil {
		return nil, err
	}
	if accID != ch.getAccountID() {
		return nil, UnauthorizedErr(errors.New("account does not own challenge"))
	}
	return ch.toACME(a.db, a.dir)
}

// ValidateChallenge attempts to validate the challenge.
func (a *Authority) ValidateChallenge(accID, chID string, jwk *jose.JSONWebKey) (*Challenge, error) {
	ch, err := getChallenge(a.db, chID)
	if err != nil {
		return nil, err
	}
	if accID != ch.getAccountID() {
		return nil, UnauthorizedErr(errors.New("account does not own challenge"))
	}
	ch, err = ch.validate(a.db, jwk, validateOptions{
		httpGet:   http.Get,
		lookupTxt: net.LookupTXT,
	})
	if err != nil {
		return nil, err
	}
	return ch.toACME(a.db, a.dir)
}

// GetCertificate retrieves the Certificate by ID.
func (a *Authority) GetCertificate(accID, certID string) ([]byte, error) {
	cert, err := getCert(a.db, certID)
	if err != nil {
		return nil, err
	}
	if accID != cert.AccountID {
		return nil, UnauthorizedErr(errors.New("account does not own certificate"))
	}
	return cert.toACME(a.db, a.dir)
}
