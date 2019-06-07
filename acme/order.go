package acme

import (
	"crypto/x509"
	"encoding/json"
	"reflect"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/nosql"
)

var defaultOrderExpiry = time.Hour * 24

// Order contains order metadata for the ACME protocol order type.
type Order struct {
	Status         string       `json:"status"`
	Expires        string       `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      string       `json:"notBefore,omitempty"`
	NotAfter       string       `json:"notAfter,omitempty"`
	Error          interface{}  `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate,omitempty"`
	ID             string       `json:"-"`
}

// GetID returns the Order ID.
func (o *Order) GetID() string {
	return o.ID
}

// OrderOptions options with which to create a new Order.
type OrderOptions struct {
	AccountID   string       `json:"accID"`
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   time.Time    `json:"notBefore"`
	NotAfter    time.Time    `json:"notAfter"`
}

type order struct {
	ID             string       `json:"id"`
	AccountID      string       `json:"accountID"`
	Created        time.Time    `json:"created"`
	Status         string       `json:"status"`
	Expires        time.Time    `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      time.Time    `json:"notBefore,omitempty"`
	NotAfter       time.Time    `json:"notAfter,omitempty"`
	Error          interface{}  `json:"error,omitempty"`
	Authorizations []string     `json:"authorizations"`
	Certificate    string       `json:"certificate,omitempty"`
}

// newOrder returns a new Order type.
func newOrder(db nosql.DB, ops OrderOptions) (*order, error) {
	id, err := randID()
	if err != nil {
		return nil, err
	}

	authzs := make([]string, len(ops.Identifiers))
	for i, identifier := range ops.Identifiers {
		authz, err := newAuthz(db, ops.AccountID, identifier)
		if err != nil {
			return nil, err
		}
		authzs[i] = authz.getID()
	}

	now := time.Now().UTC()
	o := &order{
		ID:             id,
		AccountID:      ops.AccountID,
		Created:        now,
		Status:         statusPending,
		Expires:        now.Add(defaultOrderExpiry),
		Identifiers:    ops.Identifiers,
		NotBefore:      ops.NotBefore,
		NotAfter:       ops.NotAfter,
		Authorizations: authzs,
	}
	if err := o.save(db, nil); err != nil {
		return nil, err
	}

	// TODO should we delete the Order if there are errors downstream?

	// Update the "order IDs by account ID" index //
	orderIDs, err := getOrderIDsByAccount(db, ops.AccountID)
	if err != nil {
		return nil, err
	}
	var oldb []byte
	if len(orderIDs) == 0 {
		oldb = nil
	} else {
		oldb, err = json.Marshal(orderIDs)
		if err != nil {
			return nil, ServerInternalErr(errors.Wrap(err, "error marshaling old order IDs slice"))
		}
	}
	newOrderIDs := append(orderIDs, o.ID)
	newb, err := json.Marshal(newOrderIDs)
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error marshaling new order IDs slice"))
	}
	_, swapped, err := db.CmpAndSwap(ordersByAccountIDTable, []byte(o.AccountID), oldb, newb)
	switch {
	case err != nil:
		return nil, ServerInternalErr(errors.Wrapf(err, "error storing order IDs for account %s", o.AccountID))
	case !swapped:
		return nil, ServerInternalErr(errors.Errorf("error storing order IDs "+
			"for account %s; order IDs changed since last read", o.AccountID))
	default:
		return o, nil
	}
}

func (o *order) save(db nosql.DB, old *order) error {
	var (
		err  error
		oldB []byte
	)
	if old == nil {
		oldB = nil
	} else {
		if oldB, err = json.Marshal(old); err != nil {
			return ServerInternalErr(errors.Wrap(err, "error marshaling old acme order"))
		}
	}

	newB, err := json.Marshal(o)
	if err != nil {
		return ServerInternalErr(errors.Wrap(err, "error marshaling new acme order"))
	}

	_, swapped, err := db.CmpAndSwap(orderTable, []byte(o.ID), oldB, newB)
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrap(err, "error writing acme order to disk"))
	case !swapped:
		return ServerInternalErr(errors.Errorf("error writing acme order to disk; "+
			"order %s has changed since last read", o.ID))
	default:
		return nil
	}
}

// updateStatus updates order status if necessary.
func (o *order) updateStatus(db nosql.DB) (*order, error) {
	_newOrder := *o
	newOrder := &_newOrder

	now := time.Now().UTC()
	switch o.Status {
	case statusInvalid:
		return o, nil
	case statusValid:
		return o, nil
	case statusReady:
		// check expiry
		if now.After(o.Expires) {
			newOrder.Status = statusInvalid
			// TODO add something to error/problem indicating expiration.
			break
		}
		return o, nil
	case statusPending:
		// check expiry
		if now.After(o.Expires) {
			newOrder.Status = statusInvalid
			// TODO add something to error/problem indicating expiration.
			break
		}

		var allValid = true
		for _, azID := range o.Authorizations {
			authz, err := getAuthz(db, azID)
			if err != nil {
				return nil, err
			}
			if authz, err = authz.updateStatus(db); err != nil {
				return nil, err
			}
			if authz.getStatus() != statusValid {
				allValid = false
				break
			}
		}

		if allValid {
			newOrder.Status = statusReady
			break
		}
		// Still pending, so do nothing.
		return o, nil
	}

	if err := newOrder.save(db, o); err != nil {
		return nil, err
	}
	return newOrder, nil
}

// finalize signs a certificate if the necessary conditions for Order completion
// have been met.
func (o *order) finalize(db nosql.DB, csr *x509.CertificateRequest, auth SignAuthority) (*order, error) {
	var err error
	if o, err = o.updateStatus(db); err != nil {
		return o, err
	}
	switch o.Status {
	case statusInvalid:
		return o, OrderNotReadyErr(errors.Errorf("order %s has been abandoned", o.ID))
	case statusValid:
		break
		//return o, errors.Errorf("order %s is already valid", o.ID)
	case statusPending:
		return o, OrderNotReadyErr(errors.Errorf("order %s is not ready", o.ID))
	case statusReady:
		break
	default:
		return o, ServerInternalErr(errors.Errorf("unexpected status %s for order %s", o.Status, o.ID))
	}

	// Validate identifier names against CSR alternative names //
	csrNames := make(map[string]int)
	if csr.Subject.CommonName != "" {
		csrNames[csr.Subject.CommonName] = 1
	}
	for _, n := range csr.DNSNames {
		csrNames[n] = 1
	}

	orderNames := make(map[string]int)
	for _, n := range o.Identifiers {
		orderNames[n.Value] = 1
	}

	if !reflect.DeepEqual(csrNames, orderNames) {
		// TODO Note reason on the Order error object.
		return nil, BadCSRErr(errors.Errorf("CSR names do not match order identifiers exactly"))
	}

	// Create and store a new certificate.
	leaf, inter, err := auth.Sign(csr, provisioner.Options{
		NotBefore: provisioner.NewTimeDuration(o.NotBefore),
		NotAfter:  provisioner.NewTimeDuration(o.NotAfter),
	})
	if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error generating certificat from finalize resource"))
	}

	cert, err := newCert(db, CertOptions{
		AccountID:     o.AccountID,
		OrderID:       o.ID,
		Leaf:          leaf,
		Intermediates: []*x509.Certificate{inter},
	})
	if err != nil {
		return nil, err
	}

	_newOrder := *o
	newOrder := &_newOrder
	newOrder.Certificate = cert.ID
	newOrder.Status = statusValid
	if err := newOrder.save(db, o); err != nil {
		return nil, err
	}
	return newOrder, nil
}

// getOrder retrieves and unmarshals an ACME Order type from the database.
func getOrder(db nosql.DB, id string) (*order, error) {
	b, err := db.Get(orderTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, MalformedErr(errors.Wrapf(err, "order %s not found", id))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error loading order"))
	}
	var o order
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling order"))
	}
	return &o, nil
}

// toACME converts the internal Order type into the public acmeOrder type for
// presentation in the ACME protocol.
func (o *order) toACME(db nosql.DB, dir *directory) (*Order, error) {
	azs := make([]string, len(o.Authorizations))
	for i, aid := range o.Authorizations {
		azs[i] = dir.getLink(AuthzLink, true, aid)
	}
	ao := &Order{
		Status:         o.Status,
		Expires:        o.Expires.Format(time.RFC3339),
		Identifiers:    o.Identifiers,
		NotBefore:      o.NotBefore.Format(time.RFC3339),
		NotAfter:       o.NotAfter.Format(time.RFC3339),
		Authorizations: azs,
		Finalize:       dir.getLink(FinalizeLink, true, o.ID),
		ID:             o.ID,
	}

	if o.Certificate != "" {
		ao.Certificate = dir.getLink(CertificateLink, true, o.Certificate)
	}
	return ao, nil
}
