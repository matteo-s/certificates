package acme

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/nosql"
)

// Account is a subset of the internal account type containing only those
// attributes required for responses in the ACME protocol.
type Account struct {
	Contact []string         `json:"contact,omitempty"`
	Status  string           `json:"status"`
	Orders  string           `json:"orders"`
	ID      string           `json:"-"`
	Key     *jose.JSONWebKey `json:"-"`
}

// GetID returns the account ID.
func (a *Account) GetID() string {
	return a.ID
}

// GetKey returns the JWK associated with the account.
func (a *Account) GetKey() *jose.JSONWebKey {
	return a.Key
}

// IsValid returns true if the Account is valid.
func (a *Account) IsValid() bool {
	return a.Status == statusValid
}

// AccountOptions are the options needed to create a new ACME account.
type AccountOptions struct {
	Key     *jose.JSONWebKey
	Contact []string
}

// account represents an ACME account.
type account struct {
	ID          string           `json:"id"`
	Created     time.Time        `json:"created"`
	Deactivated time.Time        `json:"deactivated"`
	Key         *jose.JSONWebKey `json:"key"`
	Contact     []string         `json:"contact,omitempty"`
	Status      string           `json:"status"`
}

// newAccount returns a new acme account type.
func newAccount(db nosql.DB, ops AccountOptions) (*account, error) {
	id, err := randID()
	if err != nil {
		return nil, err
	}

	a := &account{
		ID:      id,
		Key:     ops.Key,
		Contact: ops.Contact,
		Status:  "valid",
		Created: time.Now().UTC(),
	}

	if err := a.save(db, nil); err != nil {
		return nil, err
	}
	return a, nil
}

// toACME converts the internal Account type into the public acmeAccount
// type for presentation in the ACME protocol.
func (a *account) toACME(db nosql.DB, dir *directory) (*Account, error) {
	return &Account{
		Status:  a.Status,
		Contact: a.Contact,
		Orders:  dir.getLink(OrdersByAccountLink, true, a.ID),
		Key:     a.Key,
		ID:      a.ID,
	}, nil
}

// save writes the Account to the DB.
// If the account is new then the necessary indices will be created.
// Else, the account in the DB will be updated.
func (a *account) save(db nosql.DB, swp *account) error {
	if swp != nil {
		return saveUpdate(db, a, swp)
	}

	jwkID := []byte(a.Key.KeyID)

	// Set the jwkID -> acme account ID index
	_, swapped, err := db.CmpAndSwap(accountByKeyIDTable, jwkID, nil, []byte(a.ID))
	if err != nil {
		return errors.Wrap(err, "error setting jwkID to acme account index")
	} else if !swapped {
		return errors.Errorf("jwkID to acme account index already has entry for jwkID %s", jwkID)
	}

	accB, err := json.Marshal(*a)
	if err != nil {
		return errors.Wrap(err, "error marshaling acme account object")
	}

	// Set the Account
	_, swapped, err = db.CmpAndSwap(accountTable, []byte(a.ID), nil, accB)
	if err != nil || !swapped {
		// Attempt to clean up previously added index
		db.Del(accountByKeyIDTable, jwkID)
		if err != nil {
			return errors.Wrap(err, "error setting new acme account")
		}
		return errors.Errorf("acme account with ID %s already exists", a.ID)
	}

	return nil
}

func saveUpdate(db nosql.DB, acc, swp *account) error {
	swpB, err := json.Marshal(*swp)
	if err != nil {
		return errors.Wrap(err, "error marshaling acme account object")
	}

	accB, err := json.Marshal(*acc)
	if err != nil {
		return errors.Wrap(err, "error marshaling acme account object")
	}
	// Set the Account
	_, swapped, err := db.CmpAndSwap(accountTable, []byte(acc.ID), swpB, accB)
	if err != nil {
		return errors.Wrapf(err,
			"error updating account with ID %s", acc.ID)
	} else if !swapped {
		return errors.Wrapf(err,
			"error updating account; account with ID %s has changed since last read", acc.ID)
	}
	return nil
}

// update updates the acme account object stored in the database if,
// and only if, the account has not changed since the last read.
func (a *account) update(db nosql.DB, contact []string) (*account, error) {
	b := *a
	b.Contact = contact
	if err := (&b).save(db, a); err != nil {
		return nil, err
	}
	return &b, nil
}

// deactivate deactivates the acme account.
func (a *account) deactivate(db nosql.DB) (*account, error) {
	b := *a
	b.Status = statusDeactivated
	b.Deactivated = time.Now().UTC()
	if err := (&b).save(db, a); err != nil {
		return nil, err
	}
	return &b, nil
}

// getAccountByID retrieves the account with the given ID.
func getAccountByID(db nosql.DB, id string) (*account, error) {
	ab, err := db.Get(accountTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, MalformedErr(errors.Wrapf(err, "account %s not found", id))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error loading account"))
	}

	var a account
	if err = json.Unmarshal(ab, &a); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling account"))
	}
	return &a, nil
}

// getAccountByKeyID retrieves Id associated with the given Kid.
func getAccountByKeyID(db nosql.DB, kid string) (*account, error) {
	id, err := db.Get(accountByKeyIDTable, []byte(kid))
	if nosql.IsErrNotFound(err) {
		return nil, MalformedErr(errors.Wrapf(err, "account with key id %s not found", kid))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error loading key-account index"))
	}
	return getAccountByID(db, string(id))
}

// getOrderIDsByAccount retrieves a list of Order IDs that were created by the
// account.
func getOrderIDsByAccount(db nosql.DB, id string) ([]string, error) {
	b, err := db.Get(ordersByAccountIDTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return []string{}, nil
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error loading orderIDs for account %s", id))
	}
	var orderIDs []string
	if err := json.Unmarshal(b, &orderIDs); err != nil {
		return nil, ServerInternalErr(errors.Wrapf(err, "error unmarshaling orderIDs for account %s", id))
	}
	return orderIDs, nil
}
