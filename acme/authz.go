package acme

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
)

var defaultExpiryDuration = time.Hour * 24

// Authz is a subset of the Authz type containing only those attributes
// required for responses in the ACME protocol.
type Authz struct {
	Identifier Identifier    `json:"identifier"`
	Status     string        `json:"status"`
	Expires    string        `json:"expires"`
	Challenges []interface{} `json:"challenges"`
	Wildcard   bool          `json:"wildcard"`
	ID         string        `json:"-"`
}

// GetID returns the Authz ID.
func (a *Authz) GetID() string {
	return a.ID
}

// authz is the interface that the various authz types must implement.
type authz interface {
	save(nosql.DB, authz) error
	getID() string
	getAccountID() string
	getType() string
	getStatus() string
	getExpiry() time.Time
	isWildcard() bool
	updateStatus(db nosql.DB) (authz, error)
	toACME(nosql.DB, *directory) (*Authz, error)
}

// baseAuthz is the base authz type that others build from.
type baseAuthz struct {
	ID         string     `json:"id"`
	AccountID  string     `json:"accountID"`
	Identifier Identifier `json:"identifier"`
	Status     string     `json:"status"`
	Expires    time.Time  `json:"expires"`
	Challenges []string   `json:"challenges"`
	Wildcard   bool       `json:"wildcard"`
	Created    time.Time
}

func newBaseAuthz(accID string, identifier Identifier) (*baseAuthz, error) {
	id, err := randID()
	if err != nil {
		return nil, err
	}

	ba := &baseAuthz{
		ID:         id,
		AccountID:  accID,
		Status:     statusPending,
		Created:    time.Now().UTC(),
		Expires:    time.Now().UTC().Add(defaultExpiryDuration),
		Identifier: identifier,
	}

	if strings.HasPrefix(identifier.Value, "*.") {
		ba.Wildcard = true
		ba.Identifier = Identifier{
			Value: strings.TrimPrefix(identifier.Value, "*."),
			Type:  identifier.Type,
		}
	}

	return ba, nil
}

// getID returns the ID of the authz.
func (ba *baseAuthz) getID() string {
	return ba.ID
}

// getAccountID returns the Account ID that created the authz.
func (ba *baseAuthz) getAccountID() string {
	return ba.AccountID
}

// getType returns the type of the authz.
func (ba *baseAuthz) getType() string {
	return ba.Identifier.Type
}

// getIdentifier returns the identifier for the authz.
func (ba *baseAuthz) getIdentifier() Identifier {
	return ba.Identifier
}

// getStatus returns the status of the authz.
func (ba *baseAuthz) getStatus() string {
	return ba.Status
}

// isWildcard returns true if the authz identifier has a '*', false otherwise.
func (ba *baseAuthz) isWildcard() bool {
	return ba.Wildcard
}

// getExpiry returns the expiration time of the authz.
func (ba *baseAuthz) getExpiry() time.Time {
	return ba.Expires
}

// toACME converts the internal Authz type into the public acmeAuthz type for
// presentation in the ACME protocol.
func (ba *baseAuthz) toACME(db nosql.DB, dir *directory) (*Authz, error) {
	var chs = make([]interface{}, len(ba.Challenges))
	for i, chID := range ba.Challenges {
		ch, err := getChallenge(db, chID)
		if err != nil {
			return nil, err
		}
		chs[i], err = ch.toACME(db, dir)
		if err != nil {
			return nil, err
		}
	}
	return &Authz{
		Identifier: ba.Identifier,
		Status:     ba.getStatus(),
		Challenges: chs,
		Wildcard:   ba.isWildcard(),
		Expires:    ba.Expires.Format(time.RFC3339),
		ID:         ba.ID,
	}, nil
}

func (ba *baseAuthz) save(db nosql.DB, old authz) error {
	var (
		err        error
		oldB, newB []byte
	)
	if old == nil {
		oldB = nil
	} else {
		if oldB, err = json.Marshal(old); err != nil {
			return ServerInternalErr(errors.Wrap(err, "error marshaling old authz"))
		}
	}
	if newB, err = json.Marshal(ba); err != nil {
		return ServerInternalErr(errors.Wrap(err, "error marshaling new authz"))
	}
	_, swapped, err := db.CmpAndSwap(authzTable, []byte(ba.ID), oldB, newB)
	switch {
	case err != nil:
		return ServerInternalErr(errors.Wrapf(err, "error storing authz with ID %s", ba.ID))
	case !swapped:
		return ServerInternalErr(errors.Errorf("error storing authz with ID %s; "+
			"value has changed since last read", ba.ID))
	default:
		return nil
	}
}

func (ba *baseAuthz) clone() *baseAuthz {
	u := *ba
	return &u
}

// updateStatus attempts to update the status on a baseAuthz and stores the
// updating object if necessary.
func (ba *baseAuthz) updateStatus(db nosql.DB) (authz, error) {
	newAuthz := ba.clone()

	now := time.Now().UTC()
	switch ba.Status {
	case statusInvalid:
		return ba, nil
	case statusValid:
		return ba, nil
	case statusReady:
		// check expiry
		if now.After(ba.Expires) {
			newAuthz.Status = statusInvalid
			// TODO add something to error/problem indicating expiration.
			break
		}
		return ba, nil
	case statusPending:
		// check expiry
		if now.After(ba.Expires) {
			newAuthz.Status = statusInvalid
			// TODO add something to error/problem indicating expiration.
			break
		}

		var isValid = false
		for _, chID := range ba.Challenges {
			ch, err := getChallenge(db, chID)
			if err != nil {
				return ba, err
			}
			if ch.getStatus() == statusValid {
				isValid = true
				break
			}
		}

		if isValid {
			newAuthz.Status = statusValid
			break
		}
		// Still pending, so do nothing.
		return ba, nil
	}

	if err := newAuthz.save(db, ba); err != nil {
		return ba, err
	}
	return newAuthz, nil
}

// unmarshalAuthz unmarshals an authz type into the correct sub-type.
func unmarshalAuthz(data []byte) (authz, error) {
	var getType struct {
		Identifier Identifier `json:"identifier"`
	}
	if err := json.Unmarshal(data, &getType); err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling authz type"))
	}

	switch getType.Identifier.Type {
	case "dns":
		var az DNSAuthz
		if err := json.Unmarshal(data, &az); err != nil {
			return nil, ServerInternalErr(errors.Wrap(err, "error unmarshaling authz type into DNSAuthz"))
		}
		return &az, nil
	default:
		return nil, ServerInternalErr(errors.Errorf("unexpected authz type %s",
			getType.Identifier.Type))
	}
}

// DNSAuthz represents a dns acme authorization.
type DNSAuthz struct {
	*baseAuthz
}

// newAuthz returns a new acme authorization object based on the identifier
// type.
func newAuthz(db nosql.DB, accID string, identifier Identifier) (a authz, err error) {
	switch identifier.Type {
	case "dns":
		a, err = newDNSAuthz(db, accID, identifier)
	default:
		err = MalformedErr(errors.Errorf("unexpected authorization type %s",
			identifier.Type))
	}
	return
}

// newDNSAuthz returns a new dns acme authorization object.
func newDNSAuthz(db nosql.DB, accID string, identifier Identifier) (authz, error) {
	ba, err := newBaseAuthz(accID, identifier)
	if err != nil {
		return nil, err
	}

	ch1, err := newHTTP01Challenge(db, ChallengeOptions{
		AccountID:  accID,
		AuthzID:    ba.ID,
		Identifier: identifier})
	if err != nil {
		return nil, err
	}
	ch2, err := newDNS01Challenge(db, ChallengeOptions{
		AccountID:  accID,
		AuthzID:    ba.ID,
		Identifier: identifier})
	if err != nil {
		return nil, err
	}
	ba.Challenges = []string{ch1.getID(), ch2.getID()}

	da := &DNSAuthz{ba}
	if err := da.save(db, nil); err != nil {
		return nil, err
	}

	return da, nil
}

// getAuthz retrieves and unmarshals an ACME authz type from the database.
func getAuthz(db nosql.DB, id string) (authz, error) {
	b, err := db.Get(authzTable, []byte(id))
	if nosql.IsErrNotFound(err) {
		return nil, MalformedErr(errors.Wrapf(err, "authz %s not found", id))
	} else if err != nil {
		return nil, ServerInternalErr(errors.Wrap(err, "error loading authz"))
	}
	az, err := unmarshalAuthz(b)
	if err != nil {
		return nil, err
	}
	return az, nil
}
