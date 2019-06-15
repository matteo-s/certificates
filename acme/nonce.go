package acme

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

var nonceLen = 32

// Nonce contains nonce metadata used in the ACME protocol.
type Nonce struct {
	Created time.Time
}

// newNonce creates, stores, and returns an ACME replay-nonce.
func newNonce(db nosql.DB) (string, error) {
	b := make([]byte, nonceLen)
	_, err := rand.Read(b)
	if err != nil {
		return "", ServerInternalErr(errors.Wrap(err, "error reading random bytes from crypto/rand"))
	}

	val := base64.RawURLEncoding.EncodeToString(b)
	n := &Nonce{
		Created: time.Now().UTC(),
	}
	nb, err := json.Marshal(n)
	if err != nil {
		return "", ServerInternalErr(errors.Wrap(err, "error marshaling nonce"))
	}
	if err := db.Set(nonceTable, []byte(val), nb); err != nil {
		return "", ServerInternalErr(errors.Wrap(err, "error saving nonce"))
	}
	return val, nil
}

// useNonce verifies that the nonce is valid (by checking if it exists),
// and if so, consumes the nonce resource by deleting it from the database.
func useNonce(db nosql.DB, nonce string) error {
	err := db.Update(&database.Tx{
		Operations: []*database.TxEntry{
			&database.TxEntry{
				Bucket: nonceTable,
				Key:    []byte(nonce),
				Cmd:    database.Get,
			},
			&database.TxEntry{
				Bucket: nonceTable,
				Key:    []byte(nonce),
				Cmd:    database.Delete,
			},
		},
	})

	switch {
	case nosql.IsErrNotFound(err):
		return BadNonceErr(nil)
	case err != nil:
		return ServerInternalErr(errors.Wrap(err, "use-nonce: DB error"))
	default:
		return nil
	}
}
