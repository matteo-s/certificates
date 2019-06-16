package acme

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/db"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/nosql/database"
)

func TestAuthorityGetLink(t *testing.T) {
	auth := NewAuthority(nil, "ca.smallstep.com", "acme", nil)
	type test struct {
		auth   *Authority
		typ    Link
		abs    bool
		inputs []string
		res    string
	}
	tests := map[string]func(t *testing.T) test{
		"ok/new-account/abs": func(t *testing.T) test {
			return test{
				auth: auth,
				typ:  NewAccountLink,
				abs:  true,
				res:  "https://ca.smallstep.com/acme/new-account",
			}
		},
		"ok/new-account/no-abs": func(t *testing.T) test {
			return test{
				auth: auth,
				typ:  NewAccountLink,
				abs:  false,
				res:  "/new-account",
			}
		},
		"ok/order/abs": func(t *testing.T) test {
			return test{
				auth:   auth,
				typ:    OrderLink,
				abs:    true,
				inputs: []string{"foo"},
				res:    "https://ca.smallstep.com/acme/order/foo",
			}
		},
		"ok/order/no-abs": func(t *testing.T) test {
			return test{
				auth:   auth,
				typ:    OrderLink,
				abs:    false,
				inputs: []string{"foo"},
				res:    "/order/foo",
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			link := tc.auth.GetLink(tc.typ, tc.abs, tc.inputs...)
			assert.Equals(t, tc.res, link)
		})
	}
}

func TestAuthorityGetDirectory(t *testing.T) {
	auth := NewAuthority(nil, "ca.smallstep.com", "acme", nil)
	acmeDir := auth.GetDirectory()
	assert.Equals(t, acmeDir.NewNonce, "https://ca.smallstep.com/acme/new-nonce")
	assert.Equals(t, acmeDir.NewAccount, "https://ca.smallstep.com/acme/new-account")
	assert.Equals(t, acmeDir.NewOrder, "https://ca.smallstep.com/acme/new-order")
	//assert.Equals(t, acmeDir.NewOrder, "httsp://ca.smallstep.com/acme/new-authz")
	assert.Equals(t, acmeDir.RevokeCert, "https://ca.smallstep.com/acme/revoke-cert")
	assert.Equals(t, acmeDir.KeyChange, "https://ca.smallstep.com/acme/key-change")
}

func TestAuthorityNewNonce(t *testing.T) {
	type test struct {
		auth *Authority
		res  *string
		err  *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/newNonce-error": func(t *testing.T) test {
			auth := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				res:  nil,
				err:  ServerInternalErr(errors.New("error storing nonce: force")),
			}
		},
		"ok": func(t *testing.T) test {
			var _res string
			res := &_res
			auth := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					*res = string(key)
					return nil, true, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				res:  res,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if nonce, err := tc.auth.NewNonce(); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, nonce, *tc.res)
				}
			}
		})
	}
}

func TestAuthorityUseNonce(t *testing.T) {
	type test struct {
		auth *Authority
		err  *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/newNonce-error": func(t *testing.T) test {
			auth := NewAuthority(&db.MockNoSQLDB{
				MUpdate: func(tx *database.Tx) error {
					return errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				err:  ServerInternalErr(errors.New("error deleting nonce foo: force")),
			}
		},
		"ok": func(t *testing.T) test {
			auth := NewAuthority(&db.MockNoSQLDB{
				MUpdate: func(tx *database.Tx) error {
					return nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.auth.UseNonce("foo"); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestAuthorityNewAccount(t *testing.T) {
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	assert.FatalError(t, err)
	ops := AccountOptions{
		Key: jwk, Contact: []string{"foo", "bar"},
	}
	type test struct {
		auth *Authority
		ops  AccountOptions
		err  *Error
		acc  **Account
	}
	tests := map[string]func(t *testing.T) test{
		"fail/newAccount-error": func(t *testing.T) test {
			auth := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				ops:  ops,
				err:  ServerInternalErr(errors.New("error setting key-id to account-id index: force")),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				_acmeacc = &Account{}
				acmeacc  = &_acmeacc
				count    = 0
				dir      = newDirectory("ca.smallstep.com", "acme")
			)
			auth := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					if count == 1 {
						var acc *account
						assert.FatalError(t, json.Unmarshal(newval, &acc))
						*acmeacc, err = acc.toACME(nil, dir)
						return nil, true, nil
					}
					count++
					return nil, true, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				ops:  ops,
				acc:  acmeacc,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAcc, err := tc.auth.NewAccount(tc.ops); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAcc)
					assert.FatalError(t, err)
					expb, err := json.Marshal(*tc.acc)
					assert.FatalError(t, err)
					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetAccount(t *testing.T) {
	type test struct {
		auth *Authority
		id   string
		err  *Error
		acc  *account
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getAccount-error": func(t *testing.T) test {
			id := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, accountTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.Errorf("error loading account %s: force", id)),
			}
		},
		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   acc.ID,
				acc:  acc,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAcc, err := tc.auth.GetAccount(tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAcc)
					assert.FatalError(t, err)

					acmeExp, err := tc.acc.toACME(nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetAccountByKeyID(t *testing.T) {
	type test struct {
		auth *Authority
		kid  string
		err  *Error
		acc  *account
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getAccount-error": func(t *testing.T) test {
			kid := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, accountByKeyIDTable)
					assert.Equals(t, key, []byte(kid))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				kid:  kid,
				err:  ServerInternalErr(errors.New("error loading key-account index: force")),
			}
		},
		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)
			count := 0
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch {
					case count == 0:
						assert.Equals(t, bucket, accountByKeyIDTable)
						assert.Equals(t, key, []byte(acc.Key.KeyID))
						ret = []byte(acc.ID)
					case count == 1:
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, key, []byte(acc.ID))
						ret = b
					}
					count++
					return ret, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				kid:  acc.Key.KeyID,
				acc:  acc,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAcc, err := tc.auth.GetAccountByKeyID(tc.kid); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAcc)
					assert.FatalError(t, err)

					acmeExp, err := tc.acc.toACME(nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetOrder(t *testing.T) {
	type test struct {
		auth      *Authority
		id, accID string
		err       *Error
		o         *order
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getOrder-error": func(t *testing.T) test {
			id := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.New("error loading order foo: force")),
			}
		},
		"fail/order-not-owned-by-account": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: "foo",
				err:   UnauthorizedErr(errors.New("account does not own order")),
			}
		},
		"ok": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: o.AccountID,
				o:     o,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeO, err := tc.auth.GetOrder(tc.accID, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeO)
					assert.FatalError(t, err)

					acmeExp, err := tc.o.toACME(nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetChallenge(t *testing.T) {
	type test struct {
		auth      *Authority
		id, accID string
		err       *Error
		ch        challenge
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getChallenge-error": func(t *testing.T) test {
			id := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.Errorf("error loading challenge %s: force", id)),
			}
		},
		"fail/challenge-not-owned-by-account": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			b, err := json.Marshal(ch)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    ch.getID(),
				accID: "foo",
				err:   UnauthorizedErr(errors.New("account does not own challenge")),
			}
		},
		"ok": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			b, err := json.Marshal(ch)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    ch.getID(),
				accID: ch.getAccountID(),
				ch:    ch,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeCh, err := tc.auth.GetChallenge(tc.accID, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeCh)
					assert.FatalError(t, err)

					acmeExp, err := tc.ch.toACME(nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetCertificate(t *testing.T) {
	type test struct {
		auth      *Authority
		id, accID string
		err       *Error
		cert      *certificate
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getCertificate-error": func(t *testing.T) test {
			id := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, certTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.New("error loading certificate: force")),
			}
		},
		"fail/certificate-not-owned-by-account": func(t *testing.T) test {
			cert, err := newcert()
			assert.FatalError(t, err)
			b, err := json.Marshal(cert)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, certTable)
					assert.Equals(t, key, []byte(cert.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    cert.ID,
				accID: "foo",
				err:   UnauthorizedErr(errors.New("account does not own certificate")),
			}
		},
		"ok": func(t *testing.T) test {
			cert, err := newcert()
			assert.FatalError(t, err)
			b, err := json.Marshal(cert)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, certTable)
					assert.Equals(t, key, []byte(cert.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    cert.ID,
				accID: cert.AccountID,
				cert:  cert,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeCert, err := tc.auth.GetCertificate(tc.accID, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeCert)
					assert.FatalError(t, err)

					acmeExp, err := tc.cert.toACME(nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetAuthz(t *testing.T) {
	type test struct {
		auth      *Authority
		id, accID string
		err       *Error
		acmeAz    *Authz
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getAuthz-error": func(t *testing.T) test {
			id := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, authzTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.Errorf("error loading authz %s: force", id)),
			}
		},
		"fail/authz-not-owned-by-account": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			b, err := json.Marshal(az)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, authzTable)
					assert.Equals(t, key, []byte(az.getID()))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    az.getID(),
				accID: "foo",
				err:   UnauthorizedErr(errors.New("account does not own authz")),
			}
		},
		"fail/update-status-error": func(t *testing.T) test {
			az, err := newAz()
			assert.FatalError(t, err)
			b, err := json.Marshal(az)
			assert.FatalError(t, err)
			count := 0
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch count {
					case 0:
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, key, []byte(az.getID()))
						ret = b
					case 1:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(az.getChallenges()[0]))
						return nil, errors.New("force")
					}
					count++
					return ret, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    az.getID(),
				accID: az.getAccountID(),
				err:   ServerInternalErr(errors.New("error updating authz status: error loading challenge")),
			}
		},
		"ok": func(t *testing.T) test {
			var ch1B, ch2B = &[]byte{}, &[]byte{}
			count := 0
			mockdb := &db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					switch count {
					case 0:
						*ch1B = newval
					case 1:
						*ch2B = newval
					}
					count++
					return nil, true, nil
				},
			}
			az, err := newAuthz(mockdb, "1234", Identifier{
				Type: "dns", Value: "acme.example.com",
			})
			assert.FatalError(t, err)
			_az, ok := az.(*dnsAuthz)
			assert.Fatal(t, ok)
			_az.baseAuthz.Status = statusValid
			b, err := json.Marshal(az)
			assert.FatalError(t, err)

			ch1, err := unmarshalChallenge(*ch1B)
			assert.FatalError(t, err)
			ch2, err := unmarshalChallenge(*ch2B)
			assert.FatalError(t, err)
			count = 0
			mockdb = &db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch count {
					case 0:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch1.getID()))
						ret = *ch1B
					case 1:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch2.getID()))
						ret = *ch2B
					}
					count++
					return ret, nil
				},
			}
			acmeAz, err := az.toACME(mockdb, newDirectory("ca.smallstep.com", "acme"))
			assert.FatalError(t, err)

			count = 0
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch count {
					case 0:
						assert.Equals(t, bucket, authzTable)
						assert.Equals(t, key, []byte(az.getID()))
						ret = b
					case 1:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch1.getID()))
						ret = *ch1B
					case 2:
						assert.Equals(t, bucket, challengeTable)
						assert.Equals(t, key, []byte(ch2.getID()))
						ret = *ch2B
					}
					count++
					return ret, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:   auth,
				id:     az.getID(),
				accID:  az.getAccountID(),
				acmeAz: acmeAz,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAz, err := tc.auth.GetAuthz(tc.accID, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAz)
					assert.FatalError(t, err)

					expb, err := json.Marshal(tc.acmeAz)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityNewOrder(t *testing.T) {
	type test struct {
		auth *Authority
		ops  OrderOptions
		err  *Error
		o    **Order
	}
	tests := map[string]func(t *testing.T) test{
		"fail/newOrder-error": func(t *testing.T) test {
			auth := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				ops:  defaultOrderOps(),
				err:  ServerInternalErr(errors.New("error creating order: error creating http challenge: error saving acme challenge: force")),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				_acmeO = &Order{}
				acmeO  = &_acmeO
				count  = 0
				dir    = newDirectory("ca.smallstep.com", "acme")
				err    error
				_accID string
				accID  = &_accID
			)
			auth := NewAuthority(&db.MockNoSQLDB{
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					switch count {
					case 0:
						assert.Equals(t, bucket, challengeTable)
					case 1:
						assert.Equals(t, bucket, challengeTable)
					case 2:
						assert.Equals(t, bucket, authzTable)
					case 3:
						assert.Equals(t, bucket, challengeTable)
					case 4:
						assert.Equals(t, bucket, challengeTable)
					case 5:
						assert.Equals(t, bucket, authzTable)
					case 6:
						assert.Equals(t, bucket, orderTable)
						var o order
						assert.FatalError(t, json.Unmarshal(newval, &o))
						*acmeO, err = o.toACME(nil, dir)
						assert.FatalError(t, err)
						*accID = o.AccountID
					case 7:
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, string(key), *accID)
					}
					count++
					return nil, true, nil
				},
				MGet: func(bucket, key []byte) ([]byte, error) {
					return nil, database.ErrNotFound
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				ops:  defaultOrderOps(),
				o:    acmeO,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeO, err := tc.auth.NewOrder(tc.ops); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeO)
					assert.FatalError(t, err)
					expb, err := json.Marshal(*tc.o)
					assert.FatalError(t, err)
					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityGetOrdersByAccount(t *testing.T) {
	type test struct {
		auth *Authority
		id   string
		err  *Error
		res  []string
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getOrderIDsByAccount-error": func(t *testing.T) test {
			id := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, ordersByAccountIDTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.New("error loading orderIDs for account foo: force")),
			}
		},
		"fail/getOrder-error": func(t *testing.T) test {
			var (
				id    = "zap"
				oids  = []string{"foo", "bar"}
				count = 0
				err   error
			)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch count {
					case 0:
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(id))
						ret, err = json.Marshal(oids)
						assert.FatalError(t, err)
					case 1:
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, key, []byte(oids[0]))
						return nil, errors.New("force")
					}
					count++
					return ret, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.New("error loading order foo: force")),
			}
		},
		"ok": func(t *testing.T) test {
			var (
				id    = "zap"
				count = 0
				err   error
			)
			foo, err := newO()
			bar, err := newO()
			baz, err := newO()
			bar.Status = statusInvalid

			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					var ret []byte
					switch count {
					case 0:
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte(id))
						ret, err = json.Marshal([]string{foo.ID, bar.ID, baz.ID})
						assert.FatalError(t, err)
					case 1:
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, key, []byte(foo.ID))
						ret, err = json.Marshal(foo)
						assert.FatalError(t, err)
					case 2:
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, key, []byte(bar.ID))
						ret, err = json.Marshal(bar)
						assert.FatalError(t, err)
					case 3:
						assert.Equals(t, bucket, orderTable)
						assert.Equals(t, key, []byte(baz.ID))
						ret, err = json.Marshal(baz)
						assert.FatalError(t, err)
					}
					count++
					return ret, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				res: []string{
					fmt.Sprintf("https://ca.smallstep.com/acme/order/%s", foo.ID),
					fmt.Sprintf("https://ca.smallstep.com/acme/order/%s", baz.ID),
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if orderLinks, err := tc.auth.GetOrdersByAccount(tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.res, orderLinks)
				}
			}
		})
	}
}

func TestAuthorityFinalizeOrder(t *testing.T) {
	type test struct {
		auth      *Authority
		id, accID string
		err       *Error
		o         *order
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getOrder-error": func(t *testing.T) test {
			id := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.New("error loading order foo: force")),
			}
		},
		"fail/order-not-owned-by-account": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: "foo",
				err:   UnauthorizedErr(errors.New("account does not own order")),
			}
		},
		"fail/finalize-error": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Expires = time.Now().Add(-time.Minute)
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: o.AccountID,
				err:   ServerInternalErr(errors.New("error finalizing order: error storing order: force")),
			}
		},
		"ok": func(t *testing.T) test {
			o, err := newO()
			assert.FatalError(t, err)
			o.Status = statusValid
			o.Certificate = "certID"
			b, err := json.Marshal(o)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, orderTable)
					assert.Equals(t, key, []byte(o.ID))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    o.ID,
				accID: o.AccountID,
				o:     o,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeO, err := tc.auth.FinalizeOrder(tc.accID, tc.id, nil); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeO)
					assert.FatalError(t, err)

					acmeExp, err := tc.o.toACME(nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityValidateChallenge(t *testing.T) {
	type test struct {
		auth      *Authority
		id, accID string
		err       *Error
		ch        challenge
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getChallenge-error": func(t *testing.T) test {
			id := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.Errorf("error loading challenge %s: force", id)),
			}
		},
		"fail/challenge-not-owned-by-account": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			b, err := json.Marshal(ch)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    ch.getID(),
				accID: "foo",
				err:   UnauthorizedErr(errors.New("account does not own challenge")),
			}
		},
		"fail/validate-error": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			_ch, ok := ch.(*http01Challenge)
			assert.Fatal(t, ok)
			_ch.baseChallenge.Status = statusInvalid
			b, err := json.Marshal(ch)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    ch.getID(),
				accID: ch.getAccountID(),
				err:   MalformedErr(errors.New("challenge already has invalid status")),
			}
		},
		"ok": func(t *testing.T) test {
			ch, err := newHTTPCh()
			assert.FatalError(t, err)
			_ch, ok := ch.(*http01Challenge)
			assert.Fatal(t, ok)
			_ch.baseChallenge.Status = statusValid
			_ch.baseChallenge.Validated = time.Now().UTC().Round(time.Second)
			b, err := json.Marshal(ch)
			assert.FatalError(t, err)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, challengeTable)
					assert.Equals(t, key, []byte(ch.getID()))
					return b, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:  auth,
				id:    ch.getID(),
				accID: ch.getAccountID(),
				ch:    ch,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeCh, err := tc.auth.ValidateChallenge(tc.accID, tc.id, nil); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeCh)
					assert.FatalError(t, err)

					acmeExp, err := tc.ch.toACME(nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityUpdateAccount(t *testing.T) {
	contact := []string{"baz", "zap"}
	type test struct {
		auth    *Authority
		id      string
		contact []string
		acc     *account
		err     *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getAccount-error": func(t *testing.T) test {
			id := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, accountTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:    auth,
				id:      id,
				contact: contact,
				err:     ServerInternalErr(errors.Errorf("error loading account %s: force", id)),
			}
		},
		"fail/update-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)

			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:    auth,
				id:      acc.ID,
				contact: contact,
				err:     ServerInternalErr(errors.New("error storing account: force")),
			}
		},

		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)

			_acc := *acc
			clone := &_acc
			clone.Contact = contact
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, accountTable)
					assert.Equals(t, key, []byte(acc.ID))
					return nil, true, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth:    auth,
				id:      acc.ID,
				contact: contact,
				acc:     clone,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAcc, err := tc.auth.UpdateAccount(tc.id, tc.contact); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAcc)
					assert.FatalError(t, err)

					acmeExp, err := tc.acc.toACME(nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}

func TestAuthorityDeactivateAccount(t *testing.T) {
	type test struct {
		auth *Authority
		id   string
		acc  *account
		err  *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/getAccount-error": func(t *testing.T) test {
			id := "foo"
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					assert.Equals(t, bucket, accountTable)
					assert.Equals(t, key, []byte(id))
					return nil, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   id,
				err:  ServerInternalErr(errors.Errorf("error loading account %s: force", id)),
			}
		},
		"fail/deactivate-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)

			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					return nil, false, errors.New("force")
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   acc.ID,
				err:  ServerInternalErr(errors.New("error storing account: force")),
			}
		},

		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)

			_acc := *acc
			clone := &_acc
			clone.Status = statusDeactivated
			clone.Deactivated = time.Now().UTC().Round(time.Second)
			auth := NewAuthority(&db.MockNoSQLDB{
				MGet: func(bucket, key []byte) ([]byte, error) {
					return b, nil
				},
				MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
					assert.Equals(t, bucket, accountTable)
					assert.Equals(t, key, []byte(acc.ID))
					return nil, true, nil
				},
			}, "ca.smallstep.com", "acme", nil)
			return test{
				auth: auth,
				id:   acc.ID,
				acc:  clone,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acmeAcc, err := tc.auth.DeactivateAccount(tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					gotb, err := json.Marshal(acmeAcc)
					assert.FatalError(t, err)

					acmeExp, err := tc.acc.toACME(nil, tc.auth.dir)
					assert.FatalError(t, err)
					expb, err := json.Marshal(acmeExp)
					assert.FatalError(t, err)

					assert.Equals(t, expb, gotb)
				}
			}
		})
	}
}
