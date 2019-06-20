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
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

func newAcc() (*account, error) {
	jwk, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
	if err != nil {
		return nil, err
	}
	mockdb := &db.MockNoSQLDB{
		MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
			return nil, true, nil
		},
	}
	return newAccount(mockdb, AccountOptions{
		Key: jwk, Contact: []string{"foo", "bar"},
	})
}

func TestGetAccountByID(t *testing.T) {
	type test struct {
		id  string
		db  nosql.DB
		acc *account
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/not-found": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			return test{
				acc: acc,
				id:  acc.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, database.ErrNotFound
					},
				},
				err: MalformedErr(errors.Errorf("account %s not found: not found", acc.ID)),
			}
		},
		"fail/db-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			return test{
				acc: acc,
				id:  acc.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error loading account: force")),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			return test{
				acc: acc,
				id:  acc.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, key, []byte(acc.ID))
						return nil, nil
					},
				},
				err: ServerInternalErr(errors.New("error unmarshaling account: unexpected end of JSON input")),
			}
		},
		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)
			return test{
				acc: acc,
				id:  acc.ID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, key, []byte(acc.ID))
						return b, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acc, err := getAccountByID(tc.db, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.acc.ID, acc.ID)
					assert.Equals(t, tc.acc.Status, acc.Status)
					assert.Equals(t, tc.acc.Created, acc.Created)
					assert.Equals(t, tc.acc.Deactivated, acc.Deactivated)
					assert.Equals(t, tc.acc.Contact, acc.Contact)
					assert.Equals(t, tc.acc.Key.KeyID, acc.Key.KeyID)
				}
			}
		})
	}
}

func TestGetAccountByKeyID(t *testing.T) {
	type test struct {
		kid string
		db  nosql.DB
		acc *account
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/kid-not-found": func(t *testing.T) test {
			return test{
				kid: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, database.ErrNotFound
					},
				},
				err: MalformedErr(errors.Errorf("account with key id foo not found: not found")),
			}
		},
		"fail/db-error": func(t *testing.T) test {
			return test{
				kid: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error loading key-account index: force")),
			}
		},
		"fail/getAccount-error": func(t *testing.T) test {
			count := 0
			return test{
				kid: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						if count == 0 {
							assert.Equals(t, bucket, accountByKeyIDTable)
							assert.Equals(t, key, []byte("foo"))
							count++
							return []byte("bar"), nil
						}
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error loading account: force")),
			}
		},
		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)
			count := 0
			return test{
				kid: acc.Key.KeyID,
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						var ret []byte
						switch count {
						case 0:
							assert.Equals(t, bucket, accountByKeyIDTable)
							assert.Equals(t, key, []byte(acc.Key.KeyID))
							ret = []byte(acc.ID)
						case 1:
							assert.Equals(t, bucket, accountTable)
							assert.Equals(t, key, []byte(acc.ID))
							ret = b
						}
						count++
						return ret, nil
					},
				},
				acc: acc,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if acc, err := getAccountByKeyID(tc.db, tc.kid); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.acc.ID, acc.ID)
					assert.Equals(t, tc.acc.Status, acc.Status)
					assert.Equals(t, tc.acc.Created, acc.Created)
					assert.Equals(t, tc.acc.Deactivated, acc.Deactivated)
					assert.Equals(t, tc.acc.Contact, acc.Contact)
					assert.Equals(t, tc.acc.Key.KeyID, acc.Key.KeyID)
				}
			}
		})
	}
}

func TestGetAccountIDsByAccount(t *testing.T) {
	type test struct {
		id  string
		db  nosql.DB
		res []string
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"ok/not-found": func(t *testing.T) test {
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, database.ErrNotFound
					},
				},
				res: []string{},
			}
		},
		"fail/db-error": func(t *testing.T) test {
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						return nil, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error loading orderIDs for account foo: force")),
			}
		},
		"fail/unmarshal-error": func(t *testing.T) test {
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte("foo"))
						return nil, nil
					},
				},
				err: ServerInternalErr(errors.New("error unmarshaling orderIDs for account foo: unexpected end of JSON input")),
			}
		},
		"ok": func(t *testing.T) test {
			oids := []string{"foo", "bar", "baz"}
			b, err := json.Marshal(oids)
			assert.FatalError(t, err)
			return test{
				id: "foo",
				db: &db.MockNoSQLDB{
					MGet: func(bucket, key []byte) ([]byte, error) {
						assert.Equals(t, bucket, ordersByAccountIDTable)
						assert.Equals(t, key, []byte("foo"))
						return b, nil
					},
				},
				res: oids,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if oids, err := getOrderIDsByAccount(tc.db, tc.id); err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, tc.res, oids)
				}
			}
		})
	}
}

func TestAccountToACME(t *testing.T) {
	dir := newDirectory("ca.smallstep.com", "acme")

	type test struct {
		acc *account
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			return test{acc: acc}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			acmeAccount, err := tc.acc.toACME(nil, dir)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, acmeAccount.ID, tc.acc.ID)
					assert.Equals(t, acmeAccount.Status, tc.acc.Status)
					assert.Equals(t, acmeAccount.Contact, tc.acc.Contact)
					assert.Equals(t, acmeAccount.Key.KeyID, tc.acc.Key.KeyID)
					assert.Equals(t, acmeAccount.Orders, fmt.Sprintf("https://ca.smallstep.com/acme/account/%s/orders", tc.acc.ID))
				}
			}
		})
	}
}

func TestAccountSave(t *testing.T) {
	type test struct {
		acc, old *account
		db       nosql.DB
		err      *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/old-nil/swap-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			return test{
				acc: acc,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error storing account: force")),
			}
		},
		"fail/old-nil/swap-false": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			return test{
				acc: acc,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						return []byte("foo"), false, nil
					},
				},
				err: ServerInternalErr(errors.New("error storing account; value has changed since last read")),
			}
		},
		"ok/old-nil": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)
			return test{
				acc: acc,
				old: nil,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, nil)
						assert.Equals(t, b, newval)
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, []byte(acc.ID), key)
						return nil, true, nil
					},
				},
			}
		},
		"ok/old-not-nil": func(t *testing.T) test {
			oldAcc, err := newAcc()
			assert.FatalError(t, err)
			acc, err := newAcc()
			assert.FatalError(t, err)

			oldb, err := json.Marshal(oldAcc)
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)
			return test{
				acc: acc,
				old: oldAcc,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, old, oldb)
						assert.Equals(t, newval, b)
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, []byte(acc.ID), key)
						return []byte("foo"), true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.acc.save(tc.db, tc.old); err != nil {
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

func TestAccountSaveNew(t *testing.T) {
	type test struct {
		acc *account
		db  nosql.DB
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/swap-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			return test{
				acc: acc,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountByKeyIDTable)
						assert.Equals(t, key, []byte(acc.Key.KeyID))
						assert.Equals(t, old, nil)
						assert.Equals(t, newval, []byte(acc.ID))
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error setting key-id to account-id index: force")),
			}
		},
		"fail/swap-false": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			return test{
				acc: acc,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountByKeyIDTable)
						assert.Equals(t, key, []byte(acc.Key.KeyID))
						assert.Equals(t, old, nil)
						assert.Equals(t, newval, []byte(acc.ID))
						return nil, false, nil
					},
				},
				err: ServerInternalErr(errors.New("key-id to account-id index already exists")),
			}
		},
		"fail/save-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)
			count := 0
			return test{
				acc: acc,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 0 {
							assert.Equals(t, bucket, accountByKeyIDTable)
							assert.Equals(t, key, []byte(acc.Key.KeyID))
							assert.Equals(t, old, nil)
							assert.Equals(t, newval, []byte(acc.ID))
							count++
							return nil, true, nil
						}
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, key, []byte(acc.ID))
						assert.Equals(t, old, nil)
						assert.Equals(t, newval, b)
						return nil, false, errors.New("force")
					},
					MDel: func(bucket, key []byte) error {
						assert.Equals(t, bucket, accountByKeyIDTable)
						assert.Equals(t, key, []byte(acc.Key.KeyID))
						return nil
					},
				},
				err: ServerInternalErr(errors.New("error storing account: force")),
			}
		},
		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			b, err := json.Marshal(acc)
			assert.FatalError(t, err)
			count := 0
			return test{
				acc: acc,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						if count == 0 {
							assert.Equals(t, bucket, accountByKeyIDTable)
							assert.Equals(t, key, []byte(acc.Key.KeyID))
							assert.Equals(t, old, nil)
							assert.Equals(t, newval, []byte(acc.ID))
							count++
							return nil, true, nil
						}
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, key, []byte(acc.ID))
						assert.Equals(t, old, nil)
						assert.Equals(t, newval, b)
						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			if err := tc.acc.saveNew(tc.db); err != nil {
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

func TestAccountUpdate(t *testing.T) {
	type test struct {
		acc     *account
		contact []string
		db      nosql.DB
		res     []byte
		err     *Error
	}
	contact := []string{"foo", "bar"}
	tests := map[string]func(t *testing.T) test{
		"fail/save-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			oldb, err := json.Marshal(acc)
			assert.FatalError(t, err)

			_acc := *acc
			clone := &_acc
			clone.Contact = contact
			b, err := json.Marshal(clone)
			assert.FatalError(t, err)
			return test{
				acc:     acc,
				contact: contact,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, key, []byte(acc.ID))
						assert.Equals(t, old, oldb)
						assert.Equals(t, newval, b)
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error storing account: force")),
			}
		},
		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			oldb, err := json.Marshal(acc)
			assert.FatalError(t, err)

			_acc := *acc
			clone := &_acc
			clone.Contact = contact
			b, err := json.Marshal(clone)
			assert.FatalError(t, err)
			return test{
				acc:     acc,
				contact: contact,
				res:     b,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, key, []byte(acc.ID))
						assert.Equals(t, old, oldb)
						assert.Equals(t, newval, b)
						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			acc, err := tc.acc.update(tc.db, tc.contact)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					b, err := json.Marshal(acc)
					assert.FatalError(t, err)
					assert.Equals(t, b, tc.res)
				}
			}
		})
	}
}

func TestAccountDeactivate(t *testing.T) {
	type test struct {
		acc *account
		db  nosql.DB
		err *Error
	}
	tests := map[string]func(t *testing.T) test{
		"fail/save-error": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			oldb, err := json.Marshal(acc)
			assert.FatalError(t, err)

			return test{
				acc: acc,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, key, []byte(acc.ID))
						assert.Equals(t, old, oldb)
						return nil, false, errors.New("force")
					},
				},
				err: ServerInternalErr(errors.New("error storing account: force")),
			}
		},
		"ok": func(t *testing.T) test {
			acc, err := newAcc()
			assert.FatalError(t, err)
			oldb, err := json.Marshal(acc)
			assert.FatalError(t, err)

			return test{
				acc: acc,
				db: &db.MockNoSQLDB{
					MCmpAndSwap: func(bucket, key, old, newval []byte) ([]byte, bool, error) {
						assert.Equals(t, bucket, accountTable)
						assert.Equals(t, key, []byte(acc.ID))
						assert.Equals(t, old, oldb)
						return nil, true, nil
					},
				},
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run(t)
			acc, err := tc.acc.deactivate(tc.db)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					ae, ok := err.(*Error)
					assert.True(t, ok)
					assert.HasPrefix(t, ae.Error(), tc.err.Error())
					assert.Equals(t, ae.StatusCode(), tc.err.StatusCode())
					assert.Equals(t, ae.Type, tc.err.Type)
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.Equals(t, acc.ID, tc.acc.ID)
					assert.Equals(t, acc.Contact, tc.acc.Contact)
					assert.Equals(t, acc.Status, statusDeactivated)
					assert.Equals(t, acc.Key.KeyID, tc.acc.Key.KeyID)
					assert.Equals(t, acc.Created, tc.acc.Created)

					assert.True(t, acc.Deactivated.Before(time.Now().Add(time.Minute)))
					assert.True(t, acc.Deactivated.After(time.Now().Add(-time.Minute)))
				}
			}
		})
	}
}
