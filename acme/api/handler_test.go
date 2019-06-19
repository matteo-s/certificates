package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/jose"
)

type mockAcmeAuthority struct {
	deactivateAccount  func(string) (*acme.Account, error)
	finalizeOrder      func(accID string, id string, csr *x509.CertificateRequest) (*acme.Order, error)
	getAccount         func(id string) (*acme.Account, error)
	getAccountByKeyID  func(id string) (*acme.Account, error)
	getAuthz           func(accID string, id string) (*acme.Authz, error)
	getCertificate     func(accID string, id string) ([]byte, error)
	getChallenge       func(accID string, id string) (*acme.Challenge, error)
	getDirectory       func() *acme.Directory
	getLink            func(acme.Link, bool, ...string) string
	getOrder           func(accID string, id string) (*acme.Order, error)
	getOrdersByAccount func(id string) ([]string, error)
	newAccount         func(acme.AccountOptions) (*acme.Account, error)
	newNonce           func() (string, error)
	newOrder           func(acme.OrderOptions) (*acme.Order, error)
	updateAccount      func(string, []string) (*acme.Account, error)
	useNonce           func(string) error
	validateChallenge  func(accID string, id string, jwk *jose.JSONWebKey) (*acme.Challenge, error)
	ret1               interface{}
	err                error
}

func (m *mockAcmeAuthority) DeactivateAccount(id string) (*acme.Account, error) {
	if m.deactivateAccount != nil {
		return m.deactivateAccount(id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) FinalizeOrder(accID, id string, csr *x509.CertificateRequest) (*acme.Order, error) {
	if m.finalizeOrder != nil {
		return m.finalizeOrder(accID, id, csr)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Order), m.err
}

func (m *mockAcmeAuthority) GetAccount(id string) (*acme.Account, error) {
	if m.getAccount != nil {
		return m.getAccount(id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) GetAccountByKeyID(id string) (*acme.Account, error) {
	if m.getAccountByKeyID != nil {
		return m.getAccountByKeyID(id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) GetAuthz(accID, id string) (*acme.Authz, error) {
	if m.getAuthz != nil {
		return m.getAuthz(accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Authz), m.err
}

func (m *mockAcmeAuthority) GetCertificate(accID, id string) ([]byte, error) {
	if m.getCertificate != nil {
		return m.getCertificate(accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.([]byte), m.err
}

func (m *mockAcmeAuthority) GetChallenge(accID, id string) (*acme.Challenge, error) {
	if m.getChallenge != nil {
		return m.getChallenge(accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Challenge), m.err
}

func (m *mockAcmeAuthority) GetDirectory() *acme.Directory {
	if m.getDirectory != nil {
		return m.getDirectory()
	}
	return m.ret1.(*acme.Directory)
}

func (m *mockAcmeAuthority) GetLink(typ acme.Link, abs bool, in ...string) string {
	if m.getLink != nil {
		return m.getLink(typ, abs, in...)
	}
	return m.ret1.(string)
}

func (m *mockAcmeAuthority) GetOrder(accID, id string) (*acme.Order, error) {
	if m.getOrder != nil {
		return m.getOrder(accID, id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Order), m.err
}

func (m *mockAcmeAuthority) GetOrdersByAccount(id string) ([]string, error) {
	if m.getOrdersByAccount != nil {
		return m.getOrdersByAccount(id)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.([]string), m.err
}

func (m *mockAcmeAuthority) NewAccount(ops acme.AccountOptions) (*acme.Account, error) {
	if m.newAccount != nil {
		return m.newAccount(ops)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) NewNonce() (string, error) {
	if m.newNonce != nil {
		return m.newNonce()
	} else if m.err != nil {
		return "", m.err
	}
	return m.ret1.(string), m.err
}

func (m *mockAcmeAuthority) NewOrder(ops acme.OrderOptions) (*acme.Order, error) {
	if m.newOrder != nil {
		return m.newOrder(ops)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Order), m.err
}

func (m *mockAcmeAuthority) UpdateAccount(id string, contact []string) (*acme.Account, error) {
	if m.updateAccount != nil {
		return m.updateAccount(id, contact)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Account), m.err
}

func (m *mockAcmeAuthority) UseNonce(nonce string) error {
	if m.useNonce != nil {
		return m.useNonce(nonce)
	}
	return m.err
}

func (m *mockAcmeAuthority) ValidateChallenge(accID string, id string, jwk *jose.JSONWebKey) (*acme.Challenge, error) {
	if m.validateChallenge != nil {
		return m.validateChallenge(accID, id, jwk)
	} else if m.err != nil {
		return nil, m.err
	}
	return m.ret1.(*acme.Challenge), m.err
}

func TestHandlerGetNonce(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"GET", 204},
		{"HEAD", 200},
	}

	// Request with chi context
	req := httptest.NewRequest("GET", "http://ca.smallstep.com/nonce", nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(nil).(*Handler)
			w := httptest.NewRecorder()
			req.Method = tt.name
			h.GetNonce(w, req)
			res := w.Result()

			if res.StatusCode != tt.statusCode {
				t.Errorf("Handler.GetNonce StatusCode = %d, wants %d", res.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestHandlerGetDirectory(t *testing.T) {
	// Request with chi context
	req := httptest.NewRequest("GET", "http://ca.smallstep.com/directory", nil)
	auth := acme.NewAuthority(nil, "ca.smallstep.com", "acme", nil)
	h := New(auth).(*Handler)
	w := httptest.NewRecorder()

	h.GetDirectory(w, req)
	res := w.Result()

	assert.Equals(t, res.StatusCode, 200)

	body, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	assert.FatalError(t, err)

	expDir := acme.Directory{
		NewNonce:   "https://ca.smallstep.com/acme/new-nonce",
		NewAccount: "https://ca.smallstep.com/acme/new-account",
		NewOrder:   "https://ca.smallstep.com/acme/new-order",
		RevokeCert: "https://ca.smallstep.com/acme/revoke-cert",
		KeyChange:  "https://ca.smallstep.com/acme/key-change",
	}

	var dir acme.Directory
	json.Unmarshal(bytes.TrimSpace(body), &dir)
	assert.Equals(t, dir, expDir)
}

func TestHandlerGetAuthz(t *testing.T) {
	expiry := time.Now().UTC().Add(6 * time.Hour).Round(time.Second)
	az := acme.Authz{
		ID: "authzID",
		Identifier: acme.Identifier{
			Type:  "dns",
			Value: "example.com",
		},
		Status:   "pending",
		Expires:  expiry.Format(time.RFC3339),
		Wildcard: false,
		Challenges: []*acme.Challenge{
			&acme.Challenge{
				Type:    "http-01",
				Status:  "pending",
				Token:   "tok2",
				URL:     "https://ca.smallstep.com/acme/challenge/chHTTPID",
				ID:      "chHTTP01ID",
				AuthzID: "authzID",
			},
			&acme.Challenge{
				Type:    "dns-01",
				Status:  "pending",
				Token:   "tok2",
				URL:     "https://ca.smallstep.com/acme/challenge/chDNSID",
				ID:      "chDNSID",
				AuthzID: "authzID",
			},
		},
	}

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("authzID", az.ID)
	url := fmt.Sprintf("http://ca.smallstep.com/acme/challenge/%s", az.ID)

	type test struct {
		auth       acme.Interface
		ctx        context.Context
		statusCode int
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        context.Background(),
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, nil)
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        ctx,
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/getAuthz-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					err: acme.ServerInternalErr(errors.New("force")),
				},
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("force")),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					getAuthz: func(accID, id string) (*acme.Authz, error) {
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, az.ID)
						return &az, nil
					},
					getLink: func(typ acme.Link, abs bool, in ...string) string {
						assert.Equals(t, typ, acme.AuthzLink)
						assert.True(t, abs)
						assert.Equals(t, in, []string{az.ID})
						return url
					},
				},
				ctx:        ctx,
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := New(tc.auth).(*Handler)
			req := httptest.NewRequest("GET", url, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.GetAuthz(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.problem) {
				b, err := json.Marshal(tc.problem)
				assert.FatalError(t, err)
				//var problem *acme.Error
				//assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &problem))
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
				assert.Equals(t, bytes.TrimSpace(body), b)
			} else {
				//var gotAz acme.Authz
				//assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &gotAz))
				expB, err := json.Marshal(az)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Location"], []string{url})
			}
		})
	}
}

func TestHandlerGetCertificate(t *testing.T) {
	leaf, err := pemutil.ReadCertificate("../../authority/testdata/certs/foo.crt")
	assert.FatalError(t, err)
	inter, err := pemutil.ReadCertificate("../../authority/testdata/certs/intermediate_ca.crt")
	assert.FatalError(t, err)
	root, err := pemutil.ReadCertificate("../../authority/testdata/certs/root_ca.crt")
	assert.FatalError(t, err)

	certBytes := append(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leaf.Raw,
	}), pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: inter.Raw,
	})...)
	certBytes = append(certBytes, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root.Raw,
	})...)
	certID := "certID"

	// Request with chi context
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("certID", certID)
	url := fmt.Sprintf("http://ca.smallstep.com/acme/certificate/%s", certID)

	type test struct {
		auth       acme.Interface
		ctx        context.Context
		statusCode int
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        context.Background(),
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, nil)
			return test{
				auth:       &mockAcmeAuthority{},
				ctx:        ctx,
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/getCertificate-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					err: acme.ServerInternalErr(errors.New("force")),
				},
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("force")),
			}
		},
		"ok": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					getCertificate: func(accID, id string) ([]byte, error) {
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, certID)
						return certBytes, nil
					},
				},
				ctx:        ctx,
				statusCode: 200,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := New(tc.auth).(*Handler)
			req := httptest.NewRequest("GET", url, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.GetCertificate(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.problem) {
				b, err := json.Marshal(tc.problem)
				assert.FatalError(t, err)
				//var problem *acme.Error
				//assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &problem))
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
				assert.Equals(t, bytes.TrimSpace(body), b)
			} else {
				//var gotAz acme.Authz
				//assert.FatalError(t, json.Unmarshal(bytes.TrimSpace(body), &gotAz))
				assert.Equals(t, bytes.TrimSpace(body), bytes.TrimSpace(certBytes))
				assert.Equals(t, res.Header["Content-Type"], []string{"application/pem-certificate-chain; charset=utf-8"})
			}
		})
	}
}

func ch() acme.Challenge {
	return acme.Challenge{
		Type:    "http-01",
		Status:  "pending",
		Token:   "tok2",
		URL:     "https://ca.smallstep.com/acme/challenge/chID",
		ID:      "chID",
		AuthzID: "authzID",
	}
}

func TestHandlerGetChallenge(t *testing.T) {
	chiCtx := chi.NewRouteContext()
	chiCtx.URLParams.Add("chID", "chID")
	url := fmt.Sprintf("http://ca.smallstep.com/acme/challenge/%s", "chID")

	type test struct {
		auth       acme.Interface
		ctx        context.Context
		statusCode int
		ch         acme.Challenge
		problem    *acme.Error
	}
	var tests = map[string]func(t *testing.T) test{
		"fail/no-account": func(t *testing.T) test {
			return test{
				ctx:        context.Background(),
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/nil-account": func(t *testing.T) test {
			ctx := context.WithValue(context.Background(), accContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 404,
				problem:    acme.AccountDoesNotExistErr(nil),
			}
		},
		"fail/no-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			return test{
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("payload expected in request context")),
			}
		},
		"fail/nil-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, nil)
			return test{
				ctx:        ctx,
				statusCode: 500,
				problem:    acme.ServerInternalErr(errors.New("payload expected in request context")),
			}
		},
		"fail/malformed-payload": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{})
			return test{
				ctx:        ctx,
				statusCode: 400,
				problem:    acme.MalformedErr(errors.Errorf("payload must be either post-as-get or empty JSON blob")),
			}
		},
		"fail/validate-challenge-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{isEmptyJSON: true})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					err: acme.UnauthorizedErr(nil),
				},
				ctx:        ctx,
				statusCode: 401,
				problem:    acme.UnauthorizedErr(nil),
			}
		},
		"fail/get-challenge-error": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{isPostAsGet: true})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			return test{
				auth: &mockAcmeAuthority{
					err: acme.UnauthorizedErr(nil),
				},
				ctx:        ctx,
				statusCode: 401,
				problem:    acme.UnauthorizedErr(nil),
			}
		},
		"ok/validate-challenge": func(t *testing.T) test {
			key, err := jose.GenerateJWK("EC", "P-256", "ES256", "sig", "", 0)
			assert.FatalError(t, err)
			acc := &acme.Account{ID: "accID", Key: key}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{isEmptyJSON: true})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			ch := ch()
			ch.Status = "valid"
			ch.Validated = time.Now().UTC().Round(time.Second).Format(time.RFC3339)
			count := 0
			return test{
				auth: &mockAcmeAuthority{
					validateChallenge: func(accID, id string, jwk *jose.JSONWebKey) (*acme.Challenge, error) {
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, ch.ID)
						assert.Equals(t, jwk.KeyID, key.KeyID)
						return &ch, nil
					},
					getLink: func(typ acme.Link, abs bool, in ...string) string {
						var ret string
						switch count {
						case 0:
							assert.Equals(t, typ, acme.AuthzLink)
							assert.True(t, abs)
							assert.Equals(t, in, []string{ch.AuthzID})
							ret = fmt.Sprintf("https://ca.smallstep.com/acme/authz/%s", ch.AuthzID)
						case 1:
							assert.Equals(t, typ, acme.ChallengeLink)
							assert.True(t, abs)
							assert.Equals(t, in, []string{ch.ID})
							ret = url
						}
						count++
						return ret
					},
				},
				ctx:        ctx,
				statusCode: 200,
				ch:         ch,
			}
		},
		"ok/get-challenge": func(t *testing.T) test {
			acc := &acme.Account{ID: "accID"}
			ctx := context.WithValue(context.Background(), accContextKey, acc)
			ctx = context.WithValue(ctx, payloadContextKey, &payloadInfo{isPostAsGet: true})
			ctx = context.WithValue(ctx, chi.RouteCtxKey, chiCtx)
			ch := ch()
			count := 0
			return test{
				auth: &mockAcmeAuthority{
					getChallenge: func(accID, id string) (*acme.Challenge, error) {
						assert.Equals(t, accID, acc.ID)
						assert.Equals(t, id, ch.ID)
						return &ch, nil
					},
					getLink: func(typ acme.Link, abs bool, in ...string) string {
						var ret string
						switch count {
						case 0:
							assert.Equals(t, typ, acme.AuthzLink)
							assert.True(t, abs)
							assert.Equals(t, in, []string{ch.AuthzID})
							ret = fmt.Sprintf("https://ca.smallstep.com/acme/authz/%s", ch.AuthzID)
						case 1:
							assert.Equals(t, typ, acme.ChallengeLink)
							assert.True(t, abs)
							assert.Equals(t, in, []string{ch.ID})
							ret = url
						}
						count++
						return ret
					},
				},
				ctx:        ctx,
				statusCode: 200,
				ch:         ch,
			}
		},
	}
	for name, run := range tests {
		tc := run(t)
		t.Run(name, func(t *testing.T) {
			h := New(tc.auth).(*Handler)
			req := httptest.NewRequest("GET", url, nil)
			req = req.WithContext(tc.ctx)
			w := httptest.NewRecorder()
			h.GetChallenge(w, req)
			res := w.Result()

			assert.Equals(t, res.StatusCode, tc.statusCode)

			body, err := ioutil.ReadAll(res.Body)
			res.Body.Close()
			assert.FatalError(t, err)

			if res.StatusCode >= 400 && assert.NotNil(t, tc.problem) {
				b, err := json.Marshal(tc.problem)
				assert.FatalError(t, err)
				assert.Equals(t, res.Header["Content-Type"], []string{"application/problem+json"})
				assert.Equals(t, bytes.TrimSpace(body), b)
			} else {
				expB, err := json.Marshal(tc.ch)
				assert.FatalError(t, err)
				assert.Equals(t, bytes.TrimSpace(body), expB)
				assert.Equals(t, res.Header["Link"], []string{fmt.Sprintf("<https://ca.smallstep.com/acme/authz/%s>;\"up\"", tc.ch.AuthzID)})
				assert.Equals(t, res.Header["Location"], []string{url})
			}
		})
	}
}
