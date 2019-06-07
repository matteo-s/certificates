package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/cli/jose"
)

func link(url, typ string) string {
	return fmt.Sprintf("<%s>;\"%s\"", url, typ)
}

type contextKey string

const (
	jwsContextKey     = contextKey("jws")
	jwkContextKey     = contextKey("jwk")
	payloadContextKey = contextKey("payload")
	accContextKey     = contextKey("acc")
)

// NewAccountRequest represents the payload for a new account request.
type NewAccountRequest struct {
	Contact            []string
	OnlyReturnExisting bool
}

// Validate validates a new-account request body.
func (n *NewAccountRequest) Validate() error {
	if n.Contact != nil {
		// TODO: Check contacts.
	}
	return nil
}

// UpdateAccountRequest represents an update-account request.
type UpdateAccountRequest struct {
	Contact []string
	Status  string
}

// IsDeactivateRequest returns true if the update request is a deactivation
// request, false otherwise.
func (u *UpdateAccountRequest) IsDeactivateRequest() bool {
	return u.Contact == nil && u.Status == "deactivated"
}

// Validate validates a update-account request body.
func (u *UpdateAccountRequest) Validate() error {
	// Regular update //
	switch {
	case u.Contact != nil:
		// TODO: Check contacts.
		return nil
	case len(u.Status) > 0:
		if u.Status != "deactivated" {
			return acme.MalformedErr(errors.Errorf("cannot update account "+
				"status to %s, only deactivated", u.Status))
		}
		return nil
	default:
		return acme.MalformedErr(errors.Errorf("empty update request"))
	}
}

// NewOrderRequest represents the body for a NewOrder request.
type NewOrderRequest struct {
	Identifiers []acme.Identifier `json:"identifiers"`
	NotBefore   time.Time         `json:"notBefore"`
	NotAfter    time.Time         `json:"notAfter"`
}

// Validate validates a new-order request body.
func (n *NewOrderRequest) Validate() error {
	if len(n.Identifiers) == 0 {
		return acme.MalformedErr(errors.Errorf("identifiers list cannot be empty"))
	}
	for _, id := range n.Identifiers {
		if id.Type != "dns" {
			return acme.MalformedErr(errors.Errorf("identifier type unsupported: %s", id.Type))
		}
	}
	now := time.Now().UTC()
	if n.NotBefore.IsZero() {
		n.NotBefore = now
	}
	if n.NotAfter.IsZero() {
		n.NotAfter = now.Add(time.Hour * 24)
	}
	if now.After(n.NotAfter) {
		return acme.MalformedErr(errors.Errorf("NotAfter is already in the past: %s",
			n.NotAfter))
	}
	if n.NotBefore.After(n.NotAfter) {
		return acme.MalformedErr(errors.Errorf("NotAfter is before NotBefore "+
			"- NotBefore: %s, NotAfter: %s", n.NotBefore, n.NotAfter))
	}
	return nil
}

// FinalizeRequest captures the body for a Finalize order request.
type FinalizeRequest struct {
	CSR string
	csr *x509.CertificateRequest
}

// Validate validates a finalize request body.
func (f *FinalizeRequest) Validate() error {
	var err error
	csrBytes, err := base64.RawURLEncoding.DecodeString(f.CSR)
	if err != nil {
		return acme.MalformedErr(errors.Wrap(err, "error base64url decoding csr"))
	}
	f.csr, err = x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return acme.MalformedErr(errors.Wrap(err, "unable to parse csr"))
	}
	return nil
}

type payloadInfo struct {
	value       []byte
	isPostAsGet bool
	isEmptyJSON bool
}

func payloadFromContext(r *http.Request) (val *payloadInfo, ok bool) {
	val, ok = r.Context().Value(payloadContextKey).(*payloadInfo)
	return
}
func accountFromContext(r *http.Request) (val *acme.Account, ok bool) {
	val, ok = r.Context().Value(accContextKey).(*acme.Account)
	return
}
func jwkFromContext(r *http.Request) (val *jose.JSONWebKey, ok bool) {
	val, ok = r.Context().Value(jwkContextKey).(*jose.JSONWebKey)
	return
}
func jwsFromContext(r *http.Request) (val *jose.JSONWebSignature, ok bool) {
	val, ok = r.Context().Value(jwsContextKey).(*jose.JSONWebSignature)
	return
}

// GetNonce just sets the right header since a Nonce is added to each response
// by middleware by default.
func (h *caHandler) GetNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
	return
}

func (h *caHandler) GetDirectory(w http.ResponseWriter, r *http.Request) {
	JSON(w, h.Authority.GetDirectory())
	w.WriteHeader(http.StatusOK)
}

func (h *caHandler) NewAccount(w http.ResponseWriter, r *http.Request) {
	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, acme.ServerInternalErr(errors.Errorf("payload expected in request context")))
		return
	}
	var nar NewAccountRequest
	if err := json.Unmarshal(payload.value, &nar); err != nil {
		WriteError(w, acme.MalformedErr(errors.Wrap(err,
			"failed to unmarshal new-account request payload")))
		return
	}
	if err := nar.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	acc, ok := accountFromContext(r)
	httpStatus := http.StatusCreated
	if !ok {
		// Account does not exist //
		if nar.OnlyReturnExisting {
			WriteError(w, acme.AccountDoesNotExistErr(nil))
			return
		}
		jwk, ok := jwkFromContext(r)
		if !ok || jwk == nil {
			WriteError(w, acme.ServerInternalErr(errors.Errorf("jwk expected in request context")))
			return
		}

		var err error
		if acc, err = h.Authority.NewAccount(acme.AccountOptions{
			Key:     jwk,
			Contact: nar.Contact,
		}); err != nil {
			WriteError(w, err)
			return
		}
	} else {
		// Account exists //
		httpStatus = http.StatusOK
	}

	w.Header().Set("Location", h.Authority.GetLink(acme.AccountLink, true, acc.GetID()))
	JSON(w, acc)
	w.WriteHeader(httpStatus)
	return
}

// UpdateAccount is the api for updating an ACME account.
func (h *caHandler) UpdateAccount(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}
	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, acme.ServerInternalErr(errors.Errorf("payload expected in request context")))
		return
	}

	if !payload.isPostAsGet {
		var uar UpdateAccountRequest
		if err := json.Unmarshal(payload.value, &uar); err != nil {
			WriteError(w, acme.MalformedErr(errors.Wrap(err, "failed to unmarshal new-account request payload")))
			return
		}
		if err := uar.Validate(); err != nil {
			WriteError(w, err)
			return
		}
		var err error
		if uar.IsDeactivateRequest() {
			acc, err = h.Authority.DeactivateAccount(acc.GetID())
		} else {
			acc, err = h.Authority.UpdateAccount(acc.GetID(), uar.Contact)
		}
		if err != nil {
			WriteError(w, err)
			return
		}

	}
	w.WriteHeader(http.StatusOK)
	JSON(w, acc)
	return
}

// NewOrder ACME api for creating a new order.
func (h *caHandler) NewOrder(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}

	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, acme.ServerInternalErr(errors.Errorf("payload expected in request context")))
		return
	}
	var nor NewOrderRequest
	if err := json.Unmarshal(payload.value, &nor); err != nil {
		WriteError(w, acme.MalformedErr(errors.Wrap(err,
			"failed to unmarshal new-account request payload")))
		return
	}
	if err := nor.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	order, err := h.Authority.NewOrder(acme.OrderOptions{
		AccountID:   acc.GetID(),
		Identifiers: nor.Identifiers,
		NotBefore:   nor.NotBefore,
		NotAfter:    nor.NotAfter,
	})
	if err != nil {
		WriteError(w, err)
		return
	}

	w.Header().Set("Location", h.Authority.GetLink(acme.OrderLink, true, order.GetID()))
	JSON(w, order)
	w.WriteHeader(http.StatusCreated)
	return
}

// GetOrder ACME api for retrieving an order.
func (h *caHandler) GetOrder(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}
	oid := chi.URLParam(r, "ordID")
	order, err := h.Authority.GetOrder(acc.GetID(), oid)
	if err != nil {
		WriteError(w, err)
		return
	}

	w.Header().Set("Location", h.Authority.GetLink(acme.OrderLink, true, order.GetID()))
	JSON(w, order)
	w.WriteHeader(http.StatusOK)
	return
}

// GetOrdersByAccount ACME api for retrieving the list of order urls belonging to an account.
func (h *caHandler) GetOrdersByAccount(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}

	orders, err := h.Authority.GetOrdersByAccount(acc.GetID())
	if err != nil {
		WriteError(w, err)
		return
	}
	JSON(w, orders)
	w.WriteHeader(http.StatusOK)
	return
}

// FinalizeOrder attemptst to finalize an order and create a certificate.
func (h *caHandler) FinalizeOrder(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}
	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, acme.ServerInternalErr(errors.Errorf("payload not in request context")))
		return
	}
	var fr FinalizeRequest
	if err := json.Unmarshal(payload.value, &fr); err != nil {
		WriteError(w, acme.MalformedErr(errors.Wrap(err, "unable to parse body of finalize request")))
		return
	}
	if err := fr.Validate(); err != nil {
		WriteError(w, err)
		return
	}

	oid := chi.URLParam(r, "ordID")
	order, err := h.Authority.FinalizeOrder(acc.GetID(), oid, fr.csr)
	if err != nil {
		WriteError(w, err)
		return
	}

	w.Header().Set("Location", h.Authority.GetLink(acme.AccountLink, true, acc.GetID()))
	JSON(w, order)
	w.WriteHeader(http.StatusOK)
	return
}

// GetAuthz ACME api for retrieving an Authz.
func (h *caHandler) GetAuthz(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		WriteError(w, acme.AccountDoesNotExistErr(errors.Errorf("account not found")))
		return
	}
	authz, err := h.Authority.GetAuthz(acc.GetID(), chi.URLParam(r, "authzID"))
	if err != nil {
		WriteError(w, err)
		return
	}

	JSON(w, authz)
	w.Header().Set("Location", h.Authority.GetLink(acme.AuthzLink, true, authz.GetID()))
	w.WriteHeader(http.StatusOK)
	return
}

// GetChallenge ACME api for retrieving a Challenge.
func (h *caHandler) GetChallenge(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		WriteError(w, acme.AccountDoesNotExistErr(errors.Errorf("account not found")))
		return
	}
	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		WriteError(w, acme.ServerInternalErr(errors.Errorf("payload expected in request context")))
		return
	}
	if !(payload.isPostAsGet || payload.isEmptyJSON) {
		WriteError(w, acme.MalformedErr(errors.Errorf("payload must be either post-as-get or empty JSON blob")))
		return
	}

	// If empty JSON payload then attempt to validate the challenge.
	var (
		err  error
		ch   *acme.Challenge
		chID = chi.URLParam(r, "chID")
	)
	if payload.isEmptyJSON {
		ch, err = h.Authority.ValidateChallenge(acc.GetID(), chID, acc.GetKey())
	} else {
		ch, err = h.Authority.GetChallenge(acc.GetID(), chID)
	}
	if err != nil {
		WriteError(w, err)
		return
	}

	getLink := h.Authority.GetLink
	w.Header().Set("Link", link(getLink(acme.AuthzLink, true, ch.GetAuthzID()), "up"))
	w.Header().Set("Location", getLink(acme.ChallengeLink, true, ch.GetID()))
	JSON(w, ch)
	w.WriteHeader(http.StatusOK)
	return
}

// GetCertificate ACME api for retrieving a Certificate.
func (h *caHandler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}
	certID := chi.URLParam(r, "certID")
	certBytes, err := h.Authority.GetCertificate(acc.GetID(), certID)
	if err != nil {
		WriteError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain; charset=utf-8")
	w.Write(certBytes)
	w.WriteHeader(http.StatusOK)
	return
}
