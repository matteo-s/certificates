package api

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
)

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

// NewOrder ACME api for creating a new order.
func (h *Handler) NewOrder(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		api.WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}

	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		api.WriteError(w, acme.ServerInternalErr(errors.Errorf("payload expected in request context")))
		return
	}
	var nor NewOrderRequest
	if err := json.Unmarshal(payload.value, &nor); err != nil {
		api.WriteError(w, acme.MalformedErr(errors.Wrap(err,
			"failed to unmarshal new-order request payload")))
		return
	}
	if err := nor.Validate(); err != nil {
		api.WriteError(w, err)
		return
	}

	order, err := h.Auth.NewOrder(acme.OrderOptions{
		AccountID:   acc.GetID(),
		Identifiers: nor.Identifiers,
		NotBefore:   nor.NotBefore,
		NotAfter:    nor.NotAfter,
	})
	if err != nil {
		api.WriteError(w, err)
		return
	}

	w.Header().Set("Location", h.Auth.GetLink(acme.OrderLink, true, order.GetID()))
	w.WriteHeader(http.StatusCreated)
	api.JSON(w, order)
	return
}

// GetOrder ACME api for retrieving an order.
func (h *Handler) GetOrder(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		api.WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}
	oid := chi.URLParam(r, "ordID")
	order, err := h.Auth.GetOrder(acc.GetID(), oid)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	w.Header().Set("Location", h.Auth.GetLink(acme.OrderLink, true, order.GetID()))
	w.WriteHeader(http.StatusOK)
	api.JSON(w, order)
	return
}

// FinalizeOrder attemptst to finalize an order and create a certificate.
func (h *Handler) FinalizeOrder(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		api.WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}
	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		api.WriteError(w, acme.ServerInternalErr(errors.Errorf("payload expected in request context")))
		return
	}
	var fr FinalizeRequest
	if err := json.Unmarshal(payload.value, &fr); err != nil {
		api.WriteError(w, acme.MalformedErr(errors.Wrap(err, "failed to unmarshal finalize-order request payload")))
		return
	}
	if err := fr.Validate(); err != nil {
		api.WriteError(w, err)
		return
	}

	oid := chi.URLParam(r, "ordID")
	o, err := h.Auth.FinalizeOrder(acc.GetID(), oid, fr.csr)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	w.Header().Set("Location", h.Auth.GetLink(acme.OrderLink, true, o.ID))
	w.WriteHeader(http.StatusOK)
	api.JSON(w, o)
	return
}
