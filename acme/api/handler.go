package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
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

// New returns a new ACME API router.
func New(acmeAuth acme.Interface) api.RouterHandler {
	return &Handler{acmeAuth}
}

// Handler is the ACME request handler.
type Handler struct {
	Auth acme.Interface
}

// Route traffic and implement the Router interface.
func (h *Handler) Route(r api.Router) {
	getLink := h.Auth.GetLink
	// Standard ACME API
	r.MethodFunc("GET", getLink(acme.NewNonceLink, false), h.addNonce(h.GetNonce))
	r.MethodFunc("GET", getLink(acme.DirectoryLink, false), h.addNonce(h.GetDirectory))

	extractPayloadByJWK := func(next nextHTTP) nextHTTP {
		return h.addNonce(h.addDirectory(h.verifyContentType(h.parseJWS(h.validateJWS(h.extractJWK(h.verifyAndExtractJWSPayload(next)))))))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return h.addNonce(h.addDirectory(h.verifyContentType(h.parseJWS(h.validateJWS(h.lookupJWK(h.verifyAndExtractJWSPayload(next)))))))
	}

	r.MethodFunc("POST", getLink(acme.NewAccountLink, false), extractPayloadByJWK(h.NewAccount))
	r.MethodFunc("POST", getLink(acme.AccountLink, false, "{accID}"), extractPayloadByKid(h.isPostAsGet(h.GetUpdateAccount)))
	r.MethodFunc("POST", getLink(acme.NewOrderLink, false), extractPayloadByKid(h.NewOrder))
	r.MethodFunc("POST", getLink(acme.OrderLink, false, "{ordID}"), extractPayloadByKid(h.isPostAsGet(h.GetOrder)))
	r.MethodFunc("POST", getLink(acme.OrdersByAccountLink, false, "{accID}"), extractPayloadByKid(h.isPostAsGet(h.GetOrdersByAccount)))
	r.MethodFunc("POST", getLink(acme.FinalizeLink, false, "{ordID}"), extractPayloadByKid(h.FinalizeOrder))
	r.MethodFunc("POST", getLink(acme.AuthzLink, false, "{authzID}"), extractPayloadByKid(h.isPostAsGet(h.GetAuthz)))
	r.MethodFunc("POST", getLink(acme.ChallengeLink, false, "{chID}"), extractPayloadByKid(h.GetChallenge))
	r.MethodFunc("POST", getLink(acme.CertificateLink, false, "{certID}"), extractPayloadByKid(h.isPostAsGet(h.GetCertificate)))
}

// GetNonce just sets the right header since a Nonce is added to each response
// by middleware by default.
func (h *Handler) GetNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method == "HEAD" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusNoContent)
	}
	return
}

// GetDirectory is the ACME resource for returning an directory configuration
// for client configuration.
func (h *Handler) GetDirectory(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	api.JSON(w, h.Auth.GetDirectory())
}

// GetAuthz ACME api for retrieving an Authz.
func (h *Handler) GetAuthz(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		// Account does not exist //
		api.WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}
	authz, err := h.Auth.GetAuthz(acc.GetID(), chi.URLParam(r, "authzID"))
	if err != nil {
		api.WriteError(w, err)
		return
	}

	w.Header().Set("Location", h.Auth.GetLink(acme.AuthzLink, true, authz.GetID()))
	w.WriteHeader(http.StatusOK)
	api.JSON(w, authz)
	return
}

// GetChallenge ACME api for retrieving a Challenge.
func (h *Handler) GetChallenge(w http.ResponseWriter, r *http.Request) {
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
	if !(payload.isPostAsGet || payload.isEmptyJSON) {
		api.WriteError(w, acme.MalformedErr(errors.Errorf("payload must be either post-as-get or empty JSON blob")))
		return
	}

	// If empty JSON payload then attempt to validate the challenge.
	var (
		err  error
		ch   *acme.Challenge
		chID = chi.URLParam(r, "chID")
	)
	if payload.isEmptyJSON {
		ch, err = h.Auth.ValidateChallenge(acc.GetID(), chID, acc.GetKey())
	} else {
		ch, err = h.Auth.GetChallenge(acc.GetID(), chID)
	}
	if err != nil {
		api.WriteError(w, err)
		return
	}

	getLink := h.Auth.GetLink
	w.Header().Add("Link", link(getLink(acme.AuthzLink, true, ch.GetAuthzID()), "up"))
	w.Header().Set("Location", getLink(acme.ChallengeLink, true, ch.GetID()))
	w.WriteHeader(http.StatusOK)
	api.JSON(w, ch)
	return
}

// GetCertificate ACME api for retrieving a Certificate.
func (h *Handler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		api.WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}
	certID := chi.URLParam(r, "certID")
	certBytes, err := h.Auth.GetCertificate(acc.GetID(), certID)
	if err != nil {
		api.WriteError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/pem-certificate-chain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(certBytes)
	return
}
