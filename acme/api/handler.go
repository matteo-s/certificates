package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/logging"
	"github.com/smallstep/cli/jose"
)

func link(url, typ string) string {
	return fmt.Sprintf("<%s>;rel=\"%s\"", url, typ)
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
	r.MethodFunc("HEAD", getLink(acme.NewNonceLink, false), h.addNonce(h.GetNonce))
	r.MethodFunc("GET", getLink(acme.DirectoryLink, false), h.addNonce(h.GetDirectory))
	r.MethodFunc("HEAD", getLink(acme.DirectoryLink, false), h.addNonce(h.GetDirectory))

	extractPayloadByJWK := func(next nextHTTP) nextHTTP {
		return h.addNonce(h.addDirLink(h.verifyContentType(h.parseJWS(h.validateJWS(h.extractJWK(h.verifyAndExtractJWSPayload(next)))))))
	}
	extractPayloadByKid := func(next nextHTTP) nextHTTP {
		return h.addNonce(h.addDirLink(h.verifyContentType(h.parseJWS(h.validateJWS(h.lookupJWK(h.verifyAndExtractJWSPayload(next)))))))
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

func logDirectory(w http.ResponseWriter, dir *acme.Directory) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		m := map[string]interface{}{
			"keyChange":  dir.KeyChange,
			"newAccount": dir.NewAccount,
			"newAuthz":   dir.NewAuthz,
			"newNonce":   dir.NewNonce,
			"newOrder":   dir.NewOrder,
			"revokeCert": dir.RevokeCert,
		}
		rl.WithFields(m)
	}
}

// GetDirectory is the ACME resource for returning a directory configuration
// for client configuration.
func (h *Handler) GetDirectory(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	dir := h.Auth.GetDirectory()
	api.JSON(w, dir)
	logDirectory(w, dir)
	return
}

func logAuthz(w http.ResponseWriter, az *acme.Authz) {
	chs, _ := json.Marshal(az.Challenges)
	if rl, ok := w.(logging.ResponseLogger); ok {
		m := map[string]interface{}{
			"azIdentifier": az.Identifier,
			"azStatus":     az.Status,
			"azExpires":    az.Expires,
			"azChallenges": string(chs),
			"azWildcard":   az.Wildcard,
		}
		rl.WithFields(m)
	}
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
	logAuthz(w, authz)
	return
}

func logChallenge(w http.ResponseWriter, ch *acme.Challenge) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		m := map[string]interface{}{
			"chType":      ch.Type,
			"chStatus":    ch.Status,
			"chToken":     ch.Token,
			"chValidated": ch.Validated,
			"chURL":       ch.URL,
			"chError":     ch.Error,
		}
		rl.WithFields(m)
	}
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

	// NOTE: We should be checking that the request is either a POST-as-GET, or
	// that the payload is an empty JSON block ({}). However, older ACME clients
	// still send a vestigial body (rather than an empty JSON block) and
	// strict enforcement would render these clients broken. For the time being
	// we'll just ignore the body.

	var (
		err  error
		ch   *acme.Challenge
		chID = chi.URLParam(r, "chID")
	)
	if payload.isPostAsGet {
		ch, err = h.Auth.GetChallenge(acc.GetID(), chID)
	} else {
		ch, err = h.Auth.ValidateChallenge(acc.GetID(), chID, acc.GetKey())
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
	logChallenge(w, ch)
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
