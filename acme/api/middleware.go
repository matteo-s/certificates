package api

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/cli/jose"
	"github.com/smallstep/nosql"
)

type nextHTTP = func(http.ResponseWriter, *http.Request)

// addNonce is a middleware that adds a nonce to the response header.
func (h *Handler) addNonce(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		nonce, err := h.Auth.NewNonce()
		if err != nil {
			api.WriteError(w, err)
			return
		}
		w.Header().Set("Replay-Nonce", nonce)
		w.Header().Set("Cache-Control", "no-store")
		next(w, r)
		return
	}
}

// addDirectory is a middleware that adds a 'Link' response reader with the
// directory index url.
//
// NOTE: Go http does not support multiple headers with the same name so this header
// may be overwritten by another 'Link' addition downstream.
func (h *Handler) addDirectory(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", link(h.Auth.GetLink(acme.DirectoryLink, true), "index"))
		next(w, r)
		return
	}
}

// verifyContentType is a middleware that verifies that content type is
// application/jose+json.
func (h *Handler) verifyContentType(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := "application/jose+json"
		contentType := r.Header.Get("Content-Type")
		if contentType != expected {
			api.WriteError(w, acme.MalformedErr(errors.Errorf(
				"expected content-type %s, but got %s", expected, contentType)))
			return
		}
		next(w, r)
		return
	}
}

// parseJWS is a middleware that parses a request body into a JSONWebSignature struct.
func (h *Handler) parseJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			api.WriteError(w, acme.ServerInternalErr(errors.Wrap(err, "failed to read request body")))
			return
		}
		jws, err := jose.ParseJWS(string(body))
		if err != nil {
			api.WriteError(w, acme.MalformedErr(errors.Wrap(err, "failed to parse JWS from request body")))
			return
		}
		ctx := context.WithValue(r.Context(), jwsContextKey, jws)
		next(w, r.WithContext(ctx))
		return
	}
}

// validateJWS checks the request body for to verify that it meets ACME
// requirements for a JWS.
//
// The JWS MUST NOT have multiple signatures
// The JWS Unencoded Payload Option [RFC7797] MUST NOT be used
// The JWS Unprotected Header [RFC7515] MUST NOT be used
// The JWS Payload MUST NOT be detached
// The JWS Protected Header MUST include the following fields:
//   * “alg” (Algorithm)
//     * This field MUST NOT contain “none” or a Message Authentication Code
//       (MAC) algorithm (e.g. one in which the algorithm registry description
//       mentions MAC/HMAC).
//   * “nonce” (defined in Section 6.5)
//   * “url” (defined in Section 6.4)
//   * Either “jwk” (JSON Web Key) or “kid” (Key ID) as specified below<Paste>
func (h *Handler) validateJWS(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		jws, ok := jwsFromContext(r)
		if !ok || jws == nil {
			api.WriteError(w, acme.ServerInternalErr(errors.Errorf("jws not in request context")))
			return
		}
		if len(jws.Signatures) == 0 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("request body does not contain a signature")))
			return
		}
		if len(jws.Signatures) > 1 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("request body contains more than one signature")))
			return
		}

		sig := jws.Signatures[0]
		uh := sig.Unprotected
		if len(uh.KeyID) > 0 ||
			uh.JSONWebKey != nil ||
			len(uh.Algorithm) > 0 ||
			len(uh.Nonce) > 0 ||
			len(uh.ExtraHeaders) > 0 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("unprotected header must not be used")))
			return
		}
		hdr := sig.Protected
		if hdr.Algorithm == "none" {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("algorithm cannot be none")))
			return
		}

		// Check the validity/freshness of the Nonce.
		if err := h.Auth.UseNonce(hdr.Nonce); err != nil {
			api.WriteError(w, err)
			return
		}

		// Check that the JWS url matches the requested url.
		jwsURL, ok := hdr.ExtraHeaders["url"].(string)
		if !ok || len(jwsURL) == 0 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("JWS missing url protected header")))
			return
		}
		reqURL := &url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path}
		if jwsURL != reqURL.String() {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("url header in JWS (%s) does not match request url (%s)", jwsURL, reqURL)))
			return
		}

		if hdr.JSONWebKey != nil && len(hdr.KeyID) > 0 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("jwk and kid are mutually exclusive")))
			return
		}
		if hdr.JSONWebKey == nil && len(hdr.KeyID) == 0 {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("either jwk or kid must be defined in jws protected header")))
			return
		}
		next(w, r)
		return
	}
}

// extractJWK is a middleware that extracts the JWK from the JWS and saves it
// in the context. Make sure to parse and validate the JWS before running this
// middleware.
func (h *Handler) extractJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		jws, ok := jwsFromContext(r)
		if !ok || jws == nil {
			api.WriteError(w, acme.ServerInternalErr(errors.Errorf("jws expected in request context")))
			return
		}
		jwk := jws.Signatures[0].Protected.JSONWebKey
		if jwk == nil {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("expected jwk in protected header")))
			return
		}
		ctx = context.WithValue(ctx, jwkContextKey, jwk)

		acc, err := h.Auth.GetAccountByKeyID(jwk.KeyID)
		switch {
		case nosql.IsErrNotFound(err):
			break
		case err != nil:
			api.WriteError(w, err)
			return
		default:
			if acc.IsValid() {
				api.WriteError(w, acme.UnauthorizedErr(errors.New("acme account is not active")))
				return
			}
			ctx = context.WithValue(ctx, accContextKey, acc)
		}
		next(w, r.WithContext(ctx))
		return
	}
}

// lookupJWK loads the JWK associated with the acme account referenced by the
// kid parameter of the signed payload.
// Make sure to parse and validate the JWS before running this middleware.
func (h *Handler) lookupJWK(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		jws, ok := jwsFromContext(r)
		if !ok || jws == nil {
			api.WriteError(w, acme.ServerInternalErr(errors.Errorf("jws expected in request context")))
			return
		}

		kidPrefix := h.Auth.GetLink(acme.AccountLink, true, "")
		kid := jws.Signatures[0].Protected.KeyID
		if !strings.HasPrefix(kid, kidPrefix) {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("kid does not have "+
				"required prefix; expected %s, but got %s", kidPrefix, kid)))
			return
		}

		accID := strings.TrimPrefix(kid, kidPrefix)
		acc, err := h.Auth.GetAccount(accID)
		switch {
		case nosql.IsErrNotFound(err):
			api.WriteError(w, acme.AccountDoesNotExistErr(nil))
			return
		case err != nil:
			api.WriteError(w, err)
			return
		default:
			if !acc.IsValid() {
				api.WriteError(w, acme.UnauthorizedErr(errors.New("acme account is not active")))
				return
			}
			ctx = context.WithValue(ctx, accContextKey, acc)
			ctx = context.WithValue(ctx, jwkContextKey, acc.Key)
			next(w, r.WithContext(ctx))
			return
		}
	}
}

// verifyAndExtractJWSPayload extracts the JWK from the JWS and saves it in the context.
// Make sure to parse and validate the JWS before running this middleware.
func (h *Handler) verifyAndExtractJWSPayload(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		jws, ok := jwsFromContext(r)
		if !ok || jws == nil {
			api.WriteError(w, acme.ServerInternalErr(errors.Errorf("jws expected in request context")))
			return
		}
		jwk, ok := jwkFromContext(r)
		if !ok || jwk == nil {
			api.WriteError(w, acme.ServerInternalErr(errors.Errorf("jwk expected in request context")))
			return
		}
		payload, err := jws.Verify(jwk)
		if err != nil {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("failed to verify jws")))
			return
		}
		ctx := context.WithValue(r.Context(), payloadContextKey, &payloadInfo{
			value:       payload,
			isPostAsGet: string(payload) == "",
			isEmptyJSON: string(payload) == "{}\n",
		})
		next(w, r.WithContext(ctx))
		return
	}
}

// isPostAsGet asserts that the request is a PostAsGet (emtpy JWS payload).
func (h *Handler) isPostAsGet(next nextHTTP) nextHTTP {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, ok := payloadFromContext(r)
		if !ok || payload == nil {
			api.WriteError(w, acme.ServerInternalErr(errors.Errorf("payload expected in request context")))
			return
		}
		if !payload.isPostAsGet {
			api.WriteError(w, acme.MalformedErr(errors.Errorf("expected POST-as-GET")))
			return
		}
		next(w, r)
		return
	}
}
