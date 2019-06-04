package acme

import (
	"encoding/json"

	"github.com/pkg/errors"
)

// AccountDoesNotExistErr returns a new acme error.
func AccountDoesNotExistErr(err error) *Error {
	return &Error{
		Type:   accountDoesNotExistErr,
		Detail: "Account does not exist",
		Err:    err,
	}
}

// AlreadyRevokedErr returns a new acme error.
func AlreadyRevokedErr(err error) *Error {
	return &Error{
		Type:   alreadyRevokedErr,
		Detail: "Certificate already revoked",
		Err:    err,
	}
}

// BadCSRErr returns a new acme error.
func BadCSRErr(err error) *Error {
	return &Error{
		Type:   badCSRErr,
		Detail: "The CSR is unacceptable",
		Err:    err,
	}
}

// BadNonceErr returns a new acme error.
func BadNonceErr(err error) *Error {
	return &Error{
		Type:   badNonceErr,
		Detail: "Unacceptable anti-replay nonce",
		Err:    err,
	}
}

// BadPublicKeyErr returns a new acme error.
func BadPublicKeyErr(err error) *Error {
	return &Error{
		Type:   badPublicKeyErr,
		Detail: "The jws was signed by a public key the server does not support",
		Err:    err,
	}
}

// BadRevocationReasonErr returns a new acme error.
func BadRevocationReasonErr(err error) *Error {
	return &Error{
		Type:   badRevocationReasonErr,
		Detail: "The revocation reason provided is not allowed by the server",
		Err:    err,
	}
}

// BadSignatureAlgorithmErr returns a new acme error.
func BadSignatureAlgorithmErr(err error) *Error {
	return &Error{
		Type:   badSignatureAlgorithmErr,
		Detail: "The JWS was signed with an algorithm the server does not support",
		Err:    err,
	}
}

// CaaErr returns a new acme error.
func CaaErr(err error) *Error {
	return &Error{
		Type:   caaErr,
		Detail: "Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate",
		Err:    err,
	}
}

// CompoundErr returns a new acme error.
func CompoundErr(err error) *Error {
	return &Error{
		Type:   compoundErr,
		Detail: "Specific error conditions are indicated in the “subproblems” array",
		Err:    err,
	}
}

// ConnectionErr returns a new acme error.
func ConnectionErr(err error) *Error {
	return &Error{
		Type:   connectionErr,
		Detail: "The server could not connect to validation target",
		Err:    err,
	}
}

// DNSErr returns a new acme error.
func DNSErr(err error) *Error {
	return &Error{
		Type:   dnsErr,
		Detail: "There was a problem with a DNS query during identifier validation",
		Err:    err,
	}
}

// ExternalAccountRequiredErr returns a new acme error.
func ExternalAccountRequiredErr(err error) *Error {
	return &Error{
		Type:   externalAccountRequiredErr,
		Detail: "The request must include a value for the \"externalAccountBinding\" field",
		Err:    err,
	}
}

// IncorrectResponseErr returns a new acme error.
func IncorrectResponseErr(err error) *Error {
	return &Error{
		Type:   incorrectResponseErr,
		Detail: "Response received didn't match the challenge's requirements",
		Err:    err,
	}
}

// InvalidContactErr returns a new acme error.
func InvalidContactErr(err error) *Error {
	return &Error{
		Type:   invalidContactErr,
		Detail: "A contact URL for an account was invalid",
		Err:    err,
	}
}

// MalformedErr returns a new acme error.
func MalformedErr(err error) *Error {
	return &Error{
		Type:   malformedErr,
		Detail: "The request message was malformed",
		Err:    err,
	}
}

// OrderNotReadyErr returns a new acme error.
func OrderNotReadyErr(err error) *Error {
	return &Error{
		Type:   orderNotReadyErr,
		Detail: "The request attempted to finalize an order that is not ready to be finalized",
		Err:    err,
	}
}

// RateLimitedErr returns a new acme error.
func RateLimitedErr(err error) *Error {
	return &Error{
		Type:   rateLimitedErr,
		Detail: "The request exceeds a rate limit",
		Err:    err,
	}
}

// RejectedIdentifierErr returns a new acme error.
func RejectedIdentifierErr(err error) *Error {
	return &Error{
		Type:   rejectedIdentifierErr,
		Detail: "The server will not issue certificates for the identifier",
		Err:    err,
	}
}

// ServerInternalErr returns a new acme error.
func ServerInternalErr(err error) *Error {
	return &Error{
		Type:   serverInternalErr,
		Detail: "The server experienced an internal error",
		Err:    err,
	}
}

// TLSErr returns a new acme error.
func TLSErr(err error) *Error {
	return &Error{
		Type:   tlsErr,
		Detail: "The server received a TLS error during validation",
		Err:    err,
	}
}

// UnauthorizedErr returns a new acme error.
func UnauthorizedErr(err error) *Error {
	return &Error{
		Type:   unauthorizedErr,
		Detail: "The client lacks sufficient authorization",
		Err:    err,
	}
}

// UnsupportedContactErr returns a new acme error.
func UnsupportedContactErr(err error) *Error {
	return &Error{
		Type:   unsupportedContactErr,
		Detail: "A contact URL for an account used an unsupported protocol scheme",
		Err:    err,
	}
}

// UnsupportedIdentifierErr returns a new acme error.
func UnsupportedIdentifierErr(err error) *Error {
	return &Error{
		Type:   unsupportedIdentifierErr,
		Detail: "An identifier is of an unsupported type",
		Err:    err,
	}
}

// UserActionRequiredErr returns a new acme error.
func UserActionRequiredErr(err error) *Error {
	return &Error{
		Type:   userActionRequiredErr,
		Detail: "Visit the “instance” URL and take actions specified there",
		Err:    err,
	}
}

// ProbType is the type of the ACME problem.
type ProbType int

const (
	// The request specified an account that does not exist
	accountDoesNotExistErr ProbType = iota
	// The request specified a certificate to be revoked that has already been revoked
	alreadyRevokedErr
	// The CSR is unacceptable (e.g., due to a short key)
	badCSRErr
	// The client sent an unacceptable anti-replay nonce
	badNonceErr
	// The JWS was signed by a public key the server does not support
	badPublicKeyErr
	// The revocation reason provided is not allowed by the server
	badRevocationReasonErr
	// The JWS was signed with an algorithm the server does not support
	badSignatureAlgorithmErr
	// Certification Authority Authorization (CAA) records forbid the CA from issuing a certificate
	caaErr
	// Specific error conditions are indicated in the “subproblems” array.
	compoundErr
	// The server could not connect to validation target
	connectionErr
	// There was a problem with a DNS query during identifier validation
	dnsErr
	// The request must include a value for the “externalAccountBinding” field
	externalAccountRequiredErr
	// Response received didn’t match the challenge’s requirements
	incorrectResponseErr
	// A contact URL for an account was invalid
	invalidContactErr
	// The request message was malformed
	malformedErr
	// The request attempted to finalize an order that is not ready to be finalized
	orderNotReadyErr
	// The request exceeds a rate limit
	rateLimitedErr
	// The server will not issue certificates for the identifier
	rejectedIdentifierErr
	// The server experienced an internal error
	serverInternalErr
	// The server received a TLS error during validation
	tlsErr
	// The client lacks sufficient authorization
	unauthorizedErr
	// A contact URL for an account used an unsupported protocol scheme
	unsupportedContactErr
	// An identifier is of an unsupported type
	unsupportedIdentifierErr
	// Visit the “instance” URL and take actions specified there
	userActionRequiredErr
)

// String returns the string representation of the acme problem type,
// fulfilling the Stringer interface.
func (ap ProbType) String() string {
	switch ap {
	case accountDoesNotExistErr:
		return "accountDoesNotExist"
	case alreadyRevokedErr:
		return "alreadyRevoked"
	case badCSRErr:
		return "badCSR"
	case badNonceErr:
		return "badNonce"
	case badPublicKeyErr:
		return "badPublicKey"
	case badRevocationReasonErr:
		return "badRevocationReason"
	case badSignatureAlgorithmErr:
		return "badSignatureAlgorithm"
	case caaErr:
		return "caa"
	case compoundErr:
		return "compound"
	case connectionErr:
		return "connection"
	case dnsErr:
		return "dns"
	case externalAccountRequiredErr:
		return "externalAccountRequired"
	case incorrectResponseErr:
		return "incorrectResponse"
	case invalidContactErr:
		return "invalidContact"
	case malformedErr:
		return "malformed"
	case orderNotReadyErr:
		return "orderNotReady"
	case rateLimitedErr:
		return "rateLimited"
	case rejectedIdentifierErr:
		return "rejectedIdentifier"
	case serverInternalErr:
		return "serverInternal"
	case tlsErr:
		return "tls"
	case unauthorizedErr:
		return "unauthorized"
	case unsupportedContactErr:
		return "unsupportedContact"
	case unsupportedIdentifierErr:
		return "unsupportedIdentifier"
	case userActionRequiredErr:
		return "userActionRequired"
	default:
		return "unsupported type"
	}
}

// Error is an ACME error type complete with problem document.
type Error struct {
	Type       ProbType
	Detail     string
	Err        error
	Status     int
	Sub        []*Error
	Identifier *Identifier
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Err == nil {
		return e.Detail
	}
	return e.Err.Error()
}

// Cause returns the internal error and implements the Causer interface.
func (e *Error) Cause() error {
	if e.Err == nil {
		return errors.New(e.Detail)
	}
	return e.Err
}

// MarshalJSON converts the internal Error type into the public acme problem
// type for presentation in the ACME protocol.
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.toACME())
}

type acmeError struct {
	Type        string        `json:"type"`
	Detail      string        `json:"detail"`
	Identifier  interface{}   `json:"identifier,omitempty"`
	Subproblems []interface{} `json:"subproblems,omitempty"`
}

// toACME returns an acme representation of the problem type.
func (e *Error) toACME() interface{} {
	ae := acmeError{
		Type:   "urn:ietf:params:acme:error:" + e.Type.String(),
		Detail: e.Error(),
	}
	if e.Identifier != nil {
		ae.Identifier = *e.Identifier
	}
	for _, p := range e.Sub {
		ae.Subproblems = append(ae.Subproblems, p.toACME())
	}
	return ae
}

// StatusCode returns the status code and implements the StatusCode interface.
func (e *Error) StatusCode() int {
	return e.Status
}
