package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/pkg/errors"
	"github.com/smallstep/certificates/acme"
	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/logging"
)

// NewAccountRequest represents the payload for a new account request.
type NewAccountRequest struct {
	Contact            []string `json:"contact"`
	OnlyReturnExisting bool     `json:"onlyReturnExisting"`
}

func validateContacts(cs []string) error {
	for _, c := range cs {
		if len(c) == 0 {
			return acme.MalformedErr(errors.New("contact cannot be empty string"))
		}
	}
	return nil
}

// Validate validates a new-account request body.
func (n *NewAccountRequest) Validate() error {
	if n.OnlyReturnExisting && len(n.Contact) > 0 {
		return acme.MalformedErr(errors.New("incompatible input; onlyReturnExisting must be alone"))
	}
	return validateContacts(n.Contact)
}

// UpdateAccountRequest represents an update-account request.
type UpdateAccountRequest struct {
	Contact []string `json:"contact"`
	Status  string   `json:"status"`
}

// IsDeactivateRequest returns true if the update request is a deactivation
// request, false otherwise.
func (u *UpdateAccountRequest) IsDeactivateRequest() bool {
	return u.Status == acme.StatusDeactivated
}

// Validate validates a update-account request body.
func (u *UpdateAccountRequest) Validate() error {
	if len(u.Status) > 0 && len(u.Contact) > 0 {
		return acme.MalformedErr(errors.New("incompatible input; contact and " +
			"status updates are mutually exclusive"))
	}
	switch {
	case len(u.Contact) > 0:
		if err := validateContacts(u.Contact); err != nil {
			return err
		}
		return nil
	case len(u.Status) > 0:
		if u.Status != acme.StatusDeactivated {
			return acme.MalformedErr(errors.Errorf("cannot update account "+
				"status to %s, only deactivated", u.Status))
		}
		return nil
	default:
		return acme.MalformedErr(errors.Errorf("empty update request"))
	}
}

func logAccount(w http.ResponseWriter, acc *acme.Account) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		m := map[string]interface{}{
			"accContact": acc.Contact,
			"accStatus":  acc.Status,
			"accOrders":  acc.Orders,
		}
		rl.WithFields(m)
	}
}

// NewAccount is the handler resource for creating new ACME accounts.
func (h *Handler) NewAccount(w http.ResponseWriter, r *http.Request) {
	payload, ok := payloadFromContext(r)
	if !ok || payload == nil {
		api.WriteError(w, acme.ServerInternalErr(errors.Errorf("payload expected in request context")))
		return
	}
	var nar NewAccountRequest
	if err := json.Unmarshal(payload.value, &nar); err != nil {
		api.WriteError(w, acme.MalformedErr(errors.Wrap(err,
			"failed to unmarshal new-account request payload")))
		return
	}
	if err := nar.Validate(); err != nil {
		api.WriteError(w, err)
		return
	}

	acc, ok := accountFromContext(r)
	httpStatus := http.StatusCreated
	if !ok {
		// Account does not exist //
		if nar.OnlyReturnExisting {
			api.WriteError(w, acme.AccountDoesNotExistErr(nil))
			return
		}
		jwk, ok := jwkFromContext(r)
		if !ok || jwk == nil {
			api.WriteError(w, acme.ServerInternalErr(errors.Errorf("jwk expected in request context")))
			return
		}

		var err error
		if acc, err = h.Auth.NewAccount(acme.AccountOptions{
			Key:     jwk,
			Contact: nar.Contact,
		}); err != nil {
			api.WriteError(w, err)
			return
		}
	} else {
		// Account exists //
		httpStatus = http.StatusOK
	}

	w.Header().Set("Location", h.Auth.GetLink(acme.AccountLink, true, acc.GetID()))
	w.WriteHeader(httpStatus)
	api.JSON(w, acc)
	logAccount(w, acc)
	return
}

// GetUpdateAccount is the api for updating an ACME account.
func (h *Handler) GetUpdateAccount(w http.ResponseWriter, r *http.Request) {
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

	if !payload.isPostAsGet {
		var uar UpdateAccountRequest
		if err := json.Unmarshal(payload.value, &uar); err != nil {
			api.WriteError(w, acme.MalformedErr(errors.Wrap(err, "failed to unmarshal new-account request payload")))
			return
		}
		if err := uar.Validate(); err != nil {
			api.WriteError(w, err)
			return
		}
		var err error
		if uar.IsDeactivateRequest() {
			acc, err = h.Auth.DeactivateAccount(acc.GetID())
		} else {
			acc, err = h.Auth.UpdateAccount(acc.GetID(), uar.Contact)
		}
		if err != nil {
			api.WriteError(w, err)
			return
		}
	}
	w.Header().Set("Location", h.Auth.GetLink(acme.AccountLink, true, acc.GetID()))
	w.WriteHeader(http.StatusOK)
	api.JSON(w, acc)
	logAccount(w, acc)
	return
}

func logOrdersByAccount(w http.ResponseWriter, oids []string) {
	if rl, ok := w.(logging.ResponseLogger); ok {
		m := map[string]interface{}{
			"accOrders": oids,
		}
		rl.WithFields(m)
	}
}

// GetOrdersByAccount ACME api for retrieving the list of order urls belonging to an account.
func (h *Handler) GetOrdersByAccount(w http.ResponseWriter, r *http.Request) {
	acc, ok := accountFromContext(r)
	if !ok || acc == nil {
		api.WriteError(w, acme.AccountDoesNotExistErr(nil))
		return
	}

	accID := chi.URLParam(r, "accID")
	if acc.ID != accID {
		api.WriteError(w, acme.UnauthorizedErr(errors.New("account ID does not match url param")))
		return
	}
	orders, err := h.Auth.GetOrdersByAccount(acc.GetID())
	if err != nil {
		api.WriteError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	api.JSON(w, orders)
	logOrdersByAccount(w, orders)
	return
}
