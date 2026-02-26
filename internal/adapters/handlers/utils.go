package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// formatValidationErrors converts validator.ValidationErrors into a human-readable
// map keyed by the JSON field name (e.g. "email": "must be a valid email address").
func formatValidationErrors(err error) map[string]string {
	var ve validator.ValidationErrors
	if !isValidationErrors(err, &ve) {
		return map[string]string{"error": err.Error()}
	}
	errs := make(map[string]string, len(ve))
	for _, fe := range ve {
		errs[fe.Field()] = validationMessage(fe)
	}
	return errs
}

func isValidationErrors(err error, out *validator.ValidationErrors) bool {
	ve, ok := err.(validator.ValidationErrors)
	if ok {
		*out = ve
	}
	return ok
}

func validationMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "is required"
	case "email":
		return "must be a valid email address"
	case "min":
		return fmt.Sprintf("must be at least %s characters", fe.Param())
	case "max":
		return fmt.Sprintf("must be at most %s characters", fe.Param())
	default:
		return fmt.Sprintf("failed validation: %s", fe.Tag())
	}
}
