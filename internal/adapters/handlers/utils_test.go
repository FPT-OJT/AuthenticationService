package handlers

import (
	"reflect"
	"testing"

	"github.com/go-playground/validator/v10"
)

// ---------------------------------------------------------------------------
// validationMessage tests
// ---------------------------------------------------------------------------

// validatorForField is a helper that runs validation on a struct and returns
// the first FieldError whose JSON/field name matches fieldName, or nil.
func runValidation(t *testing.T, s any) validator.ValidationErrors {
	t.Helper()
	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := fld.Tag.Get("json")
		if name == "" || name == "-" {
			return fld.Name
		}
		return name
	})

	err := v.Struct(s)
	if err == nil {
		return nil
	}
	ve, ok := err.(validator.ValidationErrors)
	if !ok {
		t.Fatalf("unexpected error type: %T", err)
	}
	return ve
}

func TestValidationMessage_Required(t *testing.T) {
	type S struct {
		Name string `validate:"required" json:"name"`
	}
	errs := runValidation(t, S{})
	if len(errs) == 0 {
		t.Fatal("expected validation error")
	}
	msg := validationMessage(errs[0])
	if msg != "is required" {
		t.Errorf("want %q, got %q", "is required", msg)
	}
}

func TestValidationMessage_Email(t *testing.T) {
	type S struct {
		Email string `validate:"required,email" json:"email"`
	}
	errs := runValidation(t, S{Email: "not-an-email"})
	if len(errs) == 0 {
		t.Fatal("expected validation error")
	}
	// find the email tag error
	var msg string
	for _, fe := range errs {
		if fe.Tag() == "email" {
			msg = validationMessage(fe)
		}
	}
	want := "must be a valid email address"
	if msg != want {
		t.Errorf("want %q, got %q", want, msg)
	}
}

func TestValidationMessage_Min(t *testing.T) {
	type S struct {
		Password string `validate:"required,min=8" json:"password"`
	}
	errs := runValidation(t, S{Password: "short"})
	if len(errs) == 0 {
		t.Fatal("expected validation error")
	}
	var msg string
	for _, fe := range errs {
		if fe.Tag() == "min" {
			msg = validationMessage(fe)
		}
	}
	want := "must be at least 8 characters"
	if msg != want {
		t.Errorf("want %q, got %q", want, msg)
	}
}

func TestValidationMessage_Max(t *testing.T) {
	type S struct {
		Name string `validate:"required,max=3" json:"name"`
	}
	errs := runValidation(t, S{Name: "toolong"})
	if len(errs) == 0 {
		t.Fatal("expected validation error")
	}
	var msg string
	for _, fe := range errs {
		if fe.Tag() == "max" {
			msg = validationMessage(fe)
		}
	}
	want := "must be at most 3 characters"
	if msg != want {
		t.Errorf("want %q, got %q", want, msg)
	}
}

func TestValidationMessage_UnknownTag(t *testing.T) {
	type S struct {
		Age int `validate:"gte=18" json:"age"`
	}
	errs := runValidation(t, S{Age: 10})
	if len(errs) == 0 {
		t.Fatal("expected validation error")
	}
	msg := validationMessage(errs[0])
	if msg == "" {
		t.Error("expected non-empty message for unknown tag")
	}
}

// ---------------------------------------------------------------------------
// formatValidationErrors tests
// ---------------------------------------------------------------------------

func TestFormatValidationErrors_ReturnsMapKeyedByJSONName(t *testing.T) {
	type S struct {
		Email    string `validate:"required,email" json:"email"`
		Password string `validate:"required,min=8" json:"password"`
	}

	v := validator.New()
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := fld.Tag.Get("json")
		if name == "" || name == "-" {
			return fld.Name
		}
		return name
	})

	err := v.Struct(S{Email: "bad", Password: "short"})
	if err == nil {
		t.Fatal("expected validation error")
	}

	errs := formatValidationErrors(err)
	if _, ok := errs["email"]; !ok {
		t.Error("expected key 'email' in errors map")
	}
	if _, ok := errs["password"]; !ok {
		t.Error("expected key 'password' in errors map")
	}
}

func TestFormatValidationErrors_NonValidationError(t *testing.T) {
	plainErr := &nonValidationError{msg: "something bad"}
	errs := formatValidationErrors(plainErr)
	if _, ok := errs["error"]; !ok {
		t.Error("expected key 'error' when given non-validation error")
	}
}

// nonValidationError is a plain error used to test the fallback path.
type nonValidationError struct{ msg string }

func (e *nonValidationError) Error() string { return e.msg }
