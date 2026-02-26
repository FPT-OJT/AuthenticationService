package ports

type GoogleTokenPayload struct {
	GoogleID  string
	Email     string
	FirstName string
	LastName  string
}

type GoogleTokenVerifierPort interface {
	Verify(idToken string) (*GoogleTokenPayload, error)
}
