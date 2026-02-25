package domain

type RefreshToken struct {
	RefreshToken string
	FamilyToken  string
	UserID       string
	IsRevoked    bool
}
