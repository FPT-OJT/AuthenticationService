package domain

type RefreshToken struct {
	RefreshToken string
	FamilyToken  string
	UserID       string
	Role         string
	IsRevoked    bool
}
