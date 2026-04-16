package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	TokenTypeAccess   = "access"
	TokenTypeRefresh  = "refresh"
	TokenTypeSetup    = "setup"
	TokenTypeTOTP     = "totp"
	TokenTypeAPIToken = "api_token"

	AccessTokenExpiry  = 15 * time.Minute
	RefreshTokenExpiry = 7 * 24 * time.Hour
	SetupTokenExpiry   = 10 * time.Minute
	TOTPTokenExpiry    = 60 * time.Second
)

type Claims struct {
	jwt.RegisteredClaims
	Role            string `json:"role"`
	TokenType       string `json:"type"`
	TokenGeneration int    `json:"gen,omitempty"`
}

// No local TokenPair type — use model.TokenPair for JSON serialization.
// GenerateTokenPair returns raw strings to avoid a duplicate type.

func GenerateTokenPair(secret, userID, role string, tokenGen int) (accessToken, refreshToken string, err error) {
	accessToken, err = GenerateTokenWithExpiry(secret, userID, role, TokenTypeAccess, AccessTokenExpiry, tokenGen)
	if err != nil {
		return "", "", fmt.Errorf("generate access token: %w", err)
	}

	refreshToken, err = GenerateTokenWithExpiry(secret, userID, role, TokenTypeRefresh, RefreshTokenExpiry, tokenGen)
	if err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}

	return accessToken, refreshToken, nil
}

func GenerateSetupToken(secret, userID, role string) (string, error) {
	return GenerateTokenWithExpiry(secret, userID, role, TokenTypeSetup, SetupTokenExpiry)
}

func GenerateTOTPToken(secret, userID, role string) (string, error) {
	return GenerateTokenWithExpiry(secret, userID, role, TokenTypeTOTP, TOTPTokenExpiry)
}

func GenerateTokenWithExpiry(secret, userID, role, tokenType string, expiry time.Duration, tokenGen ...int) (string, error) {
	now := time.Now()
	jti := uuid.NewString()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
		},
		Role:      role,
		TokenType: tokenType,
	}
	if len(tokenGen) > 0 {
		claims.TokenGeneration = tokenGen[0]
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signed, nil
}

func ValidateToken(secret, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
