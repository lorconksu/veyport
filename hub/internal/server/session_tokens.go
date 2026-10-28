package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/wyiu/veyport/hub/internal/auth"
	"github.com/wyiu/veyport/hub/internal/model"
)

func refreshDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// issueSessionTokens records the refresh spend authority before any token is
// returned. Signing a replacement alone never makes its refresh token current.
func (s *Server) issueSessionTokens(ctx context.Context, user *model.User, sessionID, previous string, now time.Time) (string, string, error) {
	policy, err := s.strictLockoutPolicy()
	if err != nil {
		return "", "", err
	}
	access, refresh, err := auth.GenerateSessionTokenPair(s.jwtSecret, user.ID, string(user.Role), user.TokenGeneration, sessionID)
	if err != nil {
		return "", "", err
	}
	previousDigest := ""
	if previous != "" {
		previousDigest = refreshDigest(previous)
	}
	if err := s.store.RotateSessionRefresh(ctx, user, sessionID, previousDigest, refreshDigest(refresh), now, policy); err != nil {
		return "", "", err
	}
	return access, refresh, nil
}
