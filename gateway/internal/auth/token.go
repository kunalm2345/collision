package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type RunClaims struct {
	RunID    string `json:"rid"`
	UserID   string `json:"uid"`
	VendorID string `json:"vid"`
	MaxTurns int    `json:"mt"`
	Exp      int64  `json:"exp"`
}

func MintToken(claims RunClaims, secret string) (string, error) {
	if claims.RunID == "" || claims.UserID == "" {
		return "", errors.New("run_id and user_id are required")
	}
	if claims.Exp == 0 {
		claims.Exp = time.Now().Add(15 * time.Minute).Unix()
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	sig := sign(encoded, secret)
	return encoded + "." + sig, nil
}

func VerifyToken(token, secret string) (*RunClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed run token")
	}
	expected := sign(parts[0], secret)
	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return nil, errors.New("invalid run token signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("invalid run token encoding")
	}
	var claims RunClaims
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, errors.New("invalid run token payload")
	}
	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("run token expired")
	}
	return &claims, nil
}

func sign(data, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
