package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/artalkjs/artalk/v2/internal/core"
	"github.com/artalkjs/artalk/v2/server/common"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
)

const (
	opdaGatewayKeyEnv     = "OPDA_COMMENTS_GATEWAY_KEY"
	opdaAssertionIssuer   = "opda-comments-gateway"
	opdaAssertionAudience = "artalk-comments"
	opdaAssertionMaxBody  = 4096
	opdaAssertionMaxLife  = int64(15)
	opdaClockTolerance    = int64(2)
	opdaArtalkTokenTTL    = 30
	opdaReplayCacheLimit  = 4096
)

type paramsAuthOPDASession struct {
	Assertion string `json:"assertion"`
}

type opdaSessionClaims struct {
	Name string `json:"name"`
	jwt.StandardClaims
}

type opdaReplayCache struct {
	mu      sync.Mutex
	entries map[string]int64
	limit   int
}

func newOPDAReplayCache(limit int) *opdaReplayCache {
	return &opdaReplayCache{entries: make(map[string]int64), limit: limit}
}

func (cache *opdaReplayCache) reserve(jti string, expiresAt int64, now int64) bool {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for key, expiry := range cache.entries {
		if expiry < now {
			delete(cache.entries, key)
		}
	}
	if _, exists := cache.entries[jti]; exists || len(cache.entries) >= cache.limit {
		return false
	}
	cache.entries[jti] = expiresAt
	return true
}

func decodeOPDAGatewayKey(value string) ([]byte, bool) {
	if len(value) != 64 {
		return nil, false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return nil, false
		}
	}
	key, err := hex.DecodeString(value)
	return key, err == nil && len(key) == 32
}

func canonicalUUID(value string) (string, bool) {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return "", false
	}
	allZero := true
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return "", false
		}
		if char != '0' {
			allZero = false
		}
	}
	if allZero {
		return "", false
	}
	return strings.ToLower(value), true
}

func validOPDASubject(value string) bool {
	if len(value) == 0 || len(value) > 255 {
		return false
	}
	for _, char := range value {
		if char < '!' || char > '~' {
			return false
		}
	}
	return true
}

func normaliseOPDAName(value string) (string, bool) {
	if !utf8.ValidString(value) {
		return "", false
	}
	value = strings.TrimSpace(value)
	if value == "" || utf8.RuneCountInString(value) > 256 {
		return "", false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return "", false
		}
	}
	return value, true
}

func verifyOPDAAssertion(assertion string, key []byte, now int64) (opdaSessionClaims, string, bool) {
	claims := opdaSessionClaims{}
	parser := &jwt.Parser{
		ValidMethods:         []string{jwt.SigningMethodHS256.Alg()},
		SkipClaimsValidation: true,
	}
	token, err := parser.ParseWithClaims(assertion, &claims, func(token *jwt.Token) (any, error) {
		return key, nil
	})
	if err != nil || token == nil || !token.Valid {
		return opdaSessionClaims{}, "", false
	}

	name, nameOK := normaliseOPDAName(claims.Name)
	jti, jtiOK := canonicalUUID(claims.Id)
	if claims.Issuer != opdaAssertionIssuer || claims.Audience != opdaAssertionAudience ||
		!validOPDASubject(claims.Subject) || !nameOK || !jtiOK ||
		claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt ||
		claims.ExpiresAt-claims.IssuedAt > opdaAssertionMaxLife ||
		claims.IssuedAt > now+opdaClockTolerance || claims.ExpiresAt < now-opdaClockTolerance {
		return opdaSessionClaims{}, "", false
	}
	claims.Name = name
	return claims, jti, true
}

func syntheticOPDAEmail(subject string) string {
	digest := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(digest[:]) + "@members.comments.opda.org.uk"
}

// AuthOPDASession exchanges a short-lived, single-use assertion from the OPDA
// comments gateway for an equally short-lived Artalk JWT. The route stays
// disabled unless the gateway key is a lowercase 32-byte hex value.
func AuthOPDASession(app *core.App, router fiber.Router) {
	key, enabled := decodeOPDAGatewayKey(os.Getenv(opdaGatewayKeyEnv))
	replays := newOPDAReplayCache(opdaReplayCacheLimit)
	router.Post("/opda/session", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderCacheControl, "no-store")
		if !enabled {
			return common.RespError(c, http.StatusNotFound, "OPDA session exchange disabled")
		}
		body := c.Body()
		if len(body) == 0 || len(body) > opdaAssertionMaxBody {
			return common.RespError(c, http.StatusBadRequest, "Invalid OPDA session request")
		}

		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var params paramsAuthOPDASession
		if err := decoder.Decode(&params); err != nil || params.Assertion == "" {
			return common.RespError(c, http.StatusBadRequest, "Invalid OPDA session request")
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			return common.RespError(c, http.StatusBadRequest, "Invalid OPDA session request")
		}

		now := time.Now().Unix()
		claims, jti, ok := verifyOPDAAssertion(params.Assertion, key, now)
		if !ok || !replays.reserve(jti, claims.ExpiresAt+opdaClockTolerance, now) {
			return common.RespError(c, http.StatusUnauthorized, "OPDA session assertion rejected")
		}

		user, err := app.Dao().ResolveOPDAParticipantUser(
			claims.Subject, claims.Name, syntheticOPDAEmail(claims.Subject), time.Unix(now, 0),
		)
		if err != nil {
			return common.RespError(c, http.StatusInternalServerError, "OPDA participant binding unavailable")
		}
		artalkToken, err := common.LoginGetUserToken(user, app.Conf().AppKey, opdaArtalkTokenTTL)
		if err != nil {
			return common.RespError(c, http.StatusInternalServerError, "OPDA session exchange unavailable")
		}
		return common.RespData(c, ResponseUserLogin{
			Token: artalkToken,
			User:  app.Dao().CookUser(&user),
		})
	})
}
