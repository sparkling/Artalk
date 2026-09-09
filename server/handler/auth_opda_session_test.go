package handler_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/artalkjs/artalk/v2/internal/dao"
	"github.com/artalkjs/artalk/v2/internal/entity"
	"github.com/artalkjs/artalk/v2/server/handler"
	"github.com/artalkjs/artalk/v2/test"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const opdaTestKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func opdaTestKey(t *testing.T) []byte {
	t.Helper()
	key, err := hex.DecodeString(opdaTestKeyHex)
	require.NoError(t, err)
	return key
}

func newOPDATestAPI(t *testing.T, key string) (*test.TestApp, *fiber.App) {
	t.Helper()
	t.Setenv("OPDA_COMMENTS_GATEWAY_KEY", key)
	app, err := test.NewTestApp()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, app.Cleanup()) })
	fiberApp := fiber.New()
	api := fiberApp.Group("/api/v2")
	handler.AuthOPDASession(app.App, api)
	return app, fiberApp
}

func opdaClaims(now int64, subject string, name string, jti string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":  "opda-comments-gateway",
		"aud":  "artalk-comments",
		"sub":  subject,
		"name": name,
		"iat":  now,
		"exp":  now + 15,
		"jti":  jti,
	}
}

func signOPDAAssertion(t *testing.T, claims jwt.MapClaims, key []byte) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func postOPDARaw(fiberApp *fiber.App, body []byte) (*http.Response, []byte, error) {
	req := httptest.NewRequest(http.MethodPost, "/api/v2/opda/session", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := fiberApp.Test(req)
	if err != nil {
		return nil, nil, err
	}
	responseBody, readErr := io.ReadAll(resp.Body)
	return resp, responseBody, readErr
}

func postOPDAAssertion(t *testing.T, fiberApp *fiber.App, assertion string) (*http.Response, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"assertion": assertion})
	require.NoError(t, err)
	resp, responseBody, err := postOPDARaw(fiberApp, body)
	require.NoError(t, err)
	return resp, responseBody
}

func decodeOPDALogin(t *testing.T, body []byte) handler.ResponseUserLogin {
	t.Helper()
	var result handler.ResponseUserLogin
	require.NoError(t, json.Unmarshal(body, &result))
	return result
}

func opdaSyntheticEmail(subject string) string {
	digest := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(digest[:]) + "@members.comments.opda.org.uk"
}

func TestAuthOPDASessionDisabledWithoutExactKey(t *testing.T) {
	for _, gatewayKey := range []string{"", strings.ToUpper(opdaTestKeyHex), strings.Repeat("a", 63)} {
		t.Run(fmt.Sprintf("key-length-%d", len(gatewayKey)), func(t *testing.T) {
			_, fiberApp := newOPDATestAPI(t, gatewayKey)
			resp, _, err := postOPDARaw(fiberApp, []byte(`{"assertion":"unused"}`))
			require.NoError(t, err)
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		})
	}
}

func TestAuthOPDASessionRequiresOnlyBoundedAssertionBody(t *testing.T) {
	_, fiberApp := newOPDATestAPI(t, opdaTestKeyHex)
	for name, body := range map[string][]byte{
		"empty":         nil,
		"missing":       []byte(`{}`),
		"unknown field": []byte(`{"assertion":"x","extra":true}`),
		"trailing json": []byte(`{"assertion":"x"}{}`),
		"oversized":     []byte(`{"assertion":"` + strings.Repeat("x", 4090) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			resp, _, err := postOPDARaw(fiberApp, body)
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

func TestAuthOPDASessionRejectsInvalidAssertions(t *testing.T) {
	_, fiberApp := newOPDATestAPI(t, opdaTestKeyHex)
	now := time.Now().Unix()
	base := opdaClaims(now, "participant-invalid-cases", "Member", "2774dd25-2449-4d88-b8fb-f42a4d3a61c0")

	cases := map[string]func(jwt.MapClaims){
		"missing issuer":    func(c jwt.MapClaims) { delete(c, "iss") },
		"wrong issuer":      func(c jwt.MapClaims) { c["iss"] = "someone-else" },
		"wrong audience":    func(c jwt.MapClaims) { c["aud"] = "another-service" },
		"missing subject":   func(c jwt.MapClaims) { delete(c, "sub") },
		"unsafe subject":    func(c jwt.MapClaims) { c["sub"] = "participant\nother" },
		"missing name":      func(c jwt.MapClaims) { delete(c, "name") },
		"control in name":   func(c jwt.MapClaims) { c["name"] = "Member\u0000Name" },
		"missing issued":    func(c jwt.MapClaims) { delete(c, "iat") },
		"fractional issued": func(c jwt.MapClaims) { c["iat"] = float64(now) + 0.5 },
		"future issued":     func(c jwt.MapClaims) { c["iat"] = now + 3; c["exp"] = now + 10 },
		"missing expiry":    func(c jwt.MapClaims) { delete(c, "exp") },
		"expired":           func(c jwt.MapClaims) { c["iat"] = now - 20; c["exp"] = now - 3 },
		"long lifetime":     func(c jwt.MapClaims) { c["exp"] = now + 16 },
		"missing jti":       func(c jwt.MapClaims) { delete(c, "jti") },
		"invalid jti":       func(c jwt.MapClaims) { c["jti"] = "not-a-uuid" },
	}
	index := 0
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			claims := jwt.MapClaims{}
			for key, value := range base {
				claims[key] = value
			}
			index++
			claims["jti"] = fmt.Sprintf("2774dd25-2449-4d88-b8fb-%012x", index)
			mutate(claims)
			assertion := signOPDAAssertion(t, claims, opdaTestKey(t))
			resp, _ := postOPDAAssertion(t, fiberApp, assertion)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		})
	}

	forged := signOPDAAssertion(t, base, bytes.Repeat([]byte{0x42}, 32))
	resp, _ := postOPDAAssertion(t, fiberApp, forged)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestAuthOPDASessionAssertionIsSingleUse(t *testing.T) {
	_, fiberApp := newOPDATestAPI(t, opdaTestKeyHex)
	claims := opdaClaims(time.Now().Unix(), "participant-replay", "Replay Test", "7be679be-58d3-4e55-8829-bfa014326554")
	assertion := signOPDAAssertion(t, claims, opdaTestKey(t))

	first, _ := postOPDAAssertion(t, fiberApp, assertion)
	second, _ := postOPDAAssertion(t, fiberApp, assertion)
	assert.Equal(t, http.StatusOK, first.StatusCode)
	assert.Equal(t, "no-store", first.Header.Get("Cache-Control"))
	assert.Equal(t, http.StatusUnauthorized, second.StatusCode)
}

func TestAuthOPDASessionKeepsStableIdentityAcrossNameChanges(t *testing.T) {
	app, fiberApp := newOPDATestAPI(t, opdaTestKeyHex)
	now := time.Now().Unix()
	subject := "participant-stable"
	firstToken := signOPDAAssertion(t, opdaClaims(now, subject, "Original Name", "ab577ea5-299d-422a-b231-5142bc2460b3"), opdaTestKey(t))
	secondToken := signOPDAAssertion(t, opdaClaims(now, subject, "Updated Name", "b77e6155-b945-4123-b7ef-e146084975fc"), opdaTestKey(t))

	firstResp, firstBody := postOPDAAssertion(t, fiberApp, firstToken)
	secondResp, secondBody := postOPDAAssertion(t, fiberApp, secondToken)
	require.Equal(t, http.StatusOK, firstResp.StatusCode)
	require.Equal(t, http.StatusOK, secondResp.StatusCode)
	first := decodeOPDALogin(t, firstBody)
	second := decodeOPDALogin(t, secondBody)
	assert.Equal(t, first.User.ID, second.User.ID)
	assert.Equal(t, "Updated Name", second.User.Name)
	assert.Equal(t, opdaSyntheticEmail(subject), second.User.Email)
	assert.False(t, second.User.IsAdmin)

	var identities []entity.AuthIdentity
	require.NoError(t, app.Dao().DB().Where("provider = ? AND remote_uid = ?", dao.OPDAIdentityProvider, subject).Find(&identities).Error)
	assert.Len(t, identities, 1)
	var stored entity.User
	require.NoError(t, app.Dao().DB().First(&stored, first.User.ID).Error)
	assert.False(t, stored.ReceiveEmail)

	claims := struct{ jwt.StandardClaims }{}
	parsed, err := jwt.ParseWithClaims(second.Token, &claims, func(*jwt.Token) (any, error) { return []byte("test"), nil })
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	assert.Equal(t, int64(30), claims.ExpiresAt-claims.IssuedAt)
}

func TestAuthOPDASessionDoesNotMergeOrInheritAdmin(t *testing.T) {
	app, fiberApp := newOPDATestAPI(t, opdaTestKeyHex)
	subject := "participant-separate"
	legacy := entity.User{
		Name: "Same Name", Email: opdaSyntheticEmail(subject), IsAdmin: true, ReceiveEmail: true,
	}
	require.NoError(t, app.Dao().CreateUser(&legacy))

	assertion := signOPDAAssertion(t, opdaClaims(time.Now().Unix(), subject, "Same Name", "f734b9dd-4f0d-4617-b559-7d04df34cbd4"), opdaTestKey(t))
	resp, body := postOPDAAssertion(t, fiberApp, assertion)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	login := decodeOPDALogin(t, body)
	assert.NotEqual(t, legacy.ID, login.User.ID)
	assert.False(t, login.User.IsAdmin)

	var preserved entity.User
	require.NoError(t, app.Dao().DB().First(&preserved, legacy.ID).Error)
	assert.True(t, preserved.IsAdmin)
	assert.True(t, preserved.ReceiveEmail)
	var count int64
	require.NoError(t, app.Dao().DB().Model(&entity.User{}).Where("email = ?", legacy.Email).Count(&count).Error)
	assert.Equal(t, int64(2), count)
}

func TestAuthOPDASessionSerializesFirstBinding(t *testing.T) {
	app, fiberApp := newOPDATestAPI(t, opdaTestKeyHex)
	now := time.Now().Unix()
	subject := "participant-concurrent"
	assertions := []string{
		signOPDAAssertion(t, opdaClaims(now, subject, "Concurrent Member", "4f3ff151-19ed-408f-984f-11dffb1a10a0"), opdaTestKey(t)),
		signOPDAAssertion(t, opdaClaims(now, subject, "Concurrent Member", "88687149-afdd-4333-a3c9-93b284b75926"), opdaTestKey(t)),
	}

	type result struct {
		status int
		body   []byte
		err    error
	}
	start := make(chan struct{})
	results := make(chan result, len(assertions))
	var wait sync.WaitGroup
	for _, assertion := range assertions {
		wait.Add(1)
		go func(assertion string) {
			defer wait.Done()
			<-start
			body, _ := json.Marshal(map[string]string{"assertion": assertion})
			resp, responseBody, err := postOPDARaw(fiberApp, body)
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			results <- result{status: status, body: responseBody, err: err}
		}(assertion)
	}
	close(start)
	wait.Wait()
	close(results)

	var userID uint
	for result := range results {
		require.NoError(t, result.err)
		require.Equal(t, http.StatusOK, result.status)
		login := decodeOPDALogin(t, result.body)
		if userID == 0 {
			userID = login.User.ID
		}
		assert.Equal(t, userID, login.User.ID)
	}
	var identityCount int64
	require.NoError(t, app.Dao().DB().Model(&entity.AuthIdentity{}).Where(
		"provider = ? AND remote_uid = ?", dao.OPDAIdentityProvider, subject,
	).Count(&identityCount).Error)
	assert.Equal(t, int64(1), identityCount)
}

func TestAuthOPDASessionRejectsInvalidStoredBindings(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		setup func(*testing.T, *test.TestApp, string)
	}{
		{
			name: "missing user",
			setup: func(t *testing.T, app *test.TestApp, subject string) {
				now := time.Now()
				require.NoError(t, app.Dao().DB().Create(&entity.AuthIdentity{
					Provider: dao.OPDAIdentityProvider, RemoteUID: subject, UserID: 999999, ConfirmedAt: &now,
				}).Error)
			},
		},
		{
			name: "wrong bound email",
			setup: func(t *testing.T, app *test.TestApp, subject string) {
				user := entity.User{Name: "Member", Email: "legacy@example.org"}
				require.NoError(t, app.Dao().DB().Create(&user).Error)
				now := time.Now()
				require.NoError(t, app.Dao().DB().Create(&entity.AuthIdentity{
					Provider: dao.OPDAIdentityProvider, RemoteUID: subject, UserID: user.ID, ConfirmedAt: &now,
				}).Error)
			},
		},
		{
			name: "duplicate forward binding",
			setup: func(t *testing.T, app *test.TestApp, subject string) {
				now := time.Now()
				for index := 0; index < 2; index++ {
					user := entity.User{Name: "Member", Email: opdaSyntheticEmail(subject)}
					require.NoError(t, app.Dao().DB().Create(&user).Error)
					require.NoError(t, app.Dao().DB().Create(&entity.AuthIdentity{
						Provider: dao.OPDAIdentityProvider, RemoteUID: subject, UserID: user.ID, ConfirmedAt: &now,
					}).Error)
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			app, fiberApp := newOPDATestAPI(t, opdaTestKeyHex)
			subject := "participant-invalid-binding"
			testCase.setup(t, app, subject)
			assertion := signOPDAAssertion(t, opdaClaims(time.Now().Unix(), subject, "Member", "ddb9d315-aeae-4cf5-a5c0-6a28f0475801"), opdaTestKey(t))
			resp, _ := postOPDAAssertion(t, fiberApp, assertion)
			assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		})
	}
}
