package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/artalkjs/artalk/v2/internal/entity"
	"github.com/artalkjs/artalk/v2/server/handler"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func postComment(
	t *testing.T,
	fiberApp *fiber.App,
	token string,
	body map[string]any,
) (*http.Response, []byte) {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v2/comments", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := fiberApp.Test(req)
	require.NoError(t, err)
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, responseBody
}

func TestAuthOPDASessionDrivesAuthenticatedCommentLifecycle(t *testing.T) {
	app, fiberApp := newOPDATestAPI(t, opdaTestKeyHex)
	app.Conf().Auth.Enabled = true
	app.Conf().Auth.Anonymous = false
	app.Conf().Captcha.Enabled = false
	app.Dao().FindCreateSite("OPDA", "https://opda.org.uk")

	api := fiberApp.Group("/api/v2")
	handler.CommentCreate(app.App, api)
	handler.CommentList(app.App, api)

	legacy := entity.User{
		Name: "Shared Display Name", Email: "existing-member@example.org", ReceiveEmail: false,
	}
	require.NoError(t, app.Dao().CreateUser(&legacy))

	assertion := signOPDAAssertion(t, opdaClaims(
		time.Now().Unix(),
		"participant-comment-lifecycle",
		legacy.Name,
		"cb5b21e1-156a-4ddc-be52-f08161667398",
	), opdaTestKey(t))
	exchangeResp, exchangeBody := postOPDAAssertion(t, fiberApp, assertion)
	require.Equal(t, http.StatusOK, exchangeResp.StatusCode, string(exchangeBody))
	login := decodeOPDALogin(t, exchangeBody)
	require.NotEmpty(t, login.Token)
	require.NotZero(t, login.User.ID)
	assert.NotEqual(t, legacy.ID, login.User.ID)
	assert.Equal(t, legacy.Name, login.User.Name)
	assert.Equal(t, opdaSyntheticEmail("participant-comment-lifecycle"), login.User.Email)
	assert.False(t, login.User.IsAdmin)

	commentBody := map[string]any{
		"name":       login.User.Name,
		"email":      login.User.Email,
		"content":    "First gateway-backed comment.",
		"page_key":   "/integration/opda-comments",
		"page_title": "OPDA comments integration",
		"site_name":  "OPDA",
	}
	rootResp, rootBody := postComment(t, fiberApp, login.Token, commentBody)
	require.Equal(t, http.StatusOK, rootResp.StatusCode, string(rootBody))
	var root handler.ResponseCommentCreate
	require.NoError(t, json.Unmarshal(rootBody, &root))
	require.NotZero(t, root.ID)
	assert.Zero(t, root.Rid)
	assert.Equal(t, login.User.ID, root.UserID)
	assert.Equal(t, login.User.Name, root.Nick)

	replyBody := map[string]any{}
	for key, value := range commentBody {
		replyBody[key] = value
	}
	replyBody["content"] = "Reply through the same server-side session."
	replyBody["rid"] = root.ID
	replyResp, replyResponseBody := postComment(t, fiberApp, login.Token, replyBody)
	require.Equal(t, http.StatusOK, replyResp.StatusCode, string(replyResponseBody))
	var reply handler.ResponseCommentCreate
	require.NoError(t, json.Unmarshal(replyResponseBody, &reply))
	require.NotZero(t, reply.ID)
	assert.Equal(t, root.ID, reply.Rid)
	assert.Equal(t, login.User.ID, reply.UserID)

	query := url.Values{
		"page_key":  {"/integration/opda-comments"},
		"site_name": {"OPDA"},
		"limit":     {"50"},
		"offset":    {"0"},
		"flat_mode": {"true"},
		"sort_by":   {"date_asc"},
	}
	listReq := httptest.NewRequest(http.MethodGet, "/api/v2/comments?"+query.Encode(), nil)
	listReq.Header.Set("Authorization", "Bearer "+login.Token)
	listResp, err := fiberApp.Test(listReq)
	require.NoError(t, err)
	listBody, err := io.ReadAll(listResp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, listResp.StatusCode, string(listBody))
	var list handler.ResponseCommentList
	require.NoError(t, json.Unmarshal(listBody, &list))
	assert.Equal(t, int64(2), list.Count)
	assert.Equal(t, int64(1), list.RootsCount)
	require.Len(t, list.Comments, 2)
	assert.Equal(t, root.ID, list.Comments[0].ID)
	assert.Equal(t, uint(0), list.Comments[0].Rid)
	assert.Equal(t, reply.ID, list.Comments[1].ID)
	assert.Equal(t, root.ID, list.Comments[1].Rid)
	assert.Equal(t, login.User.ID, list.Comments[0].UserID)
	assert.Equal(t, login.User.ID, list.Comments[1].UserID)

	anonymousBody := map[string]any{}
	for key, value := range commentBody {
		anonymousBody[key] = value
	}
	anonymousBody["content"] = "This must not be stored."
	anonymousResp, anonymousResponseBody := postComment(t, fiberApp, "", anonymousBody)
	assert.Equal(t, http.StatusInternalServerError, anonymousResp.StatusCode, string(anonymousResponseBody))

	var storedCount int64
	require.NoError(t, app.Dao().DB().Model(&entity.Comment{}).Where(
		"page_key = ? AND site_name = ?", "/integration/opda-comments", "OPDA",
	).Count(&storedCount).Error)
	assert.Equal(t, int64(2), storedCount, fmt.Sprintf("anonymous response: %s", anonymousResponseBody))

	var preserved entity.User
	require.NoError(t, app.Dao().DB().First(&preserved, legacy.ID).Error)
	assert.Equal(t, "existing-member@example.org", preserved.Email)
	assert.False(t, preserved.IsAdmin)
}
