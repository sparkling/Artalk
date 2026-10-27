package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/artalkjs/artalk/v2/internal/entity"
	"github.com/artalkjs/artalk/v2/server/common"
	"github.com/artalkjs/artalk/v2/server/handler"
	"github.com/stretchr/testify/require"
)

func TestPersonalArtefactsPersistAndIsolateUsers(t *testing.T) {
	app, api := newOPDATestAPI(t, opdaTestKeyHex)
	handler.PersonalArtefacts(app.App, api.Group("/api/v2"))
	app.Dao().FindCreateSite("AI", "https://example.invalid")
	first := entity.User{Name: "First", Email: "first@example.invalid"}
	second := entity.User{Name: "Second", Email: "second@example.invalid"}
	require.NoError(t, app.Dao().CreateUser(&first))
	require.NoError(t, app.Dao().CreateUser(&second))
	a, err := common.LoginGetUserToken(first, app.Conf().AppKey, 60)
	require.NoError(t, err)
	b, err := common.LoginGetUserToken(second, app.Conf().AppKey, 60)
	require.NoError(t, err)
	invoke := func(method, path, token string, body any) (int, map[string]any) {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(method, "/api/v2/opda/"+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, e := api.Test(req)
		require.NoError(t, e)
		defer res.Body.Close()
		data, e := io.ReadAll(res.Body)
		require.NoError(t, e)
		var result map[string]any
		require.NoError(t, json.Unmarshal(data, &result), string(data))
		return res.StatusCode, result
	}
	key := "/custody/generation/notebook/provider.pdf"
	body := map[string]any{"key": key, "kind": "slide_deck", "href": "/n01/?deck=provider&slide=1", "title": "Chapter › Deck"}
	for range 2 {
		code, _ := invoke("PUT", "stars?site_name=AI", a, body)
		require.Equal(t, 200, code)
	}
	for _, token := range []string{a, b} {
		code, data := invoke("GET", "stars?site_name=AI", token, nil)
		require.Equal(t, 200, code)
		rows := data["items"].([]any)
		if token == a {
			require.Len(t, rows, 1)
		} else {
			require.Empty(t, rows)
		}
	}
	code, _ := invoke("GET", "stars?site_name=AI", "", nil)
	require.Equal(t, 401, code)
	forged := map[string]any{"key": key, "user_id": first.ID}
	code, _ = invoke("DELETE", "stars?site_name=AI", b, forged)
	require.Equal(t, 400, code)
	for _, token := range []string{b, a, a} {
		code, _ = invoke("DELETE", "stars?site_name=AI", token, map[string]any{"key": key})
		require.Equal(t, 200, code)
	}
	comment := entity.Comment{Content: "Feedback target", SiteName: "AI", PageKey: "/n01/", UserID: first.ID}
	require.NoError(t, app.Dao().DB().Create(&comment).Error)
	path := fmt.Sprintf("comment-vote/%d", comment.ID)
	for _, choice := range []string{"up", "up", "down", "down", ""} {
		code, data := invoke("PUT", path, a, map[string]any{"choice": choice})
		require.Equal(t, 200, code)
		require.Equal(t, choice, data["choice"])
		wantUp, wantDown := float64(0), float64(0)
		if choice == "up" {
			wantUp = 1
		}
		if choice == "down" {
			wantDown = 1
		}
		require.Equal(t, wantUp, data["up"])
		require.Equal(t, wantDown, data["down"])
	}
	code, _ = invoke("PUT", path, a, map[string]any{"choice": "up"})
	require.Equal(t, 200, code)
	code, data := invoke("GET", path, b, nil)
	require.Equal(t, 200, code)
	require.Equal(t, "", data["choice"])
	require.Equal(t, float64(1), data["up"])
	// Empty resources can receive feedback without a synthetic comment. Native
	// page vote types remain distinct from comment types, deck and slide pages.
	resource := "resource-vote?" + url.Values{"site_name": {"AI"}, "page_key": {key + "#slide-002"}, "page_title": {"Deck › Slide 2"}}.Encode()
	code, data = invoke("GET", resource, a, nil)
	require.Equal(t, 200, code)
	require.Equal(t, "", data["choice"])
	require.True(t, app.Dao().FindPage(key+"#slide-002", "AI").IsEmpty())
	for _, choice := range []string{"up", "up", "down", "down", ""} {
		code, data = invoke("PUT", resource, a, map[string]any{"choice": choice})
		require.Equal(t, 200, code)
		require.Equal(t, choice, data["choice"])
		code, read := invoke("GET", resource, a, nil)
		require.Equal(t, 200, code)
		require.Equal(t, data, read)
	}
	code, _ = invoke("PUT", resource, a, map[string]any{"choice": "up"})
	require.Equal(t, 200, code)
	code, data = invoke("GET", resource, b, nil)
	require.Equal(t, 200, code)
	require.Equal(t, "", data["choice"])
	require.Equal(t, float64(1), data["up"])
	code, data = invoke("GET", "resource-vote?"+url.Values{"site_name": {"AI"}, "page_key": {key}}.Encode(), a, nil)
	require.Equal(t, 200, code)
	require.Equal(t, float64(0), data["up"])
	code, _ = invoke("GET", resource, "", nil)
	require.Equal(t, 401, code)
	code, _ = invoke("PUT", resource, b, map[string]any{"choice": "up", "user_id": first.ID})
	require.Equal(t, 400, code)
	// Concurrent additions cannot cross the bounded list's admission limit.
	seed := make([]entity.Star, 999)
	for i := range seed {
		seed[i] = entity.Star{UserID: first.ID, SiteName: "AI", Key: fmt.Sprintf("/seed/%d.pdf", i), Kind: "slide_deck", Title: "Seed", Href: "/n01/"}
	}
	require.NoError(t, app.Dao().DB().CreateInBatches(seed, 100).Error)
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			code, _ := invoke("PUT", "stars?site_name=AI", a, map[string]any{"key": fmt.Sprintf("/new/%d.pdf", index), "kind": "slide_deck", "title": "Concurrent", "href": "/n01/"})
			codes <- code
		}(i)
	}
	wg.Wait()
	close(codes)
	accepted := 0
	for code := range codes {
		if code == 200 {
			accepted++
		} else {
			require.Equal(t, 409, code)
		}
	}
	require.Equal(t, 1, accepted)
}
