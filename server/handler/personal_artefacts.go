package handler

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync"

	"github.com/artalkjs/artalk/v2/internal/core"
	"github.com/artalkjs/artalk/v2/internal/entity"
	"github.com/artalkjs/artalk/v2/server/common"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Serialize explicit vote transitions, including counts, in this single native owner.
var personalVoteMu sync.Mutex
var personalStarMu sync.Mutex

func personalPath(value string) bool {
	u, err := url.Parse(value)
	return err == nil && len(value) > 0 && len(value) <= 2048 && strings.HasPrefix(value, "/") &&
		!strings.HasPrefix(value, "//") && !strings.ContainsAny(value, "\\\r\n\x00") &&
		!strings.Contains(u.Path, "..") && u.Host == "" && u.Scheme == ""
}

func personalBody(c *fiber.Ctx, target any) bool {
	if len(c.Body()) > 12000 {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(string(c.Body())))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil
}

// PersonalArtefacts extends the existing native store and bearer identity.
// Neither an owner ID nor an email is accepted from the caller.
func PersonalArtefacts(app *core.App, router fiber.Router) {
	router.All("/opda/stars", func(c *fiber.Ctx) error {
		user, err := common.GetUserByReq(app, c)
		if err != nil || user.IsEmpty() {
			return common.RespError(c, 401, "Sign in required")
		}
		site := c.Query("site_name")
		if site == "" || len(site) > 128 || app.Dao().FindSite(site).IsEmpty() {
			return common.RespError(c, 400, "Invalid site")
		}
		personalStarMu.Lock()
		defer personalStarMu.Unlock()
		db := app.Dao().DB()
		scope := func() *gorm.DB { return db.Model(&entity.Star{}).Where("user_id = ? AND site_name = ?", user.ID, site) }
		if c.Method() == "GET" {
			rows := []entity.Star{}
			if scope().Order("updated_at DESC, key ASC").Limit(1001).Find(&rows).Error != nil {
				return common.RespError(c, 503, "Unavailable")
			}
			return common.RespData(c, Map{"items": rows})
		}
		var body struct {
			Key   string `json:"key"`
			Title string `json:"title"`
			Kind  string `json:"kind"`
			Href  string `json:"href"`
		}
		if !personalBody(c, &body) || !personalPath(body.Key) {
			return common.RespError(c, 400, "Invalid star")
		}
		if c.Method() == "DELETE" {
			if scope().Where("key = ?", body.Key).Delete(&entity.Star{}).Error != nil {
				return common.RespError(c, 503, "Unavailable")
			}
			return common.RespData(c, Map{"starred": false})
		}
		if c.Method() != "PUT" {
			return common.RespError(c, 405, "Use GET, PUT or DELETE")
		}
		if !personalPath(body.Href) || len(body.Title) < 1 || len(body.Title) > 1000 ||
			!strings.Contains("|slide|slide_deck|audio|video|infographic|", "|"+body.Kind+"|") || body.Kind == "" {
			return common.RespError(c, 400, "Invalid star")
		}
		var count int64
		if scope().Where("key <> ?", body.Key).Count(&count).Error != nil || count >= 1000 {
			return common.RespError(c, 409, "Saved item limit reached")
		}
		star := entity.Star{UserID: user.ID, SiteName: site, Key: body.Key, Title: body.Title, Kind: body.Kind, Href: body.Href}
		if db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&star).Error != nil {
			return common.RespError(c, 503, "Unavailable")
		}
		return common.RespData(c, Map{"starred": true})
	})
	router.All("/opda/comment-vote/:id", func(c *fiber.Ctx) error {
		user, err := common.GetUserByReq(app, c)
		if err != nil || user.IsEmpty() {
			return common.RespError(c, 401, "Sign in required")
		}
		id, err := c.ParamsInt("id")
		if err != nil || id < 1 {
			return common.RespError(c, 400, "Invalid comment")
		}
		comment := app.Dao().FindComment(uint(id))
		if comment.IsEmpty() || comment.IsPending {
			return common.RespError(c, 404, "Unavailable comment")
		}
		personalVoteMu.Lock()
		defer personalVoteMu.Unlock()
		db := app.Dao().DB()
		scope := func(tx *gorm.DB) *gorm.DB {
			return tx.Where("user_id = ? AND target_id = ? AND type IN ?", user.ID, id, []string{"comment_up", "comment_down"})
		}
		if c.Method() == "PUT" {
			var body struct {
				Choice string `json:"choice"`
			}
			if !personalBody(c, &body) || (body.Choice != "" && body.Choice != "up" && body.Choice != "down") {
				return common.RespError(c, 400, "Invalid choice")
			}
			err = db.Transaction(func(tx *gorm.DB) error {
				if e := scope(tx).Unscoped().Delete(&entity.Vote{}).Error; e != nil {
					return e
				}
				if body.Choice != "" {
					return tx.Create(&entity.Vote{UserID: user.ID, TargetID: uint(id), Type: entity.VoteType("comment_" + body.Choice)}).Error
				}
				return nil
			})
			if err != nil {
				return common.RespError(c, 503, "Unavailable")
			}
		} else if c.Method() != "GET" {
			return common.RespError(c, 405, "Use GET or PUT")
		}
		var votes []entity.Vote
		if scope(db).Find(&votes).Error != nil {
			return common.RespError(c, 503, "Unavailable")
		}
		up, down := app.Dao().GetVoteNumUpDown("comment", uint(id))
		if c.Method() == "PUT" {
			db.Model(&entity.Comment{}).Where("id = ?", id).Updates(Map{"vote_up": up, "vote_down": down})
		}
		choice := ""
		if len(votes) > 0 {
			choice = strings.TrimPrefix(string(votes[0].Type), "comment_")
		}
		return common.RespData(c, Map{"up": up, "down": down, "choice": choice})
	})
}
