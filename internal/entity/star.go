package entity

import "time"

// Star is a private bookmark owned by an authenticated Artalk user.
// Content identity includes the immutable provider artefact and optional slide.
type Star struct {
	UserID    uint      `gorm:"primaryKey" json:"-"`
	SiteName  string    `gorm:"primaryKey;size:128" json:"-"`
	Key       string    `gorm:"primaryKey;size:2048" json:"key"`
	Title     string    `json:"title"`
	Kind      string    `json:"kind"`
	Href      string    `json:"href"`
	UpdatedAt time.Time `json:"updated_at"`
}
