package dao

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/artalkjs/artalk/v2/internal/entity"
	"gorm.io/gorm"
)

const OPDAIdentityProvider = "opda-participant"

var (
	ErrOPDAIdentityBinding = errors.New("invalid OPDA participant identity binding")
	opdaIdentityMu         sync.Mutex
)

// ResolveOPDAParticipantUser returns the user bound to the immutable OPDA
// participant ID, creating a distinct non-admin user on first use. The process
// lock complements the database transaction for Artalk's single-writer runtime.
func (dao *Dao) ResolveOPDAParticipantUser(
	remoteUID string,
	name string,
	email string,
	now time.Time,
) (entity.User, error) {
	opdaIdentityMu.Lock()
	defer opdaIdentityMu.Unlock()

	var user entity.User
	var previousUser *entity.User
	err := dao.DB().Transaction(func(tx *gorm.DB) error {
		var identities []entity.AuthIdentity
		if err := tx.Unscoped().Where(
			"provider = ? AND remote_uid = ?", OPDAIdentityProvider, remoteUID,
		).Find(&identities).Error; err != nil {
			return err
		}

		if len(identities) > 1 {
			return ErrOPDAIdentityBinding
		}
		if len(identities) == 1 {
			identity := identities[0]
			if identity.DeletedAt.Valid || identity.UserID == 0 || identity.Token != "" || identity.ConfirmedAt == nil {
				return ErrOPDAIdentityBinding
			}

			var bindingCount int64
			if err := tx.Unscoped().Model(&entity.AuthIdentity{}).Where(
				"user_id = ?", identity.UserID,
			).Count(&bindingCount).Error; err != nil {
				return err
			}
			if bindingCount != 1 {
				return ErrOPDAIdentityBinding
			}

			if err := tx.First(&user, identity.UserID).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ErrOPDAIdentityBinding
				}
				return err
			}
			if user.Email != email || user.IsAdmin {
				return ErrOPDAIdentityBinding
			}

			old := user
			previousUser = &old
			if user.Name != name || user.ReceiveEmail {
				if err := tx.Model(&user).Updates(map[string]any{
					"name":          name,
					"receive_email": false,
				}).Error; err != nil {
					return err
				}
				user.Name = name
				user.ReceiveEmail = false
			}
			return nil
		}

		user = entity.User{
			Name:         name,
			Email:        email,
			IsAdmin:      false,
			ReceiveEmail: false,
		}
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		// GORM applies the model's default=true to a false boolean during Create.
		if err := tx.Model(&user).Updates(map[string]any{
			"is_admin":      false,
			"receive_email": false,
		}).Error; err != nil {
			return err
		}
		user.IsAdmin = false
		user.ReceiveEmail = false

		confirmedAt := now.UTC()
		identity := entity.AuthIdentity{
			Provider:    OPDAIdentityProvider,
			RemoteUID:   remoteUID,
			UserID:      user.ID,
			ConfirmedAt: &confirmedAt,
		}
		if err := tx.Create(&identity).Error; err != nil {
			return fmt.Errorf("create OPDA participant identity: %w", err)
		}
		return nil
	})
	if err != nil {
		return entity.User{}, err
	}

	dao.CacheAction(func(cache *DaoCache) {
		if previousUser != nil {
			cache.UserCacheDel(previousUser)
		}
		_ = cache.UserCacheSave(&user)
	})
	return user, nil
}
