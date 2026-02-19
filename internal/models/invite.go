// internal/models/invite.go
package models

import "time"

type InviteStatus string

const (
	InviteUnused  InviteStatus = "UNUSED"
	InviteUsed    InviteStatus = "USED"
	InviteExpired InviteStatus = "EXPIRED"
)

type InviteToken struct {
	ID        uint         `gorm:"primaryKey" json:"id"`
	CompanyID uint         `gorm:"index;not null" json:"company_id"`
	Token     string       `gorm:"uniqueIndex;not null" json:"token"`
	Status    InviteStatus `gorm:"type:varchar(20);not null" json:"status"`
	ExpiresAt time.Time    `gorm:"index;not null" json:"expires_at"`
	CreatedBy uint         `gorm:"index;not null" json:"created_by"`
	CreatedAt time.Time    `json:"created_at"`
}
