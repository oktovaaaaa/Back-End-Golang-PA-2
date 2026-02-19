// internal/models/user.go
package models

import "time"

type UserRole string
type UserStatus string

const (
	RoleOwner    UserRole = "OWNER"
	RoleAdmin    UserRole = "ADMIN"
	RoleEmployee UserRole = "EMPLOYEE"

	StatusPending  UserStatus = "PENDING"
	StatusActive   UserStatus = "ACTIVE"
	StatusRejected UserStatus = "REJECTED"
	StatusInactive UserStatus = "INACTIVE"
)

type User struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	CompanyID    uint       `gorm:"index;not null" json:"company_id"`
	Role         UserRole   `gorm:"type:varchar(20);not null" json:"role"`
	Status       UserStatus `gorm:"type:varchar(20);not null" json:"status"`
	FullName     string     `gorm:"not null" json:"full_name"`
	Email        string     `gorm:"uniqueIndex;not null" json:"email"`
	Phone        string     `json:"phone"`
	PasswordHash string     `gorm:"not null" json:"-"`

	TOTPSecret  string `json:"-"`
	TOTPEnabled bool   `gorm:"not null;default:false" json:"totp_enabled"`

	BoundDeviceID string `gorm:"type:varchar(64)" json:"-"`

	FailedLoginCount int        `gorm:"not null;default:0" json:"-"`
	LockoutLevel     int        `gorm:"not null;default:0" json:"-"`
	LockoutUntil     *time.Time `json:"-"`

	CreatedAt time.Time `json:"created_at"`
}
