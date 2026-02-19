package models

import "time"

type Attendance struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	EmployeeID string   `gorm:"index;not null" json:"employee_id"`
	Type      string    `gorm:"not null" json:"type"` // "checkin" / "checkout"
	DeviceID   string   `gorm:"index" json:"device_id"`
	Latitude   *float64 `json:"latitude,omitempty"`
	Longitude  *float64 `json:"longitude,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}
