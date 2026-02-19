// internal/handlers/attendance.go
package handlers

import (
	"net/http"
	"strings"

	"absensi_backend/internal/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AttendanceHandler struct {
	DB *gorm.DB
}

type AttendanceRequest struct {
	EmployeeID string   `json:"employee_id" binding:"required"`
	DeviceID   string   `json:"device_id" binding:"required"`
	Latitude   *float64 `json:"latitude"`
	Longitude  *float64 `json:"longitude"`
}

func NewAttendanceHandler(db *gorm.DB) *AttendanceHandler {
	return &AttendanceHandler{DB: db}
}

func (h *AttendanceHandler) CheckIn(c *gin.Context)  { h.createAttendance(c, "checkin") }
func (h *AttendanceHandler) CheckOut(c *gin.Context) { h.createAttendance(c, "checkout") }

func (h *AttendanceHandler) createAttendance(c *gin.Context, typ string) {
	var req AttendanceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body", "detail": err.Error()})
		return
	}

	req.EmployeeID = strings.TrimSpace(req.EmployeeID)
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	if req.EmployeeID == "" || req.DeviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "employee_id and device_id required"})
		return
	}

	row := models.Attendance{
		EmployeeID: req.EmployeeID,
		Type:       typ,
		DeviceID:   req.DeviceID,
		Latitude:   req.Latitude,
		Longitude:  req.Longitude,
	}

	if err := h.DB.Create(&row).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save", "detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"data":   row,
	})
}

func (h *AttendanceHandler) ListByEmployee(c *gin.Context) {
	employeeID := strings.TrimSpace(c.Param("employee_id"))
	if employeeID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "employee_id required"})
		return
	}

	var rows []models.Attendance
	if err := h.DB.Where("employee_id = ?", employeeID).Order("created_at desc").Limit(50).Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load", "detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "data": rows})
}
