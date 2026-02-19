// internal/handlers/admin_handler.go
package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"absensi_backend/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type AdminHandler struct {
	DB *gorm.DB
}

func NewAdminHandler(db *gorm.DB) *AdminHandler { return &AdminHandler{DB: db} }

type InviteReq struct {
	MinutesValid int `json:"minutes_valid"`
}

func (h *AdminHandler) GenerateInvite(c *gin.Context) {
	var req InviteReq
	_ = c.ShouldBindJSON(&req)
	if req.MinutesValid <= 0 {
		req.MinutesValid = 60
	}

	companyID := c.GetUint("company_id")
	adminID := c.GetUint("user_id")

	token := uuid.NewString()
	inv := models.InviteToken{
		CompanyID: companyID,
		Token:     token,
		Status:    models.InviteUnused,
		ExpiresAt: time.Now().Add(time.Duration(req.MinutesValid) * time.Minute),
		CreatedBy: adminID,
	}

	if err := h.DB.Create(&inv).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create invite failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "token": token, "expires_at": inv.ExpiresAt})
}

func (h *AdminHandler) ListPendingEmployees(c *gin.Context) {
	companyID := c.GetUint("company_id")

	var rows []models.User
	if err := h.DB.Where("company_id = ? AND role = ? AND status = ?",
		companyID, models.RoleEmployee, models.StatusPending).
		Order("created_at asc").Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "load failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "data": rows})
}

func (h *AdminHandler) ApproveEmployee(c *gin.Context) {
	companyID := c.GetUint("company_id")

	idStr := strings.TrimSpace(c.Param("id"))
	id64, _ := strconv.ParseUint(idStr, 10, 64)
	id := uint(id64)

	var u models.User
	if err := h.DB.Where("company_id = ? AND id = ?", companyID, id).First(&u).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}

	u.Status = models.StatusActive
	if err := h.DB.Save(&u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "approve failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *AdminHandler) RejectEmployee(c *gin.Context) {
	companyID := c.GetUint("company_id")

	idStr := strings.TrimSpace(c.Param("id"))
	id64, _ := strconv.ParseUint(idStr, 10, 64)
	id := uint(id64)

	var u models.User
	if err := h.DB.Where("company_id = ? AND id = ?", companyID, id).First(&u).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}

	u.Status = models.StatusRejected
	if err := h.DB.Save(&u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reject failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *AdminHandler) ResetDeviceBinding(c *gin.Context) {
	companyID := c.GetUint("company_id")

	idStr := strings.TrimSpace(c.Param("id"))
	id64, _ := strconv.ParseUint(idStr, 10, 64)
	id := uint(id64)

	var u models.User
	if err := h.DB.Where("company_id = ? AND id = ?", companyID, id).First(&u).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}

	u.BoundDeviceID = ""
	if err := h.DB.Save(&u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reset failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
