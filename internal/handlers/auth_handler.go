// internal/handlers/auth_handler.go
package handlers

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"absensi_backend/internal/models"
	"absensi_backend/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

type AuthHandler struct {
	DB *gorm.DB
}

func NewAuthHandler(db *gorm.DB) *AuthHandler { return &AuthHandler{DB: db} }

// =========================
// Password policy (handler-only)
// =========================
func validatePasswordStrong(pw string) string {
	if len(pw) < 8 {
		return "password minimal 8 karakter"
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(pw) {
		return "password wajib mengandung huruf kecil (a-z)"
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(pw) {
		return "password wajib mengandung huruf besar (A-Z)"
	}
	if !regexp.MustCompile(`\d`).MatchString(pw) {
		return "password wajib mengandung angka (0-9)"
	}
	if !regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-=\[\]{};:"\\|,.<>\/\?` + "`" + `~]`).MatchString(pw) {
		return "password wajib mengandung karakter spesial (contoh: !@#)"
	}
	return ""
}

// =========================
// REGISTER ADMIN
// =========================
type RegisterAdminReq struct {
	FullName string `json:"full_name" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Phone    string `json:"phone"`
	Password string `json:"password" binding:"required"`

	CompanyName  string `json:"company_name" binding:"required"`
	CompanyEmail string `json:"company_email"`
	CompanyPhone string `json:"company_phone"`
	CompanyAddr  string `json:"company_address"`
}

func (h *AuthHandler) RegisterAdmin(c *gin.Context) {
	var req RegisterAdminReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body", "detail": err.Error()})
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.FullName = strings.TrimSpace(req.FullName)

	if req.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email required"})
		return
	}

	// password strength
	if msg := validatePasswordStrong(req.Password); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	var exists models.User
	if err := h.DB.Where("email = ?", req.Email).First(&exists).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email already used"})
		return
	}

	pwHash, err := utils.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash failed"})
		return
	}

	secret, otpauth, err := utils.GenerateTOTPSecret("AbsensiApp", req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "totp failed"})
		return
	}

	err = h.DB.Transaction(func(tx *gorm.DB) error {
		company := models.Company{
			Name:    strings.TrimSpace(req.CompanyName),
			Email:   strings.TrimSpace(req.CompanyEmail),
			Phone:   strings.TrimSpace(req.CompanyPhone),
			Address: strings.TrimSpace(req.CompanyAddr),
		}
		if err := tx.Create(&company).Error; err != nil {
			return err
		}

		admin := models.User{
			CompanyID:    company.ID,
			Role:         models.RoleOwner,
			Status:       models.StatusActive,
			FullName:     req.FullName,
			Email:        req.Email,
			Phone:        strings.TrimSpace(req.Phone),
			PasswordHash: pwHash,
			TOTPSecret:   secret,
			TOTPEnabled:  false,
		}
		if err := tx.Create(&admin).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "register failed", "detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": "admin registered. setup totp then login",
		"otpauth": otpauth,
	})
}

// =========================
// REGISTER EMPLOYEE
// =========================
type RegisterEmployeeReq struct {
	InviteToken string `json:"invite_token" binding:"required"`
	FullName    string `json:"full_name" binding:"required"`
	Email       string `json:"email" binding:"required"`
	Phone       string `json:"phone"`
	Password    string `json:"password" binding:"required"`
}

func (h *AuthHandler) RegisterEmployee(c *gin.Context) {
	var req RegisterEmployeeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body", "detail": err.Error()})
		return
	}

	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.InviteToken = strings.TrimSpace(req.InviteToken)
	req.FullName = strings.TrimSpace(req.FullName)

	if req.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email required"})
		return
	}

	// password strength
	if msg := validatePasswordStrong(req.Password); msg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	var inv models.InviteToken
	if err := h.DB.Where("token = ?", req.InviteToken).First(&inv).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invite invalid"})
		return
	}
	if inv.Status != models.InviteUnused {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invite already used/expired"})
		return
	}
	if time.Now().After(inv.ExpiresAt) {
		inv.Status = models.InviteExpired
		_ = h.DB.Save(&inv).Error
		c.JSON(http.StatusBadRequest, gin.H{"error": "invite expired"})
		return
	}

	var exists models.User
	if err := h.DB.Where("email = ?", req.Email).First(&exists).Error; err == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email already used"})
		return
	}

	pwHash, err := utils.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash failed"})
		return
	}

	secret, otpauth, err := utils.GenerateTOTPSecret("AbsensiApp", req.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "totp failed"})
		return
	}

	err = h.DB.Transaction(func(tx *gorm.DB) error {
		emp := models.User{
			CompanyID:    inv.CompanyID,
			Role:         models.RoleEmployee,
			Status:       models.StatusPending,
			FullName:     req.FullName,
			Email:        req.Email,
			Phone:        strings.TrimSpace(req.Phone),
			PasswordHash: pwHash,
			TOTPSecret:   secret,
			TOTPEnabled:  false,
		}
		if err := tx.Create(&emp).Error; err != nil {
			return err
		}

		inv.Status = models.InviteUsed
		if err := tx.Save(&inv).Error; err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "register failed", "detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": "registered. wait admin approve. setup totp now",
		"otpauth": otpauth,
	})
}

// =========================
// VERIFY TOTP SETUP
// =========================
type VerifyTotpReq struct {
	Email string `json:"email" binding:"required"`
	Code  string `json:"code" binding:"required"`
}

func (h *AuthHandler) VerifyTOTPSetup(c *gin.Context) {
	var req VerifyTotpReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	code := strings.TrimSpace(req.Code)

	var u models.User
	if err := h.DB.Where("email = ?", email).First(&u).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}
	if u.TOTPSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "totp not initialized"})
		return
	}

	// FIX: VerifyTOTP(code, secret)  (sebelumnya kebalik)
	if !utils.VerifyTOTP(code, u.TOTPSecret) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid totp"})
		return
	}

	u.TOTPEnabled = true
	if err := h.DB.Save(&u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "save failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "totp enabled"})
}

// =========================
// LOGIN
// =========================
type LoginReq struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	// NOTE: TOTPCode sekarang OPTIONAL (tidak binding required),
	// karena hanya WAJIB saat first-login (device binding pertama).
	TOTPCode string `json:"totp_code"`
	DeviceID string `json:"device_id" binding:"required"`
}

func lockMinutes(level int) int {
	if level <= 0 {
		return 5
	}
	return 5 * (level + 1)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body", "detail": err.Error()})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	deviceID := strings.TrimSpace(req.DeviceID)
	totp := strings.TrimSpace(req.TOTPCode)

	var u models.User
	if err := h.DB.Where("email = ?", email).First(&u).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if u.Status == models.StatusPending {
		c.JSON(http.StatusForbidden, gin.H{"error": "account pending admin approval"})
		return
	}
	if u.Status != models.StatusActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "account not active"})
		return
	}

	if u.LockoutUntil != nil && time.Now().Before(*u.LockoutUntil) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "locked", "until": u.LockoutUntil})
		return
	}

	if !utils.CheckPassword(u.PasswordHash, req.Password) {
		u.FailedLoginCount++
		if u.FailedLoginCount >= 5 {
			u.LockoutLevel++
			mins := lockMinutes(u.LockoutLevel - 1)
			t := time.Now().Add(time.Duration(mins) * time.Minute)
			u.LockoutUntil = &t
			u.FailedLoginCount = 0
		}
		_ = h.DB.Save(&u).Error
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Single-device check
	if u.BoundDeviceID != "" && u.BoundDeviceID != deviceID {
		c.JSON(http.StatusForbidden, gin.H{"error": "account already active on another device"})
		return
	}

	// TOTP rules:
	// - Saat first-login (belum ada bound device) => WAJIB TOTP enabled + valid
	// - Setelah bound device ada => TOTP tidak wajib (boleh kosong)
	if u.BoundDeviceID == "" {
		if !u.TOTPEnabled {
			c.JSON(http.StatusForbidden, gin.H{"error": "totp not enabled"})
			return
		}
		if totp == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "totp required for first login"})
			return
		}
		// FIX: VerifyTOTP(code, secret)
		if !utils.VerifyTOTP(totp, u.TOTPSecret) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid totp"})
			return
		}
		// bind device on first success
		u.BoundDeviceID = deviceID
	}

	// reset lock counters on successful login
	u.FailedLoginCount = 0
	u.LockoutUntil = nil
	_ = h.DB.Save(&u).Error

	secret := os.Getenv("JWT_SECRET")
	claims := jwt.MapClaims{
		"user_id":    u.ID,
		"company_id": u.CompanyID,
		"role":       string(u.Role),
		"exp":        time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "sign token failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"token":  signed,
		"user": gin.H{
			"id":         u.ID,
			"company_id": u.CompanyID,
			"role":       u.Role,
			"full_name":  u.FullName,
			"email":      u.Email,
		},
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	userIDAny, ok := c.Get("user_id")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user"})
		return
	}
	userID, ok := userIDAny.(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user"})
		return
	}

	var u models.User
	if err := h.DB.First(&u, userID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user not found"})
		return
	}

	u.BoundDeviceID = ""
	if err := h.DB.Save(&u).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
