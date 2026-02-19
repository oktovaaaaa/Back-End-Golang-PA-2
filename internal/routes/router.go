// internal/routes/router.go
package routes

import (
	"absensi_backend/internal/handlers"
	"absensi_backend/internal/middleware"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func NewRouter(db *gorm.DB) *gin.Engine {
	r := gin.Default()

	authH := handlers.NewAuthHandler(db)
	adminH := handlers.NewAdminHandler(db)

	api := r.Group("/api/v1")
	{
		api.POST("/auth/admin/register", authH.RegisterAdmin)
		api.POST("/auth/employee/register", authH.RegisterEmployee)
		api.POST("/auth/totp/verify", authH.VerifyTOTPSetup)
		api.POST("/auth/login", authH.Login)
		api.POST("/auth/logout", middleware.AuthRequired(), authH.Logout)
	}

	admin := r.Group("/api/v1/admin")
	admin.Use(middleware.AuthRequired(), middleware.RequireAdmin())
	{
		admin.POST("/invite", adminH.GenerateInvite)
		admin.GET("/employees/pending", adminH.ListPendingEmployees)
		admin.POST("/employees/:id/approve", adminH.ApproveEmployee)
		admin.POST("/employees/:id/reject", adminH.RejectEmployee)
		admin.POST("/employees/:id/reset-device", adminH.ResetDeviceBinding)
	}

	return r
}
