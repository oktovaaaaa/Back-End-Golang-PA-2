// internal/handlers/health.go
package handlers

	import "github.com/gin-gonic/gin"

	func Health(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
			"message": "absensi backend is running",
		})
	}
