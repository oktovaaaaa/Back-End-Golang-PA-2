// cmd/server/main.go
package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"

	"absensi_backend/internal/routes"
	"absensi_backend/internal/storage"
)

func main() {
	_ = godotenv.Load()

	db := storage.OpenDB()
	r := routes.NewRouter(db)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	addr := ":" + port
	log.Printf("Server running on %s", addr)

	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}
