package utils

import (
	"errors"
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// ValidatePasswordStrong enforces:
// - min 8 chars
// - at least 1 lowercase
// - at least 1 uppercase
// - at least 1 digit
// - at least 1 special character
func ValidatePasswordStrong(pw string) error {
	if len(pw) < 8 {
		return errors.New("password minimal 8 karakter")
	}
	if !regexp.MustCompile(`[a-z]`).MatchString(pw) {
		return errors.New("password wajib mengandung huruf kecil (a-z)")
	}
	if !regexp.MustCompile(`[A-Z]`).MatchString(pw) {
		return errors.New("password wajib mengandung huruf besar (A-Z)")
	}
	if !regexp.MustCompile(`\d`).MatchString(pw) {
		return errors.New("password wajib mengandung angka (0-9)")
	}
	// Special characters set (common)
	if !regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-=\[\]{};:"\\|,.<>\/\?` + "`" + `~]`).MatchString(pw) {
		return errors.New("password wajib mengandung karakter spesial (contoh: !@#)")
	}
	return nil
}
