package main

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGenerateBase64RefreshToken(t *testing.T) {
	token, err := generateBase64RefreshToken()
	if err != nil {
		t.Fatalf("Ошибка генерации Refresh токена: %v", err)
	}
	if len(token) == 0 {
		t.Errorf("Токен не должен быть пустым")
	}
}

func TestHashRefreshToken(t *testing.T) {
	token := "sample_refresh_token"
	hashedToken, err := hashRefreshToken(token)
	if err != nil {
		t.Fatalf("Ошибка хэширования токена: %v", err)
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(token))
	if err != nil {
		t.Errorf("Хэш не совпадает с оригинальным токеном: %v", err)
	}
}
