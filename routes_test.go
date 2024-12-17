package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleRefreshToken(t *testing.T) {
	app := &App{}
	err := app.initDBConnection()
	if err != nil {
		t.Fatalf("Ошибка подключения к базе данных: %v", err)
	}
	defer app.DB.Close()

	// Генерация и сохранение Refresh токена
	refreshToken, _ := generateBase64RefreshToken()
	hashedToken, _ := hashRefreshToken(refreshToken)
	app.SaveRefreshToken("test123", hashedToken)

	// Создание HTTP-запроса с изменённым IP-адресом
	req := httptest.NewRequest(http.MethodGet, "/refresh?refresh_token="+refreshToken, nil)
	req.Header.Set("X-Forwarded-For", "192.168.0.2") // Новый IP

	w := httptest.NewRecorder()

	// Используем MockEmailSender из routes.go
	mockEmailSender := &MockEmailSender{}
	app.handleRefreshToken(w, req, mockEmailSender)

	// Проверка результата
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Ожидался статус 200 OK, получен: %d", resp.StatusCode)
	}
}
