package main

import (
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// EmailSender интерфейс для отправки email
type EmailSender interface {
	SendEmail(to, subject, body string) error
}

// MockEmailSender - моковая отправка email (для разработки и тестов)
type MockEmailSender struct{}

func (m *MockEmailSender) SendEmail(to, subject, body string) error {
	// Логируем вызов вместо реальной отправки
	log.Printf("Моковая отправка email: To=%s, Subject=%s, Body=%s", to, subject, body)
	return nil
}

func (a *App) handleRefreshToken(w http.ResponseWriter, r *http.Request, emailSender EmailSender) {
	refreshToken := r.URL.Query().Get("refresh_token")
	if refreshToken == "" {
		http.Error(w, "Refresh токен отсутствует", http.StatusBadRequest)
		return
	}

	userID := "test123"
	hashedToken, err := a.GetUserIDByRefreshToken(userID)
	if err != nil {
		http.Error(w, "Токен не найден", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(refreshToken))
	if err != nil {
		http.Error(w, "Неверный Refresh токен", http.StatusUnauthorized)
		return
	}

	ipAddress := getIP(r)
	oldIP := "192.168.0.1" // Моковый старый IP
	if ipAddress != oldIP {
		log.Printf("IP изменён: старый %s, новый %s", oldIP, ipAddress)

		// Отправка email через EmailSender
		email := "test@example.com"
		subject := "Внимание: Изменение IP-адреса"
		body := fmt.Sprintf("Ваш IP-адрес изменился с %s на %s.", oldIP, ipAddress)

		if err := emailSender.SendEmail(email, subject, body); err != nil {
			log.Printf("Ошибка отправки email: %v", err)
			http.Error(w, "Ошибка отправки email уведомления", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "IP изменён. Уведомление отправлено на email.")
		return
	}

	// Генерация новых токенов
	newRefreshToken, _ := generateBase64RefreshToken()
	newHashedToken, _ := hashRefreshToken(newRefreshToken)
	a.SaveRefreshToken(userID, newHashedToken)

	newAccessToken, _ := generateAccessToken(userID, ipAddress)
	fmt.Fprintf(w, "Новый Access токен: %s\nНовый Refresh токен: %s", newAccessToken, newRefreshToken)
}
