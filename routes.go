package main

import (
	"fmt"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// Моковые данные для email и IP
var mockOldIP = "192.168.0.1"
var mockNewIP = "192.168.0.2"
var mockEmail = "testusergo@gmail.com"

// handleTokenRequest — маршрут для получения Access токена
func (a *App) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	userID, err := extractUserID(r)
	if err != nil {
		log.Printf("Ошибка: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ipAddress := getIP(r)                                // Получаем IP-адрес клиента
	token, err := generateAccessToken(userID, ipAddress) // Генерируем токен с привязкой к IP
	if err != nil {
		log.Printf("Не удалось сгенерировать токен для пользователя %s: %v", userID, err)
		http.Error(w, "Ошибка генерации токена. Попробуйте позже.", http.StatusInternalServerError)
		return
	}

	log.Printf("Токен для пользователя %s успешно сохранён", userID)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Токен успешно сохранён для пользователя %s. Ваш Access Token: %s", userID, token)
}

// handleRefreshToken — маршрут для обновления Access токена с помощью Refresh токена
func (a *App) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.URL.Query().Get("refresh_token")
	if refreshToken == "" {
		http.Error(w, "Refresh токен отсутствует", http.StatusBadRequest)
		return
	}

	// Проверяем валидность токена и соответствие IP-адреса
	valid, err := validateToken(r, refreshToken)
	if err != nil || !valid {
		http.Error(w, "Неверный токен или IP-адрес", http.StatusUnauthorized)
		return
	}

	// Получаем хэшированное значение Refresh токена из базы данных
	userID := "userID_from_refresh_token" // Здесь используем получение userID через refresh-токен
	hashedToken, err := a.GetUserIDByRefreshToken(refreshToken)
	if err != nil {
		http.Error(w, "Токен не найден или истёк", http.StatusUnauthorized)
		return
	}

	// Проверяем валидность токена
	err = bcrypt.CompareHashAndPassword([]byte(hashedToken), []byte(refreshToken))
	if err != nil {
		http.Error(w, "Неверный Refresh токен", http.StatusUnauthorized)
		return
	}

	// Проверка изменения IP-адреса
	currentIP := getIP(r) // Используем текущий IP клиента

	if mockOldIP != mockNewIP { // Сравниваем старый и новый IP
		err := sendEmail(mockEmail, mockOldIP, currentIP)
		if err != nil {
			http.Error(w, "Ошибка отправки email", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Email отправлен на %s с предупреждением о смене IP", mockEmail)
	}

	// Генерируем новый Refresh токен
	newRefreshToken, err := generateRefreshToken()
	if err != nil {
		http.Error(w, "Ошибка генерации нового Refresh токена", http.StatusInternalServerError)
		return
	}

	// Хэшируем новый Refresh токен
	newHashedToken, err := hashRefreshToken(newRefreshToken)
	if err != nil {
		http.Error(w, "Ошибка хэширования нового Refresh токена", http.StatusInternalServerError)
		return
	}

	// Удаляем старый Refresh токен
	err = a.DeleteRefreshToken(userID)
	if err != nil {
		http.Error(w, "Ошибка удаления старого Refresh токена", http.StatusInternalServerError)
		return
	}

	// Сохраняем новый Refresh токен в базе данных
	err = a.SaveRefreshToken(userID, newHashedToken)
	if err != nil {
		http.Error(w, "Ошибка сохранения нового Refresh токена", http.StatusInternalServerError)
		return
	}

	// Генерируем новый Access токен
	newAccessToken, err := generateAccessToken(userID, getIP(r))
	if err != nil {
		http.Error(w, "Ошибка генерации нового Access токена", http.StatusInternalServerError)
		return
	}

	// Отправляем новый Refresh токен и Access токен
	fmt.Fprintf(w, "Новый Access токен: %s, Новый Refresh токен: %s", newAccessToken, newRefreshToken)
}

// sendEmail — моковая функция для эмуляции отправки email
func sendEmail(userEmail string, oldIP string, newIP string) error {
	fmt.Printf("Отправлено письмо на %s: IP-адрес изменён с %s на %s\n", userEmail, oldIP, newIP)
	return nil
}

// extractUserID — функция для извлечения userID из запроса
func extractUserID(r *http.Request) (string, error) {
	userID := r.URL.Query().Get("guid")
	if userID == "" {
		return "", fmt.Errorf("userID отсутствует")
	}
	return userID, nil
}
