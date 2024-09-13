package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// getIP возвращает IP-адрес клиента
func getIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For") // Используем заголовок, если запрос идёт через прокси
	if forwarded != "" {
		return forwarded
	}
	return r.RemoteAddr // Получаем IP напрямую
}

// generateAccessToken генерирует JWT токен для пользователя с привязкой к IP-адресу
func generateAccessToken(userID, ipAddress string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"userID": userID,
		"ip":     ipAddress,                            // Привязка к IP-адресу
		"exp":    time.Now().Add(time.Hour * 1).Unix(), // Токен действует 1 час
	})
	return token.SignedString([]byte(secretKey)) // secretKey берётся из глобальной переменной
}

// validateToken проверяет валидность токена и соответствие IP-адреса
func validateToken(r *http.Request, tokenString string) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Получаем IP-адрес из токена
		tokenIP := claims["ip"].(string)

		// Текущий IP-адрес клиента
		currentIP := getIP(r)

		// Сравниваем IP-адреса
		if tokenIP != currentIP {
			return false, fmt.Errorf("IP-адрес не совпадает")
		}

		return true, nil
	} else {
		return false, err
	}
}
