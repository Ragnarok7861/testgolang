package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt" // Для хэширования токенов
)

type App struct {
	DB *sql.DB
}

const secretKey = "testgosecretkey24" // Секретный ключ для подписи JWT токенов

// Функция для генерации произвольного Refresh токена
func generateRefreshToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	// Кодируем токен в формат base64
	refreshToken := base64.StdEncoding.EncodeToString(token)
	return refreshToken, nil
}

// Функция для хэширования Refresh токена с использованием bcrypt
func hashRefreshToken(refreshToken string) (string, error) {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedToken), nil
}

// initDBConnection — функция для подключения к базе данных
func (a *App) initDBConnection() error {
	db, err := InitDB() // Подключение к базе данных (функция из db.go)
	if err != nil {
		return err
	}
	a.DB = db
	return nil
}

// setupRoutes — функция для регистрации маршрутов
func (a *App) setupRoutes() {
	http.HandleFunc("/token", a.handleTokenRequest)   // Маршрут для получения токена
	http.HandleFunc("/refresh", a.handleRefreshToken) // Маршрут для обновления токена
}

// startServer — запуск сервера
func (a *App) startServer(addr string) {
	a.setupRoutes() // Регистрация маршрутов
	log.Printf("Сервер запущен на порту %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil)) // Запуск сервера
}

func main() {
	app := &App{}

	// Подключаемся к базе данных
	if err := app.initDBConnection(); err != nil {
		log.Fatalf("Ошибка при подключении к базе данных: %v", err)
	}
	defer app.DB.Close() // Закрываем соединение с базой данных после завершения работы

	app.startServer(":8080")
}
