package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// InitDB — подключаемся к базе данных PostgreSQL
func InitDB() (*sql.DB, error) {
	connStr := "user=postgres password=7861 dbname=testgo sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть соединение с базой: %v", err)
	}

	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к базе данных: %v", err)
	}

	fmt.Println("Успешно подключились к базе данных")
	return db, nil
}

// SaveRefreshToken сохраняет хэшированный Refresh токен в базе данных
func (a *App) SaveRefreshToken(userID string, hashedRefreshToken string) error {
	_, err := a.DB.Exec("INSERT INTO tokens (user_id, refresh_token) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET refresh_token = EXCLUDED.refresh_token", userID, hashedRefreshToken)
	if err != nil {
		return fmt.Errorf("не удалось сохранить refresh токен для пользователя %s: %v", userID, err)
	}
	return nil
}

// GetUserIDByRefreshToken возвращает хэшированный Refresh токен по userID
func (a *App) GetUserIDByRefreshToken(refreshToken string) (string, error) {
	var hashedToken string
	err := a.DB.QueryRow("SELECT refresh_token FROM tokens WHERE user_id = $1", refreshToken).Scan(&hashedToken)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("токен не найден")
	} else if err != nil {
		return "", fmt.Errorf("ошибка при получении токена: %v", err)
	}
	return hashedToken, nil
}

// DeleteRefreshToken удаляет Refresh токен по userID
func (a *App) DeleteRefreshToken(userID string) error {
	_, err := a.DB.Exec("DELETE FROM tokens WHERE user_id = $1", userID)
	if err != nil {
		return fmt.Errorf("не удалось удалить refresh токен для пользователя %s: %v", userID, err)
	}
	return nil
}
