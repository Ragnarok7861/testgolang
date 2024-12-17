package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

type App struct {
	DB *sql.DB
}

func (a *App) initDBConnection() error {
	connStr := "user=postgres password=7861 dbname=testgo sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}
	a.DB = db
	_, err = a.DB.Exec(`CREATE TABLE IF NOT EXISTS tokens (
		user_id TEXT PRIMARY KEY,
		refresh_token TEXT
	)`)
	return err
}

func (a *App) SaveRefreshToken(userID, token string) error {
	_, err := a.DB.Exec(`INSERT INTO tokens (user_id, refresh_token) 
                         VALUES ($1, $2) 
                         ON CONFLICT (user_id) DO UPDATE SET refresh_token = EXCLUDED.refresh_token`,
		userID, token)
	return err
}

func (a *App) GetUserIDByRefreshToken(userID string) (string, error) {
	var token string
	err := a.DB.QueryRow(`SELECT refresh_token FROM tokens WHERE user_id = $1`, userID).Scan(&token)
	if err != nil {
		return "", err
	}
	return token, nil
}

func main() {
	// Инициализация приложения
	app := &App{}

	// Подключение к базе данных
	err := app.initDBConnection()
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}

	// Выводим сообщение, что соединение с БД установлено успешно
	fmt.Println("Успешное подключение к базе данных!")

	// Пример использования функций
	err = app.SaveRefreshToken("user123", "some-refresh-token")
	if err != nil {
		log.Fatalf("Ошибка сохранения refresh token: %v", err)
	}
	fmt.Println("Refresh token для пользователя user123 успешно сохранен")
}
