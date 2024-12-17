package main

import (
	"testing"
)

func TestSaveRefreshToken(t *testing.T) {
	// Создаём экземпляр структуры App
	app := &App{}

	// Инициализируем соединение с базой данных
	err := app.initDBConnection()
	if err != nil {
		t.Fatalf("Ошибка подключения к базе данных: %v", err)
	}
	defer app.DB.Close() // Закрываем соединение после теста

	// Вызываем метод SaveRefreshToken
	err = app.SaveRefreshToken("test123", "hashed_token_example")
	if err != nil {
		t.Errorf("Ошибка сохранения Refresh токена: %v", err)
	}
}
