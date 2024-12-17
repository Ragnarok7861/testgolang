package main

import (
	"testing"
)

func TestInitDBConnection(t *testing.T) {
	app := &App{}
	err := app.initDBConnection()
	if err != nil {
		t.Fatalf("Ошибка подключения к базе данных: %v", err)
	}
}
