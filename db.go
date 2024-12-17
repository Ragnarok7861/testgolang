package main

import (
	"database/sql"
)

type DBHandler struct {
	DB *sql.DB
}

func (db *DBHandler) SaveRefreshToken(userID, token string) error {
	_, err := db.DB.Exec(`INSERT INTO tokens (user_id, refresh_token) VALUES ($1, $2) ON CONFLICT (user_id) DO UPDATE SET refresh_token = EXCLUDED.refresh_token`, userID, token)
	return err
}

func (db *DBHandler) GetUserIDByRefreshToken(userID string) (string, error) {
	var token string
	err := db.DB.QueryRow(`SELECT refresh_token FROM tokens WHERE user_id = $1`, userID).Scan(&token)
	if err != nil {
		return "", err
	}
	return token, nil
}
