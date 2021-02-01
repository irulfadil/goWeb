package models

import "time"

// Users models is master list fo all your user table
type Users struct {
	ID          int       `json:"id"`
	Username    string    `json:"username"`
	Password    string    `json:"password"`
	Email       string    `json:"email"`
	Country     string    `json:"country"`
	Eusr        string    `json:"eUsr"`
	FirstName   string    `json:"first_name"`
	LastName    string    `json:"last_name"`
	IsSuperuser string    `json:"is_superuser"`
	IsAdmin     string    `json:"is_admin"`
	DateJoined  time.Time `json:"date_joid"`
	IsActive    string    `json:"is_active"`
}
