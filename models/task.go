package models

import "gorm.io/gorm"

type Task struct {
	gorm.Model
	Description string `gorm:"unique"`
	Completed   bool
	CreatorId   uint
}
