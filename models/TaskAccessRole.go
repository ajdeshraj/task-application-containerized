package models

import "gorm.io/gorm"

type TaskAccessRole struct {
	gorm.Model
	TaskId uint
	RoleId uint
}
