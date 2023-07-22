package models

import "gorm.io/gorm"

type UserAccessGroup struct {
	gorm.Model
	UserId  uint
	GroupId uint
}
