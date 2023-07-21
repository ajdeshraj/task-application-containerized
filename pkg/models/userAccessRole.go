package models

import "gorm.io/gorm"

type UserAccessRole struct {
    gorm.Model
    UserId uint
    RoleId uint
}
