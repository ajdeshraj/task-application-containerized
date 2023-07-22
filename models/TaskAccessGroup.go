package models

import "gorm.io/gorm"

type TaskAccessGroup struct {
    gorm.Model
    TaskId uint
    GroupId uint
}
