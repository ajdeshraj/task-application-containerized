package models

import "gorm.io/gorm"

type Task struct {
    gorm.Model
    Description string
    Completed bool
    CreatorId uint
}
