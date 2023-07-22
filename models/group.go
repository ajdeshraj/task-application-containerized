package models

import "gorm.io/gorm"

type GroupDetails struct {
    gorm.Model
    GroupName string `gorm:"unique"`
}
