package initializers

import "bar/foo/pkg/models"

func SyncDb() {
    DB.AutoMigrate(&models.User{})
}
