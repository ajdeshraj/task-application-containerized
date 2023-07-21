package initializers

import "bar/foo/pkg/models"

func SyncDb() {
    DB.AutoMigrate(&models.User{})
    DB.AutoMigrate(&models.UserAccessRole{})
    DB.AutoMigrate(&models.UserAccessGroup{})
    DB.AutoMigrate(&models.Task{})
    DB.AutoMigrate(&models.TaskAccessRole{})
    DB.AutoMigrate(&models.TaskAccessGroup{})
    DB.AutoMigrate(&models.Role{})
    DB.AutoMigrate(&models.GroupDetails{})
}
