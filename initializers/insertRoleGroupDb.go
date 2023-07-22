package initializers

import "webapp/models"

func InsertRoleDb() {
	var role models.Role

	DB.Where("role_name=?", "open").First(&role)
	if role.ID == 0 {
		openRole := models.Role{RoleName: "open"}
		DB.Select("role_name").Create(&openRole)
	}
}

func InsertGroupDb() {
	var groupDets models.GroupDetails

	DB.Where("group_name=?", "open").First(&groupDets)
	if groupDets.ID == 0 {
		openGroup := models.GroupDetails{GroupName: "open"}
		DB.Select("group_name").Create(&openGroup)
	}
}
