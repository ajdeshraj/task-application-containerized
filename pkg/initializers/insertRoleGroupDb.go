package initializers

import "bar/foo/pkg/models"

func InsertRoleDb() {
    var role models.Role
    
    DB.Where("RoleName=?", "open").First(&role)
    if role.ID == 0 {
        openRole := models.Role{RoleName: "open"}
        DB.Select("RoleName").Create(&openRole)
    }
}

func InsertGroupDb() {
    var groupDets models.GroupDetails

    DB.Where("GroupName=?", "open").First(&groupDets)
    if groupDets.ID == 0 {
        openGroup := models.GroupDetails{GroupName: "open"}
        DB.Select("GroupName").Create(&openGroup)
    }
}
