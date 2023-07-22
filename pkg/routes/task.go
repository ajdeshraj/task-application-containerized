package routes

import (
	"bar/foo/pkg/initializers"
	"bar/foo/pkg/models"
	"bar/foo/pkg/utils"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func CreateTask(c *gin.Context) {
    userToken, exists := c.Get("userToken")
    if !exists {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    // Decode Token String to obtain User ID
    token, err := jwt.Parse(userToken.(string), func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected String Sigining Method: %v", token.Header["alg"])
        }

        return []byte(os.Getenv("SECRETKEY")), nil
    })

    claims, ok := token.Claims.(jwt.MapClaims) 
    if !(ok && token.Valid) {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    userId := claims["sub"].(float64)

    var body struct {
        Description string `json:"Description" binding:"required"`
        Completed bool `json:"Completed" default:"false"`
    }

    err = c.Bind(&body)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Read Request Body",
        })
        return
    }

    task := models.Task{Description: body.Description, Completed: body.Completed, CreatorId: uint(userId)}
    result := initializers.DB.Create(&task)

    if result.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Create Task",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{})

    // Getting Task ID of just inserted task
    var lastTask models.Task

    lastRes := initializers.DB.Last(&lastTask)
    if lastRes.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Add Access Management",
        })
        return
    }

    // Inserting Default Role Access for this Task as Open
    taskRole := models.TaskAccessRole {TaskId: lastTask.ID, RoleId: 1}
    initializers.DB.Create(&taskRole)

    // Inserting Default Group Access for this Task as Open
    taskGroup := models.TaskAccessGroup {TaskId: lastTask.ID, GroupId: 1}
    initializers.DB.Create(&taskGroup)
}

func UpdateTask(c *gin.Context) {
    userToken, exists := c.Get("userToken")
    if !exists {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    // Decode Token String to obtain User ID
    token, err := jwt.Parse(userToken.(string), func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected String Sigining Method: %v", token.Header["alg"])
        }

        return []byte(os.Getenv("SECRETKEY")), nil
    })

    claims, ok := token.Claims.(jwt.MapClaims) 
    if !(ok && token.Valid) {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    userId := claims["sub"].(float64)

    // Finding User Role
    var user models.UserAccessRole
    result := initializers.DB.Where("user_id=?", userId).Find(&user)
    if result.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Unable to Find User Role",
        })
        return
    }
    userRole := user.RoleId

    // Finding User Groups
    var userGroup []models.UserAccessGroup

    initializers.DB.Where("user_id=?", userId).Find(&userGroup)
    var userArrayGroup []uint
    for i := 0; i < len(userGroup); i++ {
        // userArrayGroup[i] = userGroup[i].GroupId
        userArrayGroup = append(userArrayGroup, userGroup[i].GroupId)
    }

    var body struct {
        OldDescription string `json:"oldDescription" binding:"required"`
        NewDescription string `json:"newDescription"`
        Completed bool `json:"Completed"`
    }
    err = c.Bind(&body)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Read Request Body",
        })
        return
    }

    // Finding Task ID 
    var task models.Task
    res := initializers.DB.Where("Description=?", body.OldDescription).Find(&task)
    if res.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Find Task",
        })
        return
    }

    // Finding Roles that can Access the Task
    var roleTask []models.TaskAccessRole

    initializers.DB.Where("task_id=?", task.ID).Find(&roleTask)
    var taskArrayRole []uint
    for i := 0; i < len(taskArrayRole); i++ {
        // taskArrayRole[i] = roleTask[i].RoleId
        taskArrayRole = append(taskArrayRole, roleTask[i].RoleId)
    }

    // Finding Groups that can Access the Task
    var groupTask []models.TaskAccessGroup

    initializers.DB.Where("task_id=?", task.ID).Find(&groupTask)
    var taskArrayGroup []uint
    for i := 0; i < len(taskArrayGroup); i++ {
        // taskArrayGroup[i] = groupTask[i].GroupId
        taskArrayGroup = append(taskArrayGroup, groupTask[i].GroupId)
    }

    canUpdate := false
    // Checking if user can access the given task
    // Checking Roles
    // if userRole in retRoleTask:
    commonTask := utils.ElementInArray(taskArrayRole, userRole)
    if commonTask {
        canUpdate = true
    } else {
        // Deny Update
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    // Checking Groups
    commonGroup := utils.ArrayIntersection(taskArrayGroup, userArrayGroup)
    if len(commonGroup) > 0 {
        canUpdate = true
    } else {
        // Deny Update
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    if canUpdate {
        // Update Task
        // Update Completed because Default value of Completed will be false
        initializers.DB.Model(&task).Update("Completed", body.Completed)
        if body.NewDescription != "" {
            initializers.DB.Model(&task).Update("Description", body.NewDescription)
        }
    } else {
        // Deny Update 
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    c.JSON(http.StatusOK, gin.H{})
}

func AddTaskRole(c *gin.Context) {
    userToken, exists := c.Get("userToken")
    if !exists {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    // Decode Token String to obtain User ID
    token, err := jwt.Parse(userToken.(string), func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected String Sigining Method: %v", token.Header["alg"])
        }

        return []byte(os.Getenv("SECRETKEY")), nil
    })

    _, ok := token.Claims.(jwt.MapClaims) 
    if !(ok && token.Valid) {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    var body struct {
        RoleName string `json:"RoleName" binding:"required"`
        TaskDescription string `json:"TaskDescription" binding:"required"`
    }

    err = c.Bind(&body)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Read Request Body",
        })
        return
    }

    var role models.Role
    result := initializers.DB.Where("role_name=?", body.RoleName).Find(&role)
    if result.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Find Role",
        })
        return
    }

    var task models.Task
    res := initializers.DB.Where("Description=?", body.TaskDescription).Find(&task)
    if res.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Find Task",
        })
        return
    }

    // Removing Open Access Role
    var openRole models.Role
    initializers.DB.Where("role_id=?", 1).First(&openRole)
    if openRole.ID != 0 {
        initializers.DB.Delete(&openRole)
    }

    taskRole := models.TaskAccessRole{TaskId: task.ID, RoleId: role.ID}
    insertResult := initializers.DB.Create(&taskRole)
    if insertResult.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Insert Task-Role",
        })
        return
    }

    c.JSON(http.StatusOK,gin.H{})
}

func DeleteTaskRole(c *gin.Context) {
    userToken, exists := c.Get("userToken")
    if !exists {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    // Decode Token String to obtain User ID
    token, err := jwt.Parse(userToken.(string), func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected String Sigining Method: %v", token.Header["alg"])
        }

        return []byte(os.Getenv("SECRETKEY")), nil
    })

    _, ok := token.Claims.(jwt.MapClaims) 
    if !(ok && token.Valid) {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    var body struct {
        RoleName string `json:"RoleName" binding:"required"`
        TaskDescription string `json:"TaskDescription" binding:"required"`
    }

    err = c.Bind(&body)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Read Request Body",
        })
        return
    }

    var role models.Role
    result := initializers.DB.Where("role_name=?", body.RoleName).Find(&role)
    if result.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Find Role",
        })
        return
    }

    var task models.Task
    res := initializers.DB.Where("Description=?", body.TaskDescription).Find(&task)
    if res.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Find Task",
        })
        return
    }

    deleteResult := initializers.DB.Where("task_id=? AND role_id=?", task.ID, role.ID).Delete(&models.TaskAccessRole{})
    if deleteResult.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Delete Task-Role",
        })
        return
    }

    // Check if any other Task-Role Exists, if not, add Open Task-Role

    c.JSON(http.StatusOK,gin.H{})
}

func AddTaskGroup(c *gin.Context) {
    userToken, exists := c.Get("userToken")
    if !exists {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    // Decode Token String to obtain User ID
    token, err := jwt.Parse(userToken.(string), func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected String Sigining Method: %v", token.Header["alg"])
        }

        return []byte(os.Getenv("SECRETKEY")), nil
    })

    _, ok := token.Claims.(jwt.MapClaims) 
    if !(ok && token.Valid) {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    var body struct {
        GroupName string `json:"GroupName" binding:"required"`
        TaskDescription string `json:"TaskDescription" binding:"required"`
    }

    err = c.Bind(&body)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": err.Error(),
        })
        return
    }

    var group models.GroupDetails
    result := initializers.DB.Where("group_name=?", body.GroupName).Find(&group)
    if result.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Find Group",
        })
        return
    }

    var task models.Task
    res := initializers.DB.Where("Description=?", body.TaskDescription).Find(&task)
    if res.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Find Task",
        })
        return
    }

    taskGroup := models.TaskAccessGroup{TaskId: task.ID, GroupId: group.ID}
    insertResult := initializers.DB.Create(&taskGroup)
    if insertResult.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Insert Task-Group",
        })
        return
    }

    c.JSON(http.StatusOK,gin.H{})
}

func DeleteTaskGroup(c *gin.Context) {
    userToken, exists := c.Get("userToken")
    if !exists {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    // Decode Token String to obtain User ID
    token, err := jwt.Parse(userToken.(string), func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected String Sigining Method: %v", token.Header["alg"])
        }

        return []byte(os.Getenv("SECRETKEY")), nil
    })

    _, ok := token.Claims.(jwt.MapClaims) 
    if !(ok && token.Valid) {
        c.AbortWithStatus(http.StatusUnauthorized)
    }

    var body struct {
        GroupName string `json:"GroupName" binding:"required"`
        TaskDescription string `json:"TaskDescription" binding:"required"`
    }

    err = c.Bind(&body)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Read Request Body",
        })
        return
    }

    var group models.GroupDetails
    result := initializers.DB.Where("group_name=?", body.GroupName).Find(&group)
    if result.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Find Group",
        })
        return
    }

    var task models.Task
    res := initializers.DB.Where("Description=?", body.TaskDescription).Find(&task)
    if res.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Find Task",
        })
        return
    }

    deleteResult := initializers.DB.Where("group_id=? AND task_id=?", group.ID, task.ID).Delete(&models.TaskAccessGroup{})
    if deleteResult.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Insert Task-Group",
        })
        return
    }

    // Check if any other Task-Group Exists, if not, add Open Task-Group

    c.JSON(http.StatusOK,gin.H{})
}
