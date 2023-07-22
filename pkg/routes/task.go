package routes

import (
    "os"
    "fmt"
	"bar/foo/pkg/initializers"
	"bar/foo/pkg/models"
	"net/http"

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
