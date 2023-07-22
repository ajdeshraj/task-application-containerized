package routes

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"webapp/initializers"
	"webapp/models"
	"webapp/utils"

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
		Completed   bool   `json:"Completed" default:"false"`
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
	taskRole := models.TaskAccessRole{TaskId: lastTask.ID, RoleId: 1}
	initializers.DB.Create(&taskRole)

	// Inserting Default Group Access for this Task as Open
	taskGroup := models.TaskAccessGroup{TaskId: lastTask.ID, GroupId: 1}
	initializers.DB.Create(&taskGroup)
}

func UpdateTask(c *gin.Context) {
	var canUpdate bool
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
		OldDescription string `json:"oldDescription" binding:"required"`
		NewDescription string `json:"newDescription"`
		Completed      bool   `json:"Completed"`
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
	if res.Error != nil || res.RowsAffected == 0 {
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

	// Checking for Open Role or Group
	if utils.ElementInArray(taskArrayRole, uint(1)) && utils.ElementInArray(taskArrayGroup, uint(1)) {
		// Update Task
		// Update Completed because Default value of Completed will be false
		initializers.DB.Model(&task).Update("Completed", body.Completed)
		if body.NewDescription != "" {
			initializers.DB.Model(&task).Update("Description", body.NewDescription)
		}
	} else {
		// Deny Update
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Cannot Update Task",
		})
		return
	}

	// Finding User Role
	var user models.UserAccessRole
	result := initializers.DB.Where("user_id=?", userId).Find(&user)
	if result.Error != nil || result.RowsAffected == 0 {
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

	// Checking if user can access the given task
	// Checking Roles
	fmt.Println(taskArrayRole, userRole)
	commonTask := utils.ElementInArray(taskArrayRole, userRole)
	fmt.Println(commonTask)
	if commonTask {
		canUpdate = true
	} else {
		// Deny Update
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User Role Denied",
		})
		return
	}

	// Checking Groups
	commonGroup := utils.ArrayIntersection(taskArrayGroup, userArrayGroup)
	if len(commonGroup) > 0 {
		canUpdate = true
	} else {
		// Deny Update
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User Group Denied",
		})
		return
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
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Cannot Update Task",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func DeleteTask(c *gin.Context) {
	var canDelete bool
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
	res := initializers.DB.Where("Description=?", body.Description).Find(&task)
	if res.Error != nil || res.RowsAffected == 0 {
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

	// Checking for Open Role or Group
	if utils.ElementInArray(taskArrayRole, uint(1)) && utils.ElementInArray(taskArrayGroup, uint(1)) {
		initializers.DB.Delete(&task)
	} else {
		// Deny Delete
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Cannot Delete Task",
		})
		return
	}

	// Finding User Role
	var user models.UserAccessRole
	result := initializers.DB.Where("user_id=?", userId).Find(&user)
	if result.Error != nil || result.RowsAffected == 0 {
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

	// Checking if user can access the given task
	// Checking Roles
	fmt.Println(taskArrayRole, userRole)
	commonTask := utils.ElementInArray(taskArrayRole, userRole)
	fmt.Println(commonTask)
	if commonTask {
		canDelete = true
	} else {
		// Deny Delete
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User Role Denied",
		})
		return
	}

	// Checking Groups
	commonGroup := utils.ArrayIntersection(taskArrayGroup, userArrayGroup)
	if len(commonGroup) > 0 {
		canDelete = true
	} else {
		// Deny Delete
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User Group Denied",
		})
		return
	}

	if canDelete {
		initializers.DB.Delete(&task)
	} else {
		// Deny Delete
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Cannot Delete Task",
		})
		return
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
		RoleName        string `json:"RoleName" binding:"required"`
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
	if result.Error != nil || result.RowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Find Role",
		})
		return
	}
	// fmt.Printf("Role found is %s\nRows: %d\nError: %s\n", role.RoleName, result.RowsAffected, result.Error)

	var task models.Task
	res := initializers.DB.Where("Description=?", body.TaskDescription).Find(&task)
	if res.Error != nil || res.RowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Find Task",
		})
		return
	}
	// fmt.Printf("Task ID found: %d\n", task.ID)

	// Removing Open Access Role
	var openRole models.Role
	var taskopenrole models.TaskAccessRole
	initializers.DB.Where("role_name=?", "open").First(&openRole)
	// fmt.Printf("Open Role ID found: %d\n", openRole.ID)
	if openRole.ID != 0 {
		initializers.DB.Where("task_id = ? AND role_id = ?", task.ID, openRole.ID).Delete(&taskopenrole)
	}

	taskRole := models.TaskAccessRole{TaskId: task.ID, RoleId: role.ID}
	insertResult := initializers.DB.Create(&taskRole)
	if insertResult.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Insert Task-Role",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
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
		RoleName        string `json:"RoleName" binding:"required"`
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
	if result.Error != nil || result.RowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Find Role",
		})
		return
	}

	var task models.Task
	res := initializers.DB.Where("Description=?", body.TaskDescription).Find(&task)
	if res.Error != nil || res.RowsAffected == 0 {
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
	var taskaccrole models.TaskAccessRole
	res = initializers.DB.Where("task_id = ?", task.ID).Find(&taskaccrole)
	if res.Error != nil || res.RowsAffected == 0 {
		// No other (task_id, *) in the table
		// Default open role should be added
		taskaccrole = models.TaskAccessRole{TaskId: task.ID, RoleId: 1}
		initializers.DB.Create(&taskaccrole)
	}

	c.JSON(http.StatusOK, gin.H{})
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
		GroupName       string `json:"GroupName" binding:"required"`
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
	if result.Error != nil || result.RowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Find Group",
		})
		return
	}

	var task models.Task
	res := initializers.DB.Where("Description=?", body.TaskDescription).Find(&task)
	if res.Error != nil || res.RowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Find Task",
		})
		return
	}

	// Removing Open Access Role
	var openGroup models.GroupDetails
	var taskopengrp models.TaskAccessGroup
	initializers.DB.Where("group_name=?", "open").First(&openGroup)
	// fmt.Printf("Open Role ID found: %d\n", openRole.ID)
	if openGroup.ID != 0 {
		initializers.DB.Where("task_id = ? AND group_id = ?", task.ID, openGroup.ID).Delete(&taskopengrp)
	}

	taskGroup := models.TaskAccessGroup{TaskId: task.ID, GroupId: group.ID}
	insertResult := initializers.DB.Create(&taskGroup)
	if insertResult.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Insert Task-Group",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
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
		GroupName       string `json:"GroupName" binding:"required"`
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
	if result.Error != nil || result.RowsAffected == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Find Group",
		})
		return
	}

	var task models.Task
	res := initializers.DB.Where("Description=?", body.TaskDescription).Find(&task)
	if res.Error != nil || res.RowsAffected == 0 {
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
	var taskaccgrp models.TaskAccessGroup
	res = initializers.DB.Where("task_id = ?", task.ID).Find(&taskaccgrp)
	if res.Error != nil || res.RowsAffected == 0 {
		taskaccgrp = models.TaskAccessGroup{TaskId: task.ID, GroupId: 1}
		initializers.DB.Create(&taskaccgrp)
	}

	c.JSON(http.StatusOK, gin.H{})
}

func ParseTaskCSV(c *gin.Context) {
	type taskData struct {
		Description string
		Completed   bool
		CreatorId   uint
		Role        string
		Group       string
	}

	fileHeader, err := c.FormFile("file.csv")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Error Receiving File",
		})
		return
	}

	FileToImport, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Error Opening File",
		})
		return
	}

	defer FileToImport.Close()

	csvReader := csv.NewReader(FileToImport)
	data, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	var taskContents []taskData
	for i, line := range data {
		if i > 0 {
			var task taskData
			for j, field := range line {
				if j == 0 {
					task.Description = field
				} else if j == 1 {
					// task.Completed = bool(field)
					task.Completed, err = strconv.ParseBool(field)
					if err != nil {
						log.Println(err)
						continue
					}
				} else if j == 2 {
					// task.CreatorId = uint(field)
					num, err := strconv.ParseUint(field, 10, 64)
					if err != nil {
						log.Println(err)
						continue
					}
					task.CreatorId = uint(num)
				} else if j == 3 {
					task.Role = field
				} else {
					task.Group = field
				}
			}
			taskContents = append(taskContents, task)
		}
	}

	for i := 0; i < len(taskContents); i++ {
		// Create User
		task := models.Task{Description: taskContents[i].Description, Completed: taskContents[i].Completed, CreatorId: taskContents[i].CreatorId}
		result := initializers.DB.Create(&task)

		if result.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to Create Task",
			})
			continue
		}

		// Getting Task ID of inserted Record
		var tempTask models.Task

		initializers.DB.Where("Description=?", taskContents[i].Description).Find(&tempTask)
		if tempTask.ID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid Information",
			})
			return
		}

		// Getting Role ID of inserted Record
		var tempRole models.Role

		initializers.DB.Where("role_name=?", taskContents[i].Role).Find(&tempRole)
		if tempRole.ID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid Role Name",
			})
			return
		}

		// Adding Task-Role
		taskRole := models.TaskAccessRole{TaskId: tempTask.ID, RoleId: tempRole.ID}
		roleRes := initializers.DB.Create(&taskRole)
		if roleRes.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to Create Task-Role",
			})
			continue
		}

		// Getting Group ID of inserted Record
		var tempGroup models.GroupDetails

		initializers.DB.Where("group_name=?", taskContents[i].Group).Find(&tempGroup)
		if tempGroup.ID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid Role Name",
			})
			return
		}

		// Adding User-Group
		taskGroup := models.TaskAccessGroup{TaskId: tempTask.ID, GroupId: tempGroup.ID}
		groupRes := initializers.DB.Create(&taskGroup)
		if groupRes.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to Create Task-Group",
			})
			continue
		}
	}
}
