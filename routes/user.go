package routes

import (
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
	"webapp/initializers"
	"webapp/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(c *gin.Context) {
	// Obtain Email and Password from req body
	var body struct {
		Email    string `json: "Email" binding:"required"`
		Password string `json:"Password" binding:"required"`
	}

	err := c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Read Request Body",
		})
		return
	}

	// Hash Password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Hash Password",
		})
		return
	}

	// Create User
	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Create User",
		})
		return
	}
	// Respond
	c.JSON(http.StatusOK, gin.H{})
}

func Login(c *gin.Context) {
	// Obtain Email and Password from req body
	var body struct {
		Email    string
		Password string
	}

	err := c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Read Request Body",
		})
		return
	}

	// Search for Requested User
	var user models.User

	initializers.DB.Where("email=?", body.Email).Find(&user)
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Email or Password",
		})
		return
	}

	// Check for Correct Password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Email or Password",
		})
		return
	}

	// Generate JWT Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRETKEY")))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "Failed to Create Token",
		})
		return
	}

	// Setting Cookie with Token
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{})
}

/*
func Validate(c *gin.Context) {
    user, _ := c.Get("user")

    // To access fields of user just do user.(models.User).<whatever-field>
    c.JSON(http.StatusOK, gin.H{
        "message": user,
    })
}
*/

func AddUserRole(c *gin.Context) {
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
		RoleName string `json:"RoleName" binding:"required"`
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

	userRole := models.UserAccessRole{UserId: uint(userId), RoleId: role.ID}
	insertResult := initializers.DB.Create(&userRole)
	if insertResult.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Insert User-Role",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func DeleteUserRole(c *gin.Context) {
	userToken, exists := c.Get("userToken")
	if !exists {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	// Decode Token String to obtain User ID
	token, _ := jwt.Parse(userToken.(string), func(token *jwt.Token) (interface{}, error) {
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

	// Directly Delete With User ID since User can only have a Single Role
	deleteResult := initializers.DB.Where("user_id=?", userId).Delete(&models.UserAccessRole{})
	if deleteResult.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Delete User-Role",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func AddUserGroup(c *gin.Context) {
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
		GroupName string `json:"GroupName" binding:"required"`
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

	userGroup := models.UserAccessGroup{UserId: uint(userId), GroupId: group.ID}
	insertResult := initializers.DB.Create(&userGroup)
	if insertResult.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Insert User-Group",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func DeleteUserGroup(c *gin.Context) {
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
		GroupName string `json:"GroupName" binding:"required"`
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

	deleteResult := initializers.DB.Where("user_id=? AND group_id=?", userId, group.ID).Delete(&models.UserAccessGroup{})
	if deleteResult.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Delete User-Group",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func DeleteUser(c *gin.Context) {
	userToken, exists := c.Get("userToken")
	if !exists {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	// Decode Token String to obtain User ID
	token, _ := jwt.Parse(userToken.(string), func(token *jwt.Token) (interface{}, error) {
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

	userDelResult := initializers.DB.Where("id=?", userId).Delete(&models.User{})
	if userDelResult.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Delete User",
		})
		return
	}

	userRoleDelResult := initializers.DB.Where("user_id=?", userId).Delete(&models.UserAccessRole{})
	if userRoleDelResult.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Delete User-Role",
		})
		return
	}

	userGroupDelResult := initializers.DB.Where("user_id=?", userId).Delete(&models.UserAccessGroup{})
	if userGroupDelResult.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Delete User-Group",
		})
		return
	}

	// Removing Auth Token Cookie
	c.SetCookie("Authorization", "", -1, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{})
}

func Logout(c *gin.Context) {
	c.SetCookie("Authorization", "", -1, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully Logged Out",
	})
}

func ParseUserCSV(c *gin.Context) {
	type userData struct {
		Email    string
		Password string
		Role     string
		Group    string
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

	var userContents []userData
	for i, line := range data {
		if i > 0 {
			var user userData
			for j, field := range line {
				if j == 0 {
					user.Email = field
				} else if j == 1 {
					user.Password = field
				} else if j == 2 {
					user.Role = field
				} else {
					user.Group = field
				}
			}
			userContents = append(userContents, user)
		}
	}

	for i := 0; i < len(userContents); i++ {
		// Hash Password
		hash, err := bcrypt.GenerateFromPassword([]byte(userContents[i].Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to Hash Password",
			})
			return
		}

		// Create User
		user := models.User{Email: userContents[i].Email, Password: string(hash)}
		result := initializers.DB.Create(&user)

		if result.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to Create User",
			})
			continue
		}

		// Getting User ID of inserted Record
		var tempUser models.User

		initializers.DB.Where("email=?", userContents[i].Email).Find(&tempUser)
		if tempUser.ID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid Email or Password",
			})
			return
		}

		// Getting Role ID of inserted Record
		var tempRole models.Role

		initializers.DB.Where("role_name=?", userContents[i].Role).Find(&tempRole)
		if tempRole.ID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid Role Name",
			})
			return
		}

		// Adding User-Role
		userRole := models.UserAccessRole{UserId: tempUser.ID, RoleId: tempRole.ID}
		roleRes := initializers.DB.Create(&userRole)
		if roleRes.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to Create User-Role",
			})
			continue
		}

		// Getting Group ID of inserted Record
		var tempGroup models.GroupDetails

		initializers.DB.Where("group_name=?", userContents[i].Group).Find(&tempGroup)
		if tempGroup.ID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid Role Name",
			})
			return
		}

		// Adding User-Group
		userGroup := models.UserAccessGroup{UserId: tempUser.ID, GroupId: tempGroup.ID}
		groupRes := initializers.DB.Create(&userGroup)
		if groupRes.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to Create User-Group",
			})
			continue
		}
	}
}
