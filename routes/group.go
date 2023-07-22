package routes

import (
	"fmt"
	"net/http"
	"os"
	"webapp/initializers"
	"webapp/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func AddGroup(c *gin.Context) {
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
		Name string `json:"GroupName" binding:"required"`
	}

	err = c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Read Request Body",
		})
		return
	}

	group := models.GroupDetails{GroupName: body.Name}
	result := initializers.DB.Create(&group)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Create Group",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func DeleteGroup(c *gin.Context) {
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
		Name string `json:"GroupName" binding:"required"`
	}

	err = c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Read Request Body",
		})
		return
	}

	result := initializers.DB.Where("group_name=?", body.Name).Delete(&models.GroupDetails{})

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to Delete Group",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}
