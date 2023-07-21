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
}
