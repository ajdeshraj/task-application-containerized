package routes

import (
    "fmt"
	"net/http"
    "os"
	"bar/foo/pkg/initializers"
    "bar/foo/pkg/models"

	"github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v4"
)

func AddRole(c *gin.Context) {
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
        Name string `json:"RoleName" binding:"required"`
    }

    err = c.Bind(&body)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Read Request Body",
        })
        return
    }

    role := models.Role{RoleName: body.Name}
    result := initializers.DB.Create(&role)

    if result.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Create Role",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{})
}

func DeleteRole(c *gin.Context) {
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
        Name string `json:"RoleName" binding:"required"`
    }

    err = c.Bind(&body)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Read Request Body",
        })
        return
    }

    result := initializers.DB.Where("role_name=?", body.Name).Delete(&models.Role{})

    if result.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Failed to Delete Role",
        })
        return
    }

    c.JSON(http.StatusOK, gin.H{})
}
