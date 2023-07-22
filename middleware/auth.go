package middleware

import (
	"fmt"
	"os"
	"webapp/initializers"
	"webapp/models"

	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func RequireAuth(c *gin.Context) {
	// Obtain Cookie off Request
	tokenString, err := c.Cookie("Authorization")
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	// Decode/Validate Cookie Token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected String Sigining Method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("SECRETKEY")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check the Expiration of the Cookie
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// Find User with Token
		var user models.User
		initializers.DB.Find(&user, claims["sub"])

		if user.ID == 0 {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		// Attach to Request
		c.Set("userToken", tokenString)

		c.Next()

		fmt.Println(claims["sub"])
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}
