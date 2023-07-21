package routes

import (
    "os"
    "time"
	"bar/foo/pkg/initializers"
	"bar/foo/pkg/models"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(c *gin.Context) {
    // Obtain Email and Password from req body
    var body struct {
        Email string
        Password string
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
        Email string
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
        "exp": time.Now().Add(time.Hour*24*30).Unix(),
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

func Validate(c *gin.Context) {
    user, _ := c.Get("user")

    // To access fields of user just do user.(models.User).<whatever-field>
    c.JSON(http.StatusOK, gin.H{
        "message": user,
    })
}
