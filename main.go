package main

import (
	"bar/foo/pkg/initializers"
	"bar/foo/pkg/middleware"
	"bar/foo/pkg/routes"

	// "net/http"

	"github.com/gin-gonic/gin"
)

func init() {
    initializers.LoadEnvVars()
    initializers.ConnectDb()
    initializers.SyncDb()
}

func main() {
    r := gin.Default()

    r.POST("/signup", routes.SignUp)
    r.POST("/login", routes.Login)
    r.GET("/validate", middleware.RequireAuth, routes.Validate)
    r.Run()
}
