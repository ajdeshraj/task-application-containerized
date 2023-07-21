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
    initializers.InsertRoleDb()
    initializers.InsertGroupDb()
}

func main() {
    r := gin.Default()

    r.POST("/signup", routes.SignUp)
    r.POST("/login", routes.Login)
    r.GET("/validate", middleware.RequireAuth, routes.Validate)
    r.POST("/addtask", middleware.RequireAuth, routes.CreateTask)
    r.POST("/addrole", middleware.RequireAuth, routes.AddRole)
    r.DELETE("/deleterole", middleware.RequireAuth, routes.DeleteRole)
    r.POST("/addgroup", middleware.RequireAuth, routes.AddGroup)
    r.DELETE("/deletegroup", middleware.RequireAuth, routes.DeleteGroup)

    r.Run()
}
