package main

import (
	"webapp/initializers"
	"webapp/middleware"
	"webapp/routes"

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
	// r.GET("/validate", middleware.RequireAuth, routes.Validate)
	r.POST("/addtask", middleware.RequireAuth, routes.CreateTask)
	r.POST("/addrole", middleware.RequireAuth, routes.AddRole)
	r.DELETE("/deleterole", middleware.RequireAuth, routes.DeleteRole)
	r.POST("/addgroup", middleware.RequireAuth, routes.AddGroup)
	r.DELETE("/deletegroup", middleware.RequireAuth, routes.DeleteGroup)
	r.POST("/user/addrole", middleware.RequireAuth, routes.AddUserRole)
	r.DELETE("/user/deleterole", middleware.RequireAuth, routes.DeleteUserRole)
	r.POST("/user/addgroup", middleware.RequireAuth, routes.AddUserGroup)
	r.DELETE("/user/deletegroup", middleware.RequireAuth, routes.DeleteUserGroup)
	r.POST("/task/addrole", middleware.RequireAuth, routes.AddTaskRole)
	r.DELETE("/task/deleterole", middleware.RequireAuth, routes.DeleteTaskRole)
	r.POST("/task/addgroup", middleware.RequireAuth, routes.AddTaskGroup)
	r.DELETE("/task/deletegroup", middleware.RequireAuth, routes.DeleteTaskGroup)
	r.PATCH("/updatetask", middleware.RequireAuth, routes.UpdateTask)
	r.DELETE("/deletetask", middleware.RequireAuth, routes.DeleteTask)
	r.GET("/logout", routes.Logout)
	r.DELETE("/deleteuser", middleware.RequireAuth, routes.DeleteUser)
	r.POST("/uploadusers", routes.ParseUserCSV)
	r.POST("/uploadtasks", routes.ParseTaskCSV)

	r.Run()
}
