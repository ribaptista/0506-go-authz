package main

import (
	"log"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
)

type Contract struct {
	Id string
}

func main() {
	enforcer, err := casbin.NewEnforcer("authz/rest/model.conf", "authz/rest/policy.csv")
	if err != nil {
		log.Fatal("Failed to load enforcer" + err.Error())
	}

	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Key: []byte("secret key"),
		Authorizator: func(data interface{}, c *gin.Context) bool {
			claims := jwt.ExtractClaims(c)
			role := claims["cognito:groups"].([]interface{})[0].(string)
			log.Printf("Role: %s", role)

			method := c.Request.Method
			path := c.Request.URL.Path

			log.Printf("Method: %s", method)
			log.Printf("Path: %s", path)

			ok, err := enforcer.Enforce(role, path, method)

			if err != nil {
				log.Println("Failed to enforce" + err.Error())
				return false
			}

			return ok
		},
	})

	if err != nil {
		log.Fatal("jwt.New() Error:" + err.Error())
	}

	err = authMiddleware.MiddlewareInit()
	authzMiddleware := authMiddleware.MiddlewareFunc()

	if err != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + err.Error())
	}

	r := gin.Default()

	r.GET("/contracts", authzMiddleware, func(c *gin.Context) {
		c.JSON(200, gin.H{
			"results": []Contract{
				{Id: "100"},
				{Id: "200"},
				{Id: "300"},
				{Id: "400"},
			},
		})
	})

	r.GET("/contracts/:id", authzMiddleware, func(c *gin.Context) {
		c.JSON(200, Contract{Id: c.Params.ByName("id")})
	})

	r.POST("/contracts", authzMiddleware, func(c *gin.Context) {
		c.Status(204)
	})

	r.DELETE("/contracts/:id", authzMiddleware, func(c *gin.Context) {
		c.Status(204)
	})

	r.NoRoute(authzMiddleware, func(c *gin.Context) {
		c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
	})

	r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}
