package Routes

import (
	Controller "Server/Controllers"
	"log"
	"net/http"

	"github.com/fatih/color"
	"github.com/julienschmidt/httprouter"
)

func InitAndStartRouter(router *httprouter.Router) {
	var appController Controller.Controller
	AppRouter(router, &appController)

	color.Green("Router is running on http://127.0.0.1:9097")
	log.Fatal(http.ListenAndServe(":9097", router))
}

func AppRouter(router *httprouter.Router, appController *Controller.Controller) {
	router.POST("/YOUR_PATH/auth/login", appController.Login)
	router.POST("/YOUR_PATH/auth/logout", appController.Logout)
	router.POST("/YOUR_PATH/auth/saltedhashed", appController.SaltedHashed)
	router.POST("/YOUR_PATH/jwt/check-session", appController.CheckSession)
	router.POST("/YOUR_PATH/discourse/authorize/sso", appController.DiscourseSSO)
	router.GET("/YOUR_PATH/discourse/authorize/fetch-news", appController.DiscourseFetchNews)
	router.GET("/YOUR_PATH/discourse/authorize/fetch-news-by-id", appController.DiscourseFetchNewsById)
}
