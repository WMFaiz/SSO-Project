package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"Server/Modules"
	"Server/Routes"
	"Server/Utils"

	// "golang.org/x/oauth2"

	"github.com/julienschmidt/httprouter"
	_ "github.com/lib/pq"
)

func main() {
	//Init Database
	Utils.DBInitialization()
	defer Utils.DBClose()

	//Start context
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Start Router Server
	ROUTER := httprouter.New()
	go Routes.InitAndStartRouter(ROUTER)

	// Start OAuth2 Server
	go Modules.OAuthAuthenticator()

	//Exit context
	<-ctx.Done()
	log.Println("Main: Received shutdown signal")
	stop()
	log.Println("Main: All servers stopped gracefully")
}
