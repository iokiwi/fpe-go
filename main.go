package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"gitlab.com/ubiqsecurity/ubiq-fpe-go"
)

// var db = make(map[string]string)

type Payload struct {
	TokenData   string `json:"tokenData"`
	ProfileName string `json:"profileName"`
	AccessCode  string `json:"accessCode"`
}

type Batch []Payload


type App struct {
	Router *gin.Engine
	FF3    *ubiq.FF3_1
	Tweak  []byte
}

func NewApp() *App {

	key := []byte("01234567890123456789012345678901")
	tweak := []byte("0123456")
	radix := 32

	ff3, err := ubiq.NewFF3_1(key, tweak, radix)
	if err != nil {
		log.Fatalf("Error creating new FF3_1: %v", err)
	}

	router := gin.Default()

	app := &App{
		Router: router,
		FF3:    ff3,
		Tweak:  tweak,
	}

	app.routes()

	return app
}

func (app *App) routes() {
	app.Router.POST("/token", app.token)
	app.Router.POST("/detoken", app.detoken)
	app.Router.POST("/batch/token", app.batchToken)
	app.Router.POST("/batch/detoken", app.detoken)
}

func (app *App) token(c *gin.Context) {

	var payload Payload
	c.ShouldBind(&payload)

	ciphertext, err := app.FF3.Encrypt(payload.TokenData, app.Tweak)
	if err != nil {
		log.Fatalf("Error encrypting plaintext: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"value": ciphertext,
	})
}

func (app *App) detoken(c *gin.Context) {

	var payload Payload
	c.ShouldBind(&payload)

	plaintext, err := app.FF3.Decrypt(payload.TokenData, app.Tweak)
	if err != nil {
		log.Fatalf("Error encrypting plaintext: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"value": plaintext,
	})
}


func (app *App) batchToken(c *gin.Context) {

	var batch Batch
	if c.ShouldBind(&batch) == nil {
		// fmt.Printf("%v\n", json.MarshalIndent(batch))
	}

	results := make([]map[string]string, len(batch))
	for i, payload := range batch {
		ciphertext, err := app.FF3.Encrypt(payload.TokenData, app.Tweak)
		if err != nil {
			log.Fatalf("Error encrypting plaintext: %v", err)
		}
		results[i] = map[string]string{"value": ciphertext}
	}
	c.JSON(http.StatusOK, results)
}


func (app *App) batchDetoken(c *gin.Context) {
	var batch Batch
	if c.ShouldBind(&batch) == nil {
		// fmt.Printf("%v\n", json.MarshalIndent(batch))
	}

	results := make([]map[string]string, len(batch))
	for i, payload := range batch {
		plaintext, err := app.FF3.Decrypt(payload.TokenData, app.Tweak)
		if err != nil {
			log.Fatalf("Error encrypting plaintext: %v", err)
		}
		results[i] = map[string]string{"value": plaintext}
	}
	c.JSON(http.StatusOK, results)
}


func main() {
	app := NewApp()
	r := app.Router
	// Listen and Server in 0.0.0.0:8080
	r.Run(":8080")
}
