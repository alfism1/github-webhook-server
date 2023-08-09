package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

const (
	port = ":8080"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		return
	}

	router := gin.Default()
	router.POST("/webhook", handleWebhook)
	fmt.Println("Webhook server listening on port", port)
	router.Run(port)
}

func handleWebhook(c *gin.Context) {
	secret := os.Getenv("WEBHOOK_SECRET")
	if secret == "" {
		c.String(http.StatusInternalServerError, "Webhook secret not set")
		return
	}

	signature := c.GetHeader("X-Hub-Signature")
	payload, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to read request body")
		return
	}

	if !verifySignature(secret, signature, payload) {
		c.String(http.StatusUnauthorized, "Invalid signature")
		return
	}

	eventType := c.GetHeader("X-GitHub-Event")
	if eventType == "push" {
		// Handle code push event, e.g., pull latest code, run tests, deploy, etc.
		fmt.Println("Code pushed to the repository")
	} else {
		fmt.Println("Received GitHub event:", eventType)
	}

	c.String(http.StatusOK, "Webhook received and processed")
}

func verifySignature(secret, signature string, payload []byte) bool {
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))
	return "sha1="+expectedMAC == signature
}
