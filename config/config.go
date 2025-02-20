package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	BaseUrl       string
	EntityID      string
	Location      string
	AssertUrl     string
	TemplatePath  string
	SpEntityID    string
	ResponseLimit int
}

// NewConfig creates a new Config with default values
func NewConfig() *Config {
	// load env
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	baseUrl := os.Getenv("BASE_URL")
	assertUrl := os.Getenv("ASSERT_URL")
	spEntityID := os.Getenv("SP_ENTITY_URL")
	timeLimit := os.Getenv("SAML_RESPONSE_LIMIT_MINUTES")
	timeLimitInt, err := strconv.Atoi(timeLimit)
	if err != nil {
		// set default
		timeLimitInt = 5
	}

	return &Config{
		BaseUrl:       baseUrl,
		EntityID:      baseUrl + "/metadata",
		Location:      baseUrl + "/login",
		TemplatePath:  "template/login.html",
		AssertUrl:     assertUrl,
		SpEntityID:    spEntityID,
		ResponseLimit: timeLimitInt,
	}
}
