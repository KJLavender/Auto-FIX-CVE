package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	yaml "gopkg.in/yaml.v2"
)

type config struct {
	Port string `yaml:"port"`
}

func main() {
	var cfg config
	_ = yaml.Unmarshal([]byte("port: 8080"), &cfg)

	router := gin.Default()
	router.GET("/health", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	_ = router.Run(":" + cfg.Port)
}
