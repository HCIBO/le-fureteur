package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"golang.org/x/text/language"
)

func main() {
	tag, _ := language.Parse("tr-TR")
	r := gin.Default()
	fmt.Println(tag, r)
}
