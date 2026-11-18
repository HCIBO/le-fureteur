module example.com/app

go 1.20

require (
	github.com/gin-gonic/gin v1.6.3
	golang.org/x/text v0.3.6 // indirect
)

require github.com/dgrijalva/jwt-go v3.2.0+incompatible

replace github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.7.0
