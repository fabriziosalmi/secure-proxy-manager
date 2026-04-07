package main
import (
"fmt"
"time"
"github.com/golang-jwt/jwt/v5"
)
func main() {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()})
	str, _ := token.SignedString([]byte("secret"))
	fmt.Print(str)
}
