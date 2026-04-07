package main
import "os"
func main() {
    err := os.WriteFile("/nonexistent/file.txt", []byte("1"), 0o600)
    if err != nil {
        println("Error:", err.Error())
    } else {
        println("Success")
    }
}
