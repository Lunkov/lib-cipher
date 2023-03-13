package cipher

import (
  "time"
  rand "math/rand"
)

func GenerateRandomSeedString(min int, max int) string {
	rand.Seed(time.Now().UnixNano())
	n:=uint(min + rand.Intn( max - min))
	var letterRunes = []rune("adefghijkqrstvxyzABCDEFGHIJKLMNPQRSTUVWXYZ23456789")

    b := make([]rune, n)
    for i := range b {
        b[i] = letterRunes[rand.Intn(len(letterRunes))]
    }
    return string(b)
} 

