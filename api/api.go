package main

import (
	"encoding/json"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"net/http"
	"strings"
)

const KeySecret string = "iam-poc"

type UserClaims struct {
	//Id     int
	RoleID []uuid.UUID
	jwt.RegisteredClaims
}

type TokenResponse struct {
	Token string `json:"token"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/user-token/", getUserToken)
	http.ListenAndServe(":8181", mux)
}
func getUserToken(w http.ResponseWriter, r *http.Request) {
	urlPath := r.URL.Path
	parts := strings.Split(urlPath, "/")
	userIDString := parts[len(parts)-1]
	//userID, err := strconv.Atoi(userIDString)
	//if err != nil {
	//	http.Error(w, "Invalid user ID", http.StatusBadRequest)
	//	return
	//}
	roleId := uuid.NewSHA1(uuid.Nil, []byte(userIDString))
	randomRoleId, _ := uuid.NewRandom()
	signingKeySecret := []byte(KeySecret)

	userClaims := UserClaims{
		//Id:     userID,
		RoleID: []uuid.UUID{roleId, randomRoleId},
		RegisteredClaims: jwt.RegisteredClaims{
			ID: userIDString,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaims)
	tokenString, err := token.SignedString(signingKeySecret)

	response := TokenResponse{Token: tokenString}
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonBytes)
}
