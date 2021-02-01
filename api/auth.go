package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"goWeb/config"
	"goWeb/models"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // go-sql-driver/mysql
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/itrepablik/itrlog"
	"github.com/itrepablik/tago"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var err error

func connect() (db *sql.DB) {
	dbdrive := "mysql"
	db, err := sql.Open(dbdrive, config.DBConStr)
	if err != nil {
		panic(err.Error())
	}
	return db
}

// HashPassword this is Generate password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash this is comparatepassword
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// AuthRouters function
func AuthRouters(r *mux.Router) {
	r.HandleFunc("/api/v1/user/login", LoginUser).Methods("POST")
	r.HandleFunc("/api/v1/user/register", Register).Methods("POST")
	r.HandleFunc("/api/v1/user/getUser", GetAlluser).Methods("GET")
	r.HandleFunc("/api/v1/user/uptUser/{id:[0-9]+}", UpdateUser).Methods("PUT")
}

type jsonResponse struct {
	IsSuccess  string `json:"isSuccess"`
	AlertTitle string `json:"alertTitle"`
	AlertMsg   string `json:"alertMsg"`
	AlertType  string `json:"alertType"`
}

// LoginUser function
func LoginUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)

	body, errBody := ioutil.ReadAll(r.Body)
	if errBody != nil {
		itrlog.Error(errBody)
		panic(errBody.Error())
	}

	keyVal := make(map[string]string)
	json.Unmarshal(body, &keyVal)

	userName := strings.TrimSpace(keyVal["username"])
	password := keyVal["password"]
	isSiteKeepMe, _ := strconv.ParseBool(keyVal["isSiteKeepMe"])

	fmt.Print("userName: ", userName)
	fmt.Print("password: ", password)
	fmt.Print("isSiteKeepMe: ", isSiteKeepMe)

	itrlog.Info("userName: ", userName)
	itrlog.Info("password: ", password)
	itrlog.Info("isSiteKeepMe: ", isSiteKeepMe)

	// Check if form is empty
	if len(strings.TrimSpace(userName)) == 0 {
		w.Write([]byte(`{ "IsSuccess": "false", "AlertTitle": "Username is Required BK", "AlertMsg": "Please enter your username.", "AlertType": "error" }`))
		return
	}

	if len(password) == 0 {
		w.Write([]byte(`{ "IsSuccess": "false", "AlertTitle": "Password is Required BK", "AlertMsg": "Please enter your password.", "AlertType": "error" }`))
		return
	}

	// Set the cookie expiry in days.
	expDays := "1" // default to expire in 1 day.
	if isSiteKeepMe == true {
		expDays = config.UserCookieExp
	}

	// Encrypt the username value to store it from the user's cookie.
	encryptedUserName, err := tago.Encrypt(userName, config.MyEncryptDecryptSK)
	if err != nil {
		itrlog.Error(err)
	}

	dbCon := connect()
	var hashPassword string
	err = dbCon.QueryRow("SELECT password FROM users WHERE username = ?", userName).Scan(&hashPassword)
	if err != nil {
		fmt.Println("Error selecting encrypt in db by username")
		w.Write([]byte(`{ "isSuccess": "false", "AlertTitle": "Login Failed", "AlertMsg": "Please check Username and Password again",
		"AlertType": "error"}`))
		return
	}
	fmt.Println("inputan password:", password)
	fmt.Println("Encrypted password:", hashPassword)

	match := CheckPasswordHash(password, hashPassword)
	fmt.Println("Match :", match)

	if match != true {
		w.Write([]byte(`{ "isSuccess": "false", "AlertTitle": "Login Failed", "AlertMsg": "Please check Username and Password again",
		"AlertType": "error"}`))
		return
	}
	w.Write([]byte(`{ "isSuccess": "true", "AlertTitle": "Login Successful", "AlertMsg": "Your account has been verified and it's successfully logged-in.",
			"AlertType": "success", "redirectTo": "` + config.SiteBaseURL + `dashboard", "eUsr": "` + encryptedUserName + `", "expDays": "` + expDays + `" }`))

}

// Register function
func Register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)

	body, errBody := ioutil.ReadAll(r.Body)
	if errBody != nil {
		itrlog.Error(errBody)
		panic(errBody.Error())
	}

	users := make(map[string]string)
	json.Unmarshal(body, &users)

	username := strings.TrimSpace(users["username"])
	password := users["password"]
	confirmPassword := users["confirmPassword"]
	email := strings.TrimSpace(users["email"])
	country := users["country"]
	// firstName := keyVals["first_name"]
	// lastName := keyVals["last_name"]
	// isSuperuser := keyVals["is_superuser"]
	// isAdmin := keyVals["is_admin"]
	// dateJoined := keyVals["date_joined"]
	// isActive := keyVals["is_active"]
	rememberMe, _ := strconv.ParseBool(users["rememberMe"])

	fmt.Print("Username:", username)
	fmt.Print("Password:", password)
	fmt.Print("ConfirmPassword:", confirmPassword)
	fmt.Print("Email:", email)
	fmt.Print("Country:", country)
	// fmt.Print("First_name:", firstName)
	// fmt.Print("Last_name:", lastName)
	// fmt.Print("Superuser:", isSuperuser)
	// fmt.Print("Admin:", isAdmin)
	// fmt.Print("Date_joined:", dateJoined)
	// fmt.Print("Active:", isActive)
	fmt.Print("RemmberMe:", rememberMe)

	itrlog.Info("Username:", username)
	itrlog.Info("Password:", password)
	itrlog.Info("ConfirmPassword:", confirmPassword)
	itrlog.Info("Email:", email)
	itrlog.Info("Country:", country)
	// itrlog.Info("First_name:", firstName)
	// itrlog.Info("Last_name:", lastName)
	// itrlog.Info("Superuser:", isSuperuser)
	// itrlog.Info("Admin:", isAdmin)
	// itrlog.Info("Date_joined:", dateJoined)
	// itrlog.Info("Active:", isActive)
	itrlog.Info("RemmberMe:", rememberMe)

	if len(strings.TrimSpace(username)) == 0 {
		w.Write([]byte(`{"IsSuccess":"false", "AlertTitle":"Name is Required REG", "AlertMsg":"Please enter your Username", "AlertType":"error"}`))
	}

	if len(strings.TrimSpace(password)) == 0 {
		w.Write([]byte(`{"IsSuccess":"false", "AlertTitle":"Name is Required REG", "AlertMsg":"Please enter your Password", "AlertType":"error"}`))
	}

	if len(strings.TrimSpace(confirmPassword)) == 0 {
		w.Write([]byte(`{"IsSuccess":"false", "AlertTitle":"Name is Required REG", "AlertMsg":"Please enter your Confirm Password", "AlertType":"error"}`))
	}

	if len(strings.TrimSpace(email)) == 0 {
		w.Write([]byte(`{"IsSuccess":"false", "AlertTitle":"Name is Required REG", "AlertMsg":"Please enter your Email", "AlertType":"error"}`))
	}

	if len(strings.TrimSpace(country)) == 0 {
		w.Write([]byte(`{"IsSuccess":"false", "AlertTitle":"Name is Required REG", "AlertMsg":"Please enter your Country", "AlertType":"error"}`))
	}

	// if len(strings.TrimSpace(firstName)) == 0 {
	// 	w.Write([]byte(`{"IsSuccess":"false", "AlertTitle":"Name is Required REG", "AlertMsg":"Please enter your First Name", "AlertType":"error"}`))
	// }

	// if len(strings.TrimSpace(lastName)) == 0 {
	// 	w.Write([]byte(`{"IsSuccess":"false", "AlertTitle":"Name is Required REG", "AlertMsg":"Please enter your Last Name", "AlertType":"error"}`))
	// }

	// if len(strings.TrimSpace(isSuperuser)) == 0 {
	// 	w.Write([]byte(`{"IsSuccess":"false", "AlertTitle":"Name is Required REG", "AlertMsg":"Please enter your Superuser", "AlertType":"error"}`))
	// }

	// if len(strings.TrimSpace(isAdmin)) == 0 {
	// 	w.Write([]byte(`{"IsSuccess":"false", "AlertTitle":"Name is Required REG", "AlertMsg":"Please enter your Admin", "AlertType":"error"}`))
	// }

	expDays := "1"
	if rememberMe == true {
		expDays = config.UserCookieExp
	}

	encryptedUserName, err := tago.Encrypt(username, config.MyEncryptDecryptSK)
	if err != nil {
		itrlog.Error(err)
	}

	dbCon := connect()
	eUsr := encryptedUserName
	password, _ = HashPassword(password)

	insert, err := dbCon.Prepare("INSERT INTO users (username, password, country, email, eUsr, first_name, last_name," +
		"is_superuser, is_admin, date_joined, is_active) VALUES (?,?,?,?,?,?,?,?,?,?,?)")

	if err != nil {
		itrlog.Error(err)
	}

	insert.Exec(username, password, country, email, eUsr, "irul", "fadil", "super", "admin", time.Now(), 0)
	defer insert.Close()

	w.Write([]byte(`{"IsSuccess":"true", "AlertTitle":"Register Successful", "AlertMsg":"Your registed has been successful, please login to next aplication", 
					"AlertType":"success", "redirectTo":"` + config.SiteBaseURL + `", "eUsr":"` + encryptedUserName + `", "expDays":"` + expDays + `"}`))

}

// GetAlluser this is funtion all data from database to endpoint
func GetAlluser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusOK)

	dbCon := connect()
	stm := fmt.Sprintf("SELECT id, username, password, country, email, eUsr, first_name, last_name," +
		"is_superuser, is_admin, date_joined, is_active FROM users")
	rows, err := dbCon.Query(stm)
	if err != nil {
		fmt.Println("Error, Selecting in table")
		return
	}
	defer rows.Close()

	users := []models.Users{}

	for rows.Next() {
		var u models.Users
		if err := rows.Scan(&u.ID, &u.Username, &u.Password, &u.Country, &u.Email, &u.Eusr, &u.FirstName, &u.LastName, &u.IsSuperuser, &u.IsAdmin, &u.DateJoined, &u.IsActive); err != nil {
			return
		}
		users = append(users, u)
	}
	response, _ := json.Marshal(users)
	w.Write(response)
}

// UpdateUser this is function to update user table
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		fmt.Println(w, http.StatusBadRequest, "Invalid Request ID")
		return
	}

	var Users models.Users
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&Users); err != nil {
		fmt.Println(w, http.StatusBadRequest, "Invalid Request Payload")
		return
	}
	defer r.Body.Close()

	fmt.Println(Users)

	Users.ID = id
	dbCon := connect()
	layoutDateTime := "2006-01-02 15:04:05"
	stmt := fmt.Sprintf("UPDATE users SET username='%s', password='%s', country='%s', email='%s', eUsr='%s', first_name='%s', last_name='%s', is_superuser='%s', is_admin='%s', date_joined='%v', is_active='%s' WHERE id='%d'", Users.Username, Users.Password, Users.Country, Users.Email, Users.Eusr, Users.FirstName, Users.LastName, Users.IsSuperuser, Users.IsAdmin, time.Now().Format(layoutDateTime), Users.IsActive, Users.ID)
	_, err = dbCon.Exec(stmt)
	if err != nil {
		log.Printf(err.Error())
		return
	}

	response, _ := json.Marshal(Users)

	w.Header().Set("X-Csrf-Token", csrf.Token(r))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}
