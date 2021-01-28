package api

import (
	"fmt"
	"goWeb/config"
	"html/template"
	"net/http"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
)

// MainRouters are the collection of all URLs for the Main App.
func MainRouters(r *mux.Router) {
	//Router Login admin
	r.HandleFunc("/", Home).Methods("GET")
	r.HandleFunc("/signup", AccountSignup).Methods("GET")
	r.HandleFunc("/passrecover", PasswordRecover).Methods("GET")

	//Router Homepage
	r.HandleFunc("/product/{product_name}/{id:[0-9]+}", ProductInfo).Methods("GET")
	r.HandleFunc("/articles/{category}/", ArticlesCategoryHandler).Methods("GET")

	// Router Dashboard
	r.HandleFunc("/dashboard", Dashboard).Methods("GET")
}

// contextData are the most widely use common variables for each pages to load.
type contextData map[string]interface{}

// Home function is to render the homepage page.
func Home(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles(config.SiteRootTemplate+"front/index.html", config.SiteHeaderTemplate, config.SiteFooterTemplate))

	data := contextData{
		"PageTitle":    "Login SIM",
		"PageMetaDesc": config.SiteSlogan,
		"CanonicalURL": r.RequestURI,
		"CsrfToken":    csrf.Token(r),
		"Settings":     config.SiteSettings,
	}
	tmpl.Execute(w, data)
}

// AccountSignup function is to render new account page.
func AccountSignup(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles(config.SiteRootTemplate+"front/account-sign-up.html", config.SiteHeaderTemplate, config.SiteFooterTemplate))

	data := contextData{
		"PageTitle":    "SignUp SIM",
		"PageMetaDesc": config.SiteSlogan,
		"CanonicalURL": r.RequestURI,
		"CsrfToken":    csrf.Token(r),
		"Settings":     config.SiteSettings,
	}
	tmpl.Execute(w, data)
}

// PasswordRecover function is to render password reocver page.
func PasswordRecover(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles(config.SiteRootTemplate+"front/account-password-recover.html", config.SiteHeaderTemplate, config.SiteFooterTemplate))

	data := contextData{
		"PageTitle":    "Recover SIM",
		"PageMetaDesc": config.SiteSlogan,
		"CanonicalURL": r.RequestURI,
		"CsrfToken":    csrf.Token(r),
		"Settings":     config.SiteSettings,
	}
	tmpl.Execute(w, data)
}

// ArticlesCategoryHandler function
func ArticlesCategoryHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Category: %v\n", vars["category"])
}

// ProductInfo function
func ProductInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Product Name: %v\n", vars["product_name"])
	fmt.Fprintf(w, "Product ID: %v\n", vars["id"])
}

// Dashboard function is to render Homepage admin page.
func Dashboard(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles(config.SiteRootTemplate+"dashboard/dashboard.html", config.SiteHeaderTemplate, config.SiteFooterTemplate))

	data := contextData{
		"PageTitle":    "Dashboard SIM",
		"PageMetaDesc": config.SiteSlogan,
		"CanonicalURL": r.RequestURI,
		"CsrfToken":    csrf.Token(r),
		"Settings":     config.SiteSettings,
	}
	tmpl.Execute(w, data)
}
