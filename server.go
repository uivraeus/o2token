package main

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"
)

//Embed html for the served endpoints to make the binary self-standing

//go:embed html/index.html
var indexPage string

//go:embed html/success.html
var successPage string

var indexPath = "/"
var loginPath = "/login"
var successPath = "/success"

func serveAuthCodeFlow() {
	mux := http.NewServeMux()
	mux.HandleFunc(successPath, serveEmbeddedPage)
	mux.HandleFunc(appConfig.CallbackPath, oauth2CodeCallback)
	mux.HandleFunc(loginPath, startFlow)
	mux.HandleFunc(indexPath, serveEmbeddedPage)

	portStr := fmt.Sprintf(":%v", appConfig.Port)
	loginUrlStr := fmt.Sprintf("http://localhost%v/login\n", portStr)
	server := &http.Server{Addr: portStr, Handler: mux}

	go func() {
		fmt.Fprintf(os.Stderr, "Serving oauth2 authorization code flow at 👉 %v\n", loginUrlStr)
		serveErr := server.ListenAndServe()
		if serveErr != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "ERROR: Unexpected error from HTTP server: %v\n", serveErr)
		}
	}()

	go func() {
		if !appConfig.NoBrowser {
			time.Sleep(10 * time.Millisecond) // ensure proper print-out order (a bit dirty...)
			launchBrowser(loginUrlStr)
		}
	}()

	// Setting up signal capturing
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// Waiting for SIGINT (kill -2)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Unexpected error when closing server: %v\n", err)
	}
}

func serveEmbeddedPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == indexPath {
		serveString(indexPage, w)
	} else if r.URL.Path == successPath {
		serveString(successPage, w)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func serveString(value string, w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	w.Write(([]byte)(value))
}

func reportErrorAndSoftExit(label string, err error, code int, w http.ResponseWriter) {
	msg := fmt.Sprintf("ERROR: %v: %v", label, err)
	if w != nil {

		w.WriteHeader(code)
		w.Write(([]byte)(msg))
	}
	fmt.Fprintln(os.Stderr, msg)
	softExit(code)
}
