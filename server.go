package main

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

//go:embed html/index.html
var indexPage string

var indexPath = "/"
var loginPath = "/login"

// Graceful exit after server has been started
var serverExit = func() {
	os.Exit(1) // Placeholder until signal capturing has been configured
}

func serveAuthCodeFlow() {
	mux := http.NewServeMux()
	mux.HandleFunc(appConfig.CallbackPath, oauth2CodeCallback)
	mux.HandleFunc(loginPath, startFlow)
	mux.HandleFunc(indexPath, serveEmbeddedPage)

	portStr := fmt.Sprintf(":%v", appConfig.Port)
	loginUrlStr := fmt.Sprintf("http://localhost%v/login\n", portStr)
	server := &http.Server{Addr: portStr, Handler: mux}

	go func() {
		serveErr := server.ListenAndServe()
		if serveErr != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "ERROR: Unexpected error from HTTP server: %v\n", serveErr)
		}
	}()

	go func() {
		manualLaunch := appConfig.NoBrowser || launchBrowser(loginUrlStr) != nil
		if manualLaunch {
			fmt.Fprintf(os.Stderr, "👉 Initiate login flow via your browser at: %v\n", loginUrlStr)
		}
	}()

	// Setting up signal capturing and configure special exit-function
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	serverExit = func() {
		stop <- syscall.SIGINT
	}

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
