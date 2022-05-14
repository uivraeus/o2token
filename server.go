package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"
)

func serveAuthCodeFlow() {
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("public"))
	mux.Handle("/", noCache(fs))
	mux.HandleFunc(appConfig.CallbackPath, oauth2CodeCallback)
	mux.HandleFunc("/login", startFlow)

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

// https://stackoverflow.com/questions/33880343/go-webserver-dont-cache-files-using-timestamp
func noCache(h http.Handler) http.Handler {
	var epoch = time.Unix(0, 0).Format(time.RFC1123)
	var noCacheHeaders = map[string]string{
		"Expires":         epoch,
		"Cache-Control":   "no-cache, private, max-age=0",
		"Pragma":          "no-cache",
		"X-Accel-Expires": "0",
	}

	var etagHeaders = []string{
		"ETag",
		"If-Modified-Since",
		"If-Match",
		"If-None-Match",
		"If-Range",
		"If-Unmodified-Since",
	}

	fn := func(w http.ResponseWriter, r *http.Request) {
		// Delete any ETag headers that may have been set
		for _, v := range etagHeaders {
			if r.Header.Get(v) != "" {
				r.Header.Del(v)
			}
		}

		// Set our NoCache headers
		for k, v := range noCacheHeaders {
			w.Header().Set(k, v)
		}

		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
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
