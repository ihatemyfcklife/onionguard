package main

import (
	"log"
	"net/http"
	"time"

	og "github.com/ihatemyfcklife/onionguard"
	"github.com/ihatemyfcklife/onionguard/middleware"
)

func main() {
	cfg := og.DefaultConfig()
	cfg.WaitRoom.WaitTime = 5 * time.Second
	cfg.Captcha.Enabled = true
	engine, err := og.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("onionguard: admitted\n"))
	})

	h := middleware.Middleware(engine)(mux)
	server := &http.Server{Addr: ":8080", Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	log.Printf("onionguard example listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
