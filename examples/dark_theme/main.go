package main

import (
	"fmt"
	"image/color"
	"log"
	"net/http"
	"time"

	og "onionguard"
	"onionguard/middleware"
)

func main() {
	cfg := og.DefaultConfig()

	// 1. Personnalisation graphique du PNG (Style Dark Terminal)
	cfg.Captcha.Visual = og.CaptchaVisualConfig{
		BackgroundColor: color.RGBA{R: 18, G: 18, B: 18, A: 255},  // Noir profond
		TextColor:       color.RGBA{R: 0, G: 255, B: 128, A: 255}, // Vert néon
		LineColor:       color.RGBA{R: 60, G: 60, B: 80, A: 180},  // Bleu sombre
		NoiseLines:      3,
		NoiseRatio:      0.015,
		JitterPixels:    3,
	}

	// 2. Page de file d'attente (Auto-refresh sans JS pour Tor)
	cfg.CustomWaitRoomHTML = func(r *http.Request, retry time.Duration) string {
		sec := int(retry.Seconds())
		if sec < 1 {
			sec = 1
		}
		return fmt.Sprintf(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="%d">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <title>Patientez</title>
  <style>
    body { background: #121212; color: #e0e0e0; font-family: monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .box { border: 1px solid #333; padding: 2rem; border-radius: 4px; text-align: center; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Vérification en cours</h2>
    <p>Accès au service dans %d seconde(s)...</p>
  </div>
</body>
</html>`, sec, sec)
	}

	// 3. Page de CAPTCHA
	cfg.CustomChallengeHTML = func(r *http.Request, ch *og.CaptchaChallenge, ccfg og.CaptchaConfig) string {
		return fmt.Sprintf(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'">
  <title>Défi</title>
  <style>
    body { background: #121212; color: #fff; font-family: monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    form { display: flex; flex-direction: column; gap: 10px; border: 1px solid #00ff80; padding: 20px; }
    input, button { background: #222; border: 1px solid #444; color: #00ff80; padding: 8px; font-family: monospace; }
    button { cursor: pointer; }
  </style>
</head>
<body>
  <form method="post" action="%s">
    <img src="%s" alt="CAPTCHA" style="border: 1px solid #333;">
    <input name="answer" maxlength="%d" placeholder="Recopiez le texte" autofocus required autocomplete="off">
    <button type="submit">Valider</button>
  </form>
</body>
</html>`, ccfg.EndpointPath, ch.ImageDataURI, ccfg.Length)
	}

	// 4. Page d'erreur générique (Rate limit, session expirée)
	cfg.CustomErrorHTML = func(r *http.Request, adm *og.AdmissionError) string {
		return fmt.Sprintf(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>%s</title><style>body{background:#121212;color:#ff5555;font-family:monospace;padding:2rem;}</style></head>
<body>
  <h1>Erreur %d (%s)</h1>
  <p>%s</p>
  <a href="/" style="color:#00ff80;">Retour à l'accueil</a>
</body>
</html>`, adm.Code, adm.StatusCode, adm.Code, adm.Message)
	}

	engine, err := og.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Bienvenue sur le service protégé par OnionGuard !\n"))
	})

	h := middleware.Middleware(engine)(mux)
	server := &http.Server{
		Addr:              ":8082",
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	log.Printf("Dark theme example running on http://localhost%s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
