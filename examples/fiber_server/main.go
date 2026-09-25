package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	og "github.com/ihatemyfcklife/onionguard"
	ogfiber "github.com/ihatemyfcklife/onionguard/middleware/fiber"
)

func main() {
	cfg := og.DefaultConfig()
	engine, err := og.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()

	app := fiber.New(fiber.Config{BodyLimit: int(cfg.MaxBodyBytes)})
	app.Use(ogfiber.Middleware(engine))
	app.Get("/", func(c *fiber.Ctx) error { c.Type("text", "utf-8"); return c.SendString("onionguard: admitted\n") })
	app.Get("/healthz", func(c *fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })
	log.Fatal(app.Listen(":8081"))
}
