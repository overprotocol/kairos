// Copyright 2024 The kairos Authors
// This file is part of the kairos library.
//
// The kairos library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The kairos library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the kairos library. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

type Server struct {
	handler *Handler
}

func NewServer(handler *Handler) *Server {
	return &Server{handler}
}

func (s *Server) start() {
	app := fiber.New(fiber.Config{
		ReadTimeout:  rpc.DefaultHTTPTimeouts.ReadTimeout,
		WriteTimeout: rpc.DefaultHTTPTimeouts.WriteTimeout,
		IdleTimeout:  rpc.DefaultHTTPTimeouts.IdleTimeout,
	})

	app.Use(recover.New())

	app.Use(cors.New(cors.Config{
		AllowOrigins: *corsDomainFlag,
	}))

	app.Use("/", func(c *fiber.Ctx) error {
		start := time.Now()
		defer func() {
			end := time.Since(start)

			log.Printf("[AccessLog] %s - %d %d %v - %s\n", getRemoteIP(c), c.Response().StatusCode(), len(c.Response().Body()), end, string(c.Request().RequestURI()))
		}()

		c.Response().Header.SetContentType("application/json")

		return c.Next()
	})

	app.Get("/minimumFee", func(ctx *fiber.Ctx) error {
		return ctx.Status(200).SendString(s.handler.HandleMinimumFee())
	})

	app.Get("/feeRecipient", func(ctx *fiber.Ctx) error {
		return ctx.Status(200).SendString(s.handler.HandleFeeRecipient())
	})

	app.Post("/requestRestoration", func(ctx *fiber.Ctx) error {
		restoreDataArgs := new(RestoreDataArgs)
		if err := ctx.BodyParser(restoreDataArgs); err != nil {
			return ctx.Status(400).SendString(err.Error())
		}
		restoreData := restoreDataArgs.toRestoreData()
		txHash, err := s.handler.HandleRequestRestoration(ctx.Context(), restoreData)
		if err != nil {
			return ctx.Status(400).SendString(err.Error())
		}
		return ctx.Status(200).SendString(txHash)
	})

	go func() {
		if err := app.Listen(*portFlag); err != nil {
			log.Printf("Listen Error %+v\n", err)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	log.Println("Gracefully shutting down...")
	app.Shutdown()
}

func getRemoteIP(ctx *fiber.Ctx) string {
	xForwardedFor := ctx.Request().Header.Peek("x-forwarded-for")
	if xForwardedFor != nil {
		return string(xForwardedFor)
	}

	return ctx.Context().RemoteIP().String()
}
