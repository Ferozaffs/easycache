package main

import (
	"context"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"easycache/internal/cache"
	"easycache/internal/discovery"
)

func main() {
	addr := flag.String("addr", env("CACHE_ADDR", ":8765"), "HTTP listen address")
	dir := flag.String("dir", env("CACHE_DIR", "./cachedata"), "storage directory")
	instance := flag.String("name", env("CACHE_NAME", "easycache"), "zero-config instance name")
	advertise := flag.Bool("advertise", boolEnv("CACHE_ADVERTISE", true), "announce via mDNS/zero-config")
	flag.Parse()

	log.SetFormatter(&log.TextFormatter{})
	log.SetLevel(log.InfoLevel)
	log.SetOutput(os.Stdout)

	store, err := cache.Open(*dir)
	if err != nil {
		log.WithError(err).Fatal("open cache store")
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.WithError(err).Fatal("listen")
	}
	port := ln.Addr().(*net.TCPAddr).Port
	log.Infof("cache listening on %s (dir %s)", ln.Addr(), *dir)

	if *advertise {
		go announce(*instance, port)
	}

	h := cache.NewHandler(store)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		_ = ln.Close()
	}()

	log.Infof("serving /check and /upload (instance %q)", *instance)
	if err := http.Serve(ln, h.Routes()); err != nil && ctx.Err() == nil {
		log.WithError(err).Fatal("serve")
	}
}

func announce(instance string, port int) {
	svr, err := discovery.Register(instance, port, map[string]string{
		"http": "1",
		"name": instance,
		"ver":  "1",
	})
	if err != nil {
		log.WithError(err).Warn("mDNS advertise unavailable; continuing without discovery")
		return
	}
	log.Infof("advertising %s.%s on port %d", instance, discovery.Service, port)
	<-time.After(3650 * 24 * time.Hour)
	svr.Shutdown()
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func boolEnv(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}
