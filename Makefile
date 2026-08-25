# SDP-1: Semantic Delta Proof Engine
# Simple Makefile to manage build, run, stop, status, ui, and test operations.
# Inspired by EUDI Makefile architecture.
#
# Quick Start:
#   make run     # builds (if needed) and starts the Spring Boot API service
#   make ui      # opens the demo console in your default browser
#   make stop    # stops the service and cleans orphaned processes
#   make status  # displays service health status
#   make logs    # tails API log file
#   make test    # runs Rust and Java test suites

SHELL := /bin/bash

RUN_DIR := .run
API_LOG := $(RUN_DIR)/api.log
API_PID := $(RUN_DIR)/api.pid

API_URL := http://localhost:8080
JAR     := sdp-api/target/sdp-api-0.1.0-SNAPSHOT.jar

# Find Java & Maven executables
MVN_BIN := $(shell command -v mvn 2>/dev/null || echo "./mvnw")

.PHONY: all build build-engine build-api run start stop restart status logs \
        ui test test-engine test-api clean help

all: help

help:
	@echo "==================================================================="
	@echo "               SDP-1 Semantic Delta Proof Engine                   "
	@echo "==================================================================="
	@echo ""
	@echo "  make run      build (if needed) and start the SDP-1 API service"
	@echo "  make ui       open the demo console at $(API_URL)/"
	@echo "  make status   show service status and health"
	@echo "  make logs     tail service log (ctrl-c to stop watching)"
	@echo "  make stop     stop the service and kill orphaned processes"
	@echo "  make restart  stop then run"
	@echo "  make test     run Rust engine + Java API test suites"
	@echo "  make clean    stop service and remove build artifacts"
	@echo ""
	@echo "Service URLs:"
	@echo "  Demo Console : $(API_URL)/"
	@echo "  Swagger (api): $(API_URL)/swagger-ui.html"
	@echo "  Swagger (eng): $(API_URL)/swagger-ui/"
	@echo "==================================================================="

# ---- build -------------------------------------------------------------

ENGINE_SRC := $(shell find sdp-engine/src -type f 2>/dev/null) sdp-engine/Cargo.toml sdp-engine/Cargo.lock
JAVA_SRC   := $(shell find sdp-api/src -type f 2>/dev/null) sdp-api/pom.xml

build: build-engine build-api

build-engine:
	@echo "Building Rust engine core..."
	@cd sdp-engine && cargo build --release

build-api: $(JAR)

$(JAR): $(JAVA_SRC)
	@echo "Building Java Spring Boot API JAR..."
	@cd sdp-api && $(MVN_BIN) clean package -DskipTests

# ---- run / stop ----------------------------------------------------------

run: start

start: $(RUN_DIR)
	@if [ -f $(API_PID) ] && kill -0 $$(cat $(API_PID)) 2>/dev/null; then \
		echo "SDP API service is already running (pid $$(cat $(API_PID)))"; \
	else \
		$(MAKE) $(JAR); \
		echo "Starting SDP API service on port 8080..."; \
		java --enable-native-access=ALL-UNNAMED -jar $(JAR) > $(API_LOG) 2>&1 & echo $$! > $(API_PID); \
	fi
	@echo -n "Waiting for service health"; \
	for i in $$(seq 1 40); do \
		curl -sf $(API_URL)/ >/dev/null 2>&1 && { echo " OK"; break; }; \
		echo -n "."; sleep 1; \
		if [ $$i -eq 40 ]; then echo " FAILED — inspect $(API_LOG)"; exit 1; fi; \
	done
	@owner=$$(lsof -t -i :8080 -sTCP:LISTEN 2>/dev/null | head -1); \
	tracked=$$(cat $(API_PID) 2>/dev/null); \
	if [ -n "$$owner" ] && [ "$$owner" != "$$tracked" ]; then \
		echo "WARNING: Port 8080 is being served by pid $$owner, not tracked pid $$tracked."; \
		echo "Run 'make stop' then 'make run' again."; \
	fi
	@echo ""
	@echo "SDP-1 Service is running live:"
	@echo "  Demo Console : $(API_URL)/"
	@echo "  Swagger (api): $(API_URL)/swagger-ui.html"
	@echo "  Swagger (eng): $(API_URL)/swagger-ui/"

stop:
	@if [ -f $(API_PID) ]; then \
		pid=$$(cat $(API_PID)); \
		if kill -0 $$pid 2>/dev/null; then \
			kill $$pid 2>/dev/null && echo "Stopped SDP API service (pid $$pid)" || true; \
		else \
			echo "API process $$pid not running"; \
		fi; \
		rm -f $(API_PID); \
	else \
		echo "API process not tracked in $(API_PID)"; \
	fi
	@for p in $$(lsof -t -i :8080 -sTCP:LISTEN 2>/dev/null); do \
		echo "Killing untracked process listening on port 8080 (pid $$p)"; \
		kill -9 $$p 2>/dev/null || true; \
	done

restart: stop run

status:
	@printf "%-18s" "sdp-api service:"; \
	if [ -f $(API_PID) ] && kill -0 $$(cat $(API_PID)) 2>/dev/null; then \
		curl -sf $(API_URL)/ >/dev/null 2>&1 && echo "RUNNING, HEALTHY (pid $$(cat $(API_PID)))" \
			|| echo "RUNNING, UNHEALTHY (pid $$(cat $(API_PID)))"; \
	else \
		owner=$$(lsof -t -i :8080 -sTCP:LISTEN 2>/dev/null | head -1); \
		if [ -n "$$owner" ]; then \
			echo "RUNNING on 8080 (untracked pid $$owner)"; \
		else \
			echo "STOPPED"; \
		fi; \
	fi

logs:
	@if [ -f $(API_LOG) ]; then \
		tail -f $(API_LOG); \
	else \
		echo "No log file found at $(API_LOG). Run 'make run' first."; \
	fi

$(RUN_DIR):
	@mkdir -p $(RUN_DIR)

# ---- UI & Demo -----------------------------------------------------------

ui: run
	@echo "Opening $(API_URL)/ in browser..."
	@open $(API_URL)/ 2>/dev/null \
		|| xdg-open $(API_URL)/ 2>/dev/null \
		|| powershell.exe -c "Start-Process '$(API_URL)/'" 2>/dev/null \
		|| echo "Open $(API_URL)/ manually in your web browser."

# ---- tests -----------------------------------------------------------

test: test-engine test-api

test-engine:
	@echo "Running Rust core engine unit tests..."
	@cd sdp-engine && cargo test

test-api:
	@echo "Running Java API tests..."
	@cd sdp-api && $(MVN_BIN) test

# ---- clean -----------------------------------------------------------

clean: stop
	@echo "Cleaning Rust & Java build artifacts..."
	@cd sdp-engine && cargo clean 2>/dev/null || true
	@cd sdp-api && $(MVN_BIN) clean 2>/dev/null || true
	@rm -rf $(RUN_DIR)
