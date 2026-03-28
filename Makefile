.PHONY: help build run stop logs test clean get-chat-id

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build Docker image
	docker build -t mtproto-checker .

run: ## Run checker with docker-compose
	docker-compose up -d

stop: ## Stop checker
	docker-compose down

logs: ## Show logs
	docker-compose logs -f

restart: stop run ## Restart checker

test: ## Run tests
	python3 test_checker.py

clean: ## Clean up containers and images
	docker-compose down -v
	docker rmi mtproto-checker 2>/dev/null || true

get-chat-id: ## Get Telegram chat ID (requires BOT_TOKEN env var)
	@if [ -z "$$BOT_TOKEN" ]; then \
		echo "Error: BOT_TOKEN environment variable not set"; \
		echo "Usage: BOT_TOKEN=your_token make get-chat-id"; \
		exit 1; \
	fi
	python3 checker.py --get-chat-id

get-chat-id-docker: build ## Get chat ID using Docker
	@if [ -z "$$BOT_TOKEN" ]; then \
		echo "Error: BOT_TOKEN environment variable not set"; \
		echo "Usage: BOT_TOKEN=your_token make get-chat-id-docker"; \
		exit 1; \
	fi
	docker run --rm -e BOT_TOKEN=$$BOT_TOKEN mtproto-checker python3 /app/checker.py --get-chat-id

setup: ## Setup .env file from example
	@if [ -f .env ]; then \
		echo ".env file already exists. Remove it first if you want to recreate."; \
	else \
		cp .env.example .env; \
		echo "Created .env file. Please edit it with your values."; \
	fi

status: ## Show container status
	docker-compose ps

validate-env: ## Validate environment configuration
	@echo "Validating environment variables..."
	@python3 -c "import os; missing = [v for v in ['BOT_TOKEN', 'CHAT_ID', 'PROXY_HOST', 'PROXY_PORT', 'PROXY_SECRET'] if not os.getenv(v)]; print('Missing: ' + ', '.join(missing) if missing else 'All required variables set ✓')"
