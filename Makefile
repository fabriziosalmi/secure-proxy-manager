.PHONY: setup start stop restart logs build clean adversarial

# First-run setup: create .env from template if not exists
setup:
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✅ Created .env from .env.example"; \
		echo "⚠️  Edit .env to set BASIC_AUTH_USERNAME and BASIC_AUTH_PASSWORD"; \
	else \
		echo "ℹ️  .env already exists"; \
	fi
	@mkdir -p data logs config config/dnsmasq.d

# Build and start all services
start: setup
	docker compose up -d --build

# Stop all services
stop:
	docker compose down

# Restart with rebuild
restart: stop start

# View logs
logs:
	docker compose logs -f --tail=50

# Build without starting
build: setup
	docker compose build

# Clean everything (data preserved)
clean:
	docker compose down -v --remove-orphans
	@echo "⚠️  Data in ./data/ preserved. Remove manually if needed."

# Adversarial e2e: drive attacker traffic against the real proxy + WAF/ICAP
# (block-matrix) and the backend auth boundary (API attacker) in an isolated
# sandbox; gate on false negatives/positives and auth bypasses (#200).
adversarial:
	bash tests/adversarial/run.sh
