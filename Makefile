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

# Adversarial e2e: 5-plane suite against the real stack in an isolated sandbox —
# block-matrix (proxy+WAF/ICAP), API attacker (backend auth), k6 latency bench,
# resilience (fail-closed + self-heal), and config-matrix (settings flip the data
# plane); gates on FN/FP, auth bypasses, p95/error-rate, fail-open, and settings
# that don't take effect (#200).
adversarial:
	bash tests/adversarial/run.sh
