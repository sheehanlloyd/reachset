.PHONY: up down install migrate test test-unit lint typecheck bench seed demo fmt

UV ?= uv

# `make test` runs against the compose stack from `make up` (same shape as CI's
# service containers). Unset these to let testcontainers manage everything.
export REACHSET_TEST_DATABASE_URL ?= postgresql+asyncpg://reachset:reachset@localhost:5442/reachset
export REACHSET_TEST_REDIS_URL ?= redis://localhost:6390/0
export REACHSET_TEST_VAULT_ADDR ?= http://localhost:8220
export REACHSET_TEST_VAULT_TOKEN ?= reachset-dev-root
export REACHSET_TEST_VAULT_AUDIT_CMD ?= docker compose exec -T vault cat /vault/logs/audit.log

install:
	$(UV) sync

up:
	docker compose up -d postgres redis vault
	docker compose ps

down:
	docker compose down -v

migrate:
	$(UV) run alembic upgrade head

test:
	$(UV) run pytest --cov=reachset --cov-report=term-missing

test-unit:
	$(UV) run pytest -m "not integration and not live_vault" --no-cov

lint:
	$(UV) run ruff check src tests bench
	$(UV) run ruff format --check src tests bench

fmt:
	$(UV) run ruff format src tests bench
	$(UV) run ruff check --fix src tests bench

typecheck:
	$(UV) run mypy

bench:
	$(UV) run python -m bench.run
	$(UV) run python -m bench.plot

seed:
	$(UV) run python -m reachset.synth.generator --tenant synth --principals 200 --grants 800 --events 5000

# Load both fixture connectors into a `demo` tenant and show it off. This is
# the fastest way to see what the tool actually does on a clean checkout.
demo: migrate
	$(UV) run reachset sync --tenant demo --app vault  --fixtures tests/fixtures/vault
	$(UV) run reachset sync --tenant demo --app github --fixtures tests/fixtures/github
	@echo
	$(UV) run reachset blast-radius --tenant demo --principal token:acc-null-display --limit 5
	@echo
	$(UV) run reachset detect --tenant demo
