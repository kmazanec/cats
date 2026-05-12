.PHONY: help sync dev lint fmt typecheck test test-unit migrate revision smoke api worker compose-up compose-down

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' Makefile | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

sync: ## uv sync all deps
	uv sync --all-extras

dev: sync compose-up migrate ## one-shot bootstrap

compose-up: ## start postgres + redis
	docker compose up -d

compose-down: ## stop postgres + redis
	docker compose down

lint: ## ruff + mypy strict
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy

fmt: ## ruff format
	uv run ruff format .
	uv run ruff check --fix .

typecheck:
	uv run mypy

test: ## full test suite
	uv run pytest

test-unit: ## unit tests only
	uv run pytest tests/unit

migrate: ## apply alembic migrations
	uv run alembic upgrade head

revision: ## create a new alembic revision (use MSG="...")
	uv run alembic revision --autogenerate -m "$(MSG)"

smoke: ## end-to-end no-LLM smoke path
	uv run cats smoke

api: ## run FastAPI dev server
	uv run uvicorn cats.api.app:app --host 0.0.0.0 --port 8400 --reload

worker: ## run a campaign worker against a registered project
	uv run python -m cats.workers.campaign_worker
