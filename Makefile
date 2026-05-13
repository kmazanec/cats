.PHONY: help sync dev lint fmt typecheck test test-unit migrate revision smoke api worker worker-orchestrator worker-red-team worker-judge worker-documentation workers-all compose-up compose-down eval eval-orchestrator eval-red-team eval-judge eval-documentation

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

worker: ## run a campaign worker against a registered project (R3, legacy)
	uv run python -m cats.workers.campaign_worker

worker-orchestrator: ## run the orchestrator agent locally
	uv run python -m cats.workers.orchestrator

worker-red-team: ## run the red_team agent locally
	uv run python -m cats.workers.red_team

worker-judge: ## run the judge agent locally
	uv run python -m cats.workers.judge

worker-documentation: ## run the documentation agent locally
	uv run python -m cats.workers.documentation

workers-all: ## start all four R4 workers under docker compose
	docker compose up orchestrator red_team judge documentation

eval: ## run all four agent eval suites (no LLM, no DB)
	uv run python -m evals.suite

eval-orchestrator: ## run the orchestrator eval suite
	uv run python -m evals.runners.orchestrator

eval-red-team: ## run the red_team eval suite
	uv run python -m evals.runners.red_team

eval-judge: ## run the judge eval suite (evidence-only by default; add --with-fake-llm)
	uv run python -m evals.runners.judge

eval-documentation: ## run the documentation eval suite
	uv run python -m evals.runners.documentation
