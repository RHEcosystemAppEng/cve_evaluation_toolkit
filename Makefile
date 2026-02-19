.PHONY: help install sync test lint format clean docker-build deploy-dev deploy-prod

help:
	@echo "Available commands:"
	@echo "  make install          - Install all dependencies"
	@echo "  make sync             - Sync dependencies from lock file"
	@echo "  make test             - Run tests"
	@echo "  make lint             - Run linters"
	@echo "  make format           - Format code"
	@echo "  make clean            - Clean cache files"
	@echo "  make docker-build     - Build Docker image"
	@echo "  make deploy-dev       - Deploy to dev environment"
	@echo "  make deploy-prod      - Deploy to prod environment"

install:
	uv sync

sync:
	uv sync

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run mypy evaluation/

format:
	uv run black .
	uv run ruff check --fix .

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov/

docker-build:
	docker build -t cve-evaluation:latest -f deployment/Dockerfile .

docker-build-dev:
	docker build -t quay.io/your-org/cve-evaluation:dev -f deployment/Dockerfile .

docker-push-dev:
	docker push quay.io/your-org/cve-evaluation:dev

deploy-dev:
	kubectl apply -k deployment/overlays/dev

deploy-prod:
	kubectl apply -k deployment/overlays/prod

logs-dev:
	kubectl logs -f -n cve-evaluation-dev deployment/dev-cve-evaluation

logs-prod:
	kubectl logs -f -n cve-evaluation-prod deployment/prod-cve-evaluation
