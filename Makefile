.PHONY: install dev test lint serve clean

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v

test-unit:
	python -m pytest tests/unit/ -v

test-cov:
	python -m pytest tests/ --cov=zuultimate --cov-report=html

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff format src/ tests/

serve:
	uvicorn zuultimate.app:create_app --factory --reload --port 8000

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
