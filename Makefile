.PHONY: install seed demo serve test docker clean

install:
	pip install -e ".[test]"

seed:
	python -m itops_mcp_gateway.seed

demo: seed
	python demo.py

serve: seed
	uvicorn itops_mcp_gateway.api:app --host 0.0.0.0 --port 8000 --reload

test:
	python -m pytest -q

docker:
	docker build -t itops-mcp-gateway .
	docker run --rm -p 8000:8000 itops-mcp-gateway

clean:
	rm -rf data/*.db .pytest_cache build *.egg-info src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
