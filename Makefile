.PHONY: install seed demo serve test docker clean

install:
	pip install -r requirements.txt

seed:
	python src/seed.py

demo: seed
	python demo.py

serve: seed
	uvicorn src.api:app --host 0.0.0.0 --port 8000 --reload

test:
	python -m pytest tests/ -q

docker:
	docker build -t itops-mcp-gateway .
	docker run --rm -p 8000:8000 itops-mcp-gateway

clean:
	rm -rf data/*.db __pycache__ .pytest_cache src/__pycache__ tests/__pycache__
