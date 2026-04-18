.PHONY: up down logs build rebuild clean stats psql token

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=200 app

rebuild:
	docker compose up -d --build

clean:
	docker compose down -v

psql:
	docker compose exec db psql -U tracker -d tracker

token:
	@openssl rand -hex 32

stats:
	@curl -sS -H "Authorization: Bearer $$API_TOKEN" http://localhost:8080/stats | jq . || echo "(set API_TOKEN env var first)"
