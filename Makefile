up-b:
	podman compose -f docker/docker-compose.yaml --env-file .env up -d --build
down-v:
	podman compose -f docker/docker-compose.yaml --env-file .env down -v

.PHONY: up-b down-v