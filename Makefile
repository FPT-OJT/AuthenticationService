start:
	podman compose -f docker/docker-compose.prod.yaml --env-file .env pull
	podman compose -f docker/docker-compose.prod.yaml --env-file .env up -d

up:
	podman compose -f docker/docker-compose.yaml --env-file .env up -d

up-b:
	podman compose -f docker/docker-compose.yaml --env-file .env up -d --build
down-v:
	podman compose -f docker/docker-compose.yaml --env-file .env down -v

tidy:
	go mod tidy

.PHONY: up up-b down-v tidy start