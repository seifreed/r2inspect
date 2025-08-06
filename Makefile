# Makefile for r2inspect Docker operations
.PHONY: help build run shell batch clean push pull test dev prod

# Variables
IMAGE_NAME := r2inspect
IMAGE_TAG := latest
FULL_IMAGE := $(IMAGE_NAME):$(IMAGE_TAG)
CONTAINER_NAME := r2inspect-analysis
REGISTRY := docker.io
REGISTRY_USER := your-username

# Directories
SAMPLES_DIR := ./samples
OUTPUT_DIR := ./output
CONFIG_DIR := ./config

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m

help: ## Show this help message
	@echo "$(GREEN)r2inspect Docker Management$(NC)"
	@echo ""
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make build          # Build Docker image"
	@echo "  make run FILE=malware.exe  # Analyze a file"
	@echo "  make batch          # Batch analyze samples directory"
	@echo "  make shell          # Start interactive shell"

build: ## Build production Docker image
	@echo "$(YELLOW)Building production Docker image $(FULL_IMAGE)...$(NC)"
	@docker build --build-arg BUILD_TYPE=production -t $(FULL_IMAGE) .
	@echo "$(GREEN)Production build complete!$(NC)"

build-dev: ## Build development Docker image
	@echo "$(YELLOW)Building development Docker image $(IMAGE_NAME):dev...$(NC)"
	@docker build --build-arg BUILD_TYPE=development -t $(IMAGE_NAME):dev .
	@echo "$(GREEN)Development build complete!$(NC)"

build-nocache: ## Build Docker image without cache
	@echo "$(YELLOW)Building Docker image $(FULL_IMAGE) without cache...$(NC)"
	@docker build --no-cache --build-arg BUILD_TYPE=production -t $(FULL_IMAGE) .
	@echo "$(GREEN)Build complete!$(NC)"

build-dev-nocache: ## Build development Docker image without cache
	@echo "$(YELLOW)Building development Docker image $(IMAGE_NAME):dev without cache...$(NC)"
	@docker build --no-cache --build-arg BUILD_TYPE=development -t $(IMAGE_NAME):dev .
	@echo "$(GREEN)Development build complete!$(NC)"

run: ## Run r2inspect on a file (use FILE=path/to/file)
	@if [ -z "$(FILE)" ]; then \
		echo "$(RED)Error: Please specify FILE=path/to/file$(NC)"; \
		exit 1; \
	fi
	@echo "$(YELLOW)Analyzing $(FILE)...$(NC)"
	@docker run --rm \
		-v "$(shell pwd)/$(FILE):/tmp/analysis/$(notdir $(FILE)):ro" \
		-v "$(shell pwd)/$(OUTPUT_DIR)":/home/analyst/output:rw \
		--cap-drop=ALL \
		--cap-add=SYS_PTRACE \
		--cap-add=DAC_READ_SEARCH \
		--security-opt=no-new-privileges:true \
		--memory=2g \
		--cpus=2 \
		$(FULL_IMAGE) /tmp/analysis/$(notdir $(FILE)) $(ARGS)

shell: ## Start interactive shell in container
	@echo "$(YELLOW)Starting interactive shell...$(NC)"
	@mkdir -p $(SAMPLES_DIR) $(OUTPUT_DIR) $(CONFIG_DIR)
	@docker run --rm -it \
		--name $(CONTAINER_NAME) \
		-v "$(shell pwd)/$(SAMPLES_DIR)":/home/analyst/samples:ro \
		-v "$(shell pwd)/$(OUTPUT_DIR)":/home/analyst/output:rw \
		-v "$(shell pwd)/$(CONFIG_DIR)":/home/analyst/config:ro \
		--cap-drop=ALL \
		--cap-add=SYS_PTRACE \
		--cap-add=DAC_READ_SEARCH \
		--security-opt=no-new-privileges:true \
		--memory=2g \
		--cpus=2 \
		--entrypoint /bin/bash \
		$(FULL_IMAGE)

batch: ## Run batch analysis on samples directory
	@echo "$(YELLOW)Running batch analysis on $(SAMPLES_DIR)...$(NC)"
	@mkdir -p $(SAMPLES_DIR) $(OUTPUT_DIR) $(CONFIG_DIR)
	@docker run --rm \
		--name $(CONTAINER_NAME) \
		-v "$(shell pwd)/$(SAMPLES_DIR)":/home/analyst/samples:ro \
		-v "$(shell pwd)/$(OUTPUT_DIR)":/home/analyst/output:rw \
		-v "$(shell pwd)/$(CONFIG_DIR)":/home/analyst/config:ro \
		--cap-drop=ALL \
		--cap-add=SYS_PTRACE \
		--cap-add=DAC_READ_SEARCH \
		--security-opt=no-new-privileges:true \
		--memory=2g \
		--cpus=2 \
		$(FULL_IMAGE) --batch /home/analyst/samples -o /home/analyst/output/batch_results.csv $(ARGS)

compose-up: ## Start services with docker-compose
	@echo "$(YELLOW)Starting r2inspect services...$(NC)"
	@docker-compose up -d
	@echo "$(GREEN)Services started!$(NC)"

compose-down: ## Stop services with docker-compose
	@echo "$(YELLOW)Stopping r2inspect services...$(NC)"
	@docker-compose down
	@echo "$(GREEN)Services stopped!$(NC)"

compose-logs: ## Show docker-compose logs
	@docker-compose logs -f

clean: ## Clean up Docker resources
	@echo "$(YELLOW)Cleaning up Docker resources...$(NC)"
	@docker stop $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm $(CONTAINER_NAME) 2>/dev/null || true
	@docker rmi $(FULL_IMAGE) 2>/dev/null || true
	@echo "$(GREEN)Cleanup complete!$(NC)"

push: ## Push image to registry
	@echo "$(YELLOW)Pushing image to $(REGISTRY)/$(REGISTRY_USER)/$(FULL_IMAGE)...$(NC)"
	@docker tag $(FULL_IMAGE) $(REGISTRY)/$(REGISTRY_USER)/$(FULL_IMAGE)
	@docker push $(REGISTRY)/$(REGISTRY_USER)/$(FULL_IMAGE)
	@echo "$(GREEN)Push complete!$(NC)"

pull: ## Pull image from registry
	@echo "$(YELLOW)Pulling image from $(REGISTRY)/$(REGISTRY_USER)/$(FULL_IMAGE)...$(NC)"
	@docker pull $(REGISTRY)/$(REGISTRY_USER)/$(FULL_IMAGE)
	@docker tag $(REGISTRY)/$(REGISTRY_USER)/$(FULL_IMAGE) $(FULL_IMAGE)
	@echo "$(GREEN)Pull complete!$(NC)"

test: ## Test Docker image
	@echo "$(YELLOW)Testing Docker image...$(NC)"
	@docker run --rm $(FULL_IMAGE) --version
	@docker run --rm $(FULL_IMAGE) --help
	@echo "$(GREEN)Tests passed!$(NC)"

shell-dev: ## Start interactive shell in development container
	@echo "$(YELLOW)Starting development shell...$(NC)"
	@mkdir -p $(SAMPLES_DIR) $(OUTPUT_DIR) $(CONFIG_DIR)
	@docker run --rm -it \
		--name $(CONTAINER_NAME)-dev \
		-v "$(shell pwd)/$(SAMPLES_DIR)":/home/analyst/samples:ro \
		-v "$(shell pwd)/$(OUTPUT_DIR)":/home/analyst/output:rw \
		-v "$(shell pwd)/$(CONFIG_DIR)":/home/analyst/config:ro \
		-v "$(shell pwd)/r2inspect":/app/r2inspect:rw \
		--cap-drop=ALL \
		--cap-add=SYS_PTRACE \
		--cap-add=DAC_READ_SEARCH \
		--security-opt=no-new-privileges:true \
		--memory=4g \
		--cpus=4 \
		$(IMAGE_NAME):dev

stats: ## Show container stats
	@docker stats --no-stream $(CONTAINER_NAME)

inspect: ## Inspect the Docker image
	@docker inspect $(FULL_IMAGE)

size: ## Show image size
	@echo "$(YELLOW)Image size:$(NC)"
	@docker images $(FULL_IMAGE) --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

dirs: ## Create required directories
	@mkdir -p $(SAMPLES_DIR) $(OUTPUT_DIR) $(CONFIG_DIR)
	@echo "$(GREEN)Directories created: $(SAMPLES_DIR), $(OUTPUT_DIR), $(CONFIG_DIR)$(NC)"