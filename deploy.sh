#!/bin/bash

# AppSec Platform Deployment Script
# This script helps deploy the AppSec Platform using Docker Compose

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=================================================${NC}"
echo -e "${GREEN}   AppSec Platform Deployment Script${NC}"
echo -e "${GREEN}=================================================${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo "Please install Docker from https://www.docker.com/get-started"
    exit 1
fi

# Detect Docker Compose command (supports both docker-compose and docker compose)
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
elif docker compose version &> /dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    echo -e "${RED}Error: Docker Compose is not installed${NC}"
    echo "Please install Docker Compose"
    exit 1
fi

echo "Using Docker Compose command: $DOCKER_COMPOSE"

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}Warning: .env file not found${NC}"
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo -e "${YELLOW}Please edit .env file with your configuration before running again${NC}"
    echo ""
    echo "Required configuration:"
    echo "  - SECRET_KEY (generate with: openssl rand -hex 32)"
    echo "  - CORS_ORIGINS (your domain URLs)"
    echo "  - VITE_API_URL (your API URL)"
    echo "  - AI API keys (optional)"
    echo ""
    exit 1
fi

# Function to check if SECRET_KEY has been changed
check_secret_key() {
    if grep -q "your-secret-key-change-in-production" .env; then
        echo -e "${RED}Error: Please change the SECRET_KEY in .env file${NC}"
        echo "Generate a secure key with: openssl rand -hex 32"
        exit 1
    fi
}

# Parse command line arguments
MODE=${1:-dev}

if [ "$MODE" == "production" ] || [ "$MODE" == "prod" ]; then
    echo -e "${GREEN}Deploying in PRODUCTION mode with PostgreSQL${NC}"
    check_secret_key
    # Check PostgreSQL password
    if grep -q "change_this_to_secure_password" .env; then
        echo -e "${RED}Error: Please change POSTGRES_PASSWORD in .env file${NC}"
        exit 1
    fi
    $DOCKER_COMPOSE -f docker-compose.prod.yml up -d --build

elif [ "$MODE" == "production-nginx" ] || [ "$MODE" == "prod-nginx" ]; then
    echo -e "${GREEN}Deploying in PRODUCTION mode with PostgreSQL + Nginx${NC}"
    check_secret_key
    if grep -q "change_this_to_secure_password" .env; then
        echo -e "${RED}Error: Please change POSTGRES_PASSWORD in .env file${NC}"
        exit 1
    fi
    COMPOSE_PROFILES=production $DOCKER_COMPOSE -f docker-compose.prod.yml up -d --build

elif [ "$MODE" == "dev" ] || [ "$MODE" == "development" ]; then
    echo -e "${GREEN}Deploying in DEVELOPMENT mode (SQLite)${NC}"
    $DOCKER_COMPOSE up -d --build

elif [ "$MODE" == "stop" ]; then
    echo -e "${YELLOW}Stopping all containers...${NC}"
    $DOCKER_COMPOSE down
    echo -e "${GREEN}Containers stopped${NC}"
    exit 0

elif [ "$MODE" == "restart" ]; then
    echo -e "${YELLOW}Restarting containers...${NC}"
    $DOCKER_COMPOSE restart
    echo -e "${GREEN}Containers restarted${NC}"
    exit 0

elif [ "$MODE" == "logs" ]; then
    echo -e "${GREEN}Showing logs (Ctrl+C to exit)...${NC}"
    $DOCKER_COMPOSE logs -f
    exit 0

elif [ "$MODE" == "clean" ]; then
    echo -e "${YELLOW}Cleaning up containers, images, and volumes...${NC}"
    read -p "Are you sure? This will delete all data! (yes/no): " -r
    if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        $DOCKER_COMPOSE down -v
        docker system prune -af
        echo -e "${GREEN}Cleanup complete${NC}"
    else
        echo "Cleanup cancelled"
    fi
    exit 0

else
    echo -e "${RED}Error: Invalid mode '$MODE'${NC}"
    echo ""
    echo "Usage: ./deploy.sh [mode]"
    echo ""
    echo "Available modes:"
    echo "  dev              - Start in development mode with SQLite (default)"
    echo "  production       - Start in production mode with PostgreSQL"
    echo "  production-nginx - Start in production mode with PostgreSQL + Nginx"
    echo "  stop             - Stop all containers"
    echo "  restart          - Restart all containers"
    echo "  logs             - Show container logs"
    echo "  clean            - Remove all containers, images, and volumes"
    echo ""
    exit 1
fi

# Wait for services to be healthy
echo ""
echo -e "${YELLOW}Waiting for services to start...${NC}"
sleep 10

# Check if containers are running
if $DOCKER_COMPOSE ps | grep -q "Up"; then
    echo -e "${GREEN}✓ Deployment successful!${NC}"
    echo ""
    echo "Services are running:"
    $DOCKER_COMPOSE ps
    echo ""
    echo -e "${GREEN}Access the application:${NC}"

    if [ "$MODE" == "production" ] || [ "$MODE" == "prod" ]; then
        echo "  Frontend: http://localhost:80"
        echo "  Backend:  http://localhost:8000"
        echo "  API Docs: http://localhost:8000/docs"
    else
        echo "  Frontend: http://localhost:3000"
        echo "  Backend:  http://localhost:8000"
        echo "  API Docs: http://localhost:8000/docs"
    fi
    echo ""
    echo "VS Code Extension v1.4.0 is available at:"
    if [ "$MODE" == "production" ] || [ "$MODE" == "prod" ]; then
        echo "  http://localhost:80/downloads/appsec-ai-scanner-2.0.0.vsix"
    else
        echo "  http://localhost:3000/downloads/appsec-ai-scanner-2.0.0.vsix"
    fi
    echo ""
    echo -e "${YELLOW}View logs with: ./deploy.sh logs${NC}"
    echo -e "${YELLOW}Stop with: ./deploy.sh stop${NC}"
else
    echo -e "${RED}✗ Deployment failed!${NC}"
    echo "Check logs with: ./deploy.sh logs"
    exit 1
fi
