#!/bin/bash

# AppSec AI Platform - Local Deployment Test Script
# This script helps you test the deployment locally using Docker before deploying to production

set -e  # Exit on error

echo "🚀 AppSec AI Platform - Local Deployment Test"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker Desktop first."
    echo "Download from: https://www.docker.com/products/docker-desktop"
    exit 1
fi

print_success "Docker is installed"

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_error "Docker Compose is not available. Please install Docker Compose."
    exit 1
fi

print_success "Docker Compose is available"

# Check if .env file exists
if [ ! -f .env ]; then
    print_warning ".env file not found. Creating from .env.example..."

    if [ -f .env.example ]; then
        cp .env.example .env
        print_info "Please edit .env file and add your API keys:"
        print_info "  - ANTHROPIC_API_KEY"
        print_info "  - OPENAI_API_KEY"
        print_info "  - DB_PASSWORD (generate a secure password)"
        print_info "  - SECRET_KEY (use: python3 -c 'import secrets; print(secrets.token_hex(32))')"
        echo ""
        read -p "Press Enter after updating .env file..."
    else
        print_error ".env.example not found. Cannot create .env file."
        exit 1
    fi
fi

print_success ".env file exists"

# Check if required environment variables are set
source .env

if [ -z "$SECRET_KEY" ] || [ "$SECRET_KEY" = "your-secret-key-min-32-characters-long-change-this" ]; then
    print_error "SECRET_KEY not set in .env file"
    print_info "Generate one with: python3 -c 'import secrets; print(secrets.token_hex(32))'"
    exit 1
fi

print_success "SECRET_KEY is configured"

if [ -z "$ANTHROPIC_API_KEY" ] || [ "$ANTHROPIC_API_KEY" = "sk-ant-your-key-here" ]; then
    print_warning "ANTHROPIC_API_KEY not set - AI chatbot may not work"
fi

if [ -z "$OPENAI_API_KEY" ] || [ "$OPENAI_API_KEY" = "sk-your-key-here" ]; then
    print_warning "OPENAI_API_KEY not set - some AI features may not work"
fi

# Stop any existing containers
print_info "Stopping existing containers..."
docker-compose down &> /dev/null || true

# Build and start containers
echo ""
print_info "Building Docker images (this may take a few minutes)..."
docker-compose build

echo ""
print_info "Starting services..."
docker-compose up -d

# Wait for services to be ready
echo ""
print_info "Waiting for services to start..."
sleep 5

# Check if database is ready
print_info "Waiting for database to be ready..."
for i in {1..30}; do
    if docker-compose exec -T db pg_isready -U appsec_user -d appsec_db &> /dev/null; then
        print_success "Database is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "Database failed to start"
        docker-compose logs db
        exit 1
    fi
    sleep 2
done

# Check if backend is ready
print_info "Waiting for backend to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:8000/docs &> /dev/null; then
        print_success "Backend is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "Backend failed to start"
        docker-compose logs backend
        exit 1
    fi
    sleep 2
done

# Check if frontend is ready
print_info "Waiting for frontend to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:5173 &> /dev/null; then
        print_success "Frontend is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        print_error "Frontend failed to start"
        docker-compose logs frontend
        exit 1
    fi
    sleep 2
done

# All services are ready
echo ""
echo "=============================================="
print_success "All services are running successfully!"
echo "=============================================="
echo ""
print_info "Application URLs:"
echo "  Frontend:  http://localhost:5173"
echo "  Backend API: http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo ""
print_info "Default Credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
print_info "Useful Commands:"
echo "  View logs:     docker-compose logs -f"
echo "  Stop services: docker-compose down"
echo "  Restart:       docker-compose restart"
echo "  View status:   docker-compose ps"
echo ""
print_warning "Remember to change the default admin password after first login!"
echo ""

# Open browser (optional)
read -p "Open application in browser? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v open &> /dev/null; then
        open http://localhost:5173
    elif command -v xdg-open &> /dev/null; then
        xdg-open http://localhost:5173
    else
        print_info "Please open http://localhost:5173 in your browser"
    fi
fi

print_success "Local deployment test complete!"
print_info "If everything works locally, you're ready to deploy to production!"
print_info "Follow DEPLOYMENT_CHECKLIST.md for production deployment steps."
