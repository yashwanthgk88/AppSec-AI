#!/bin/bash

# AppSec Platform - Automated Setup Script
# This script sets up both backend and frontend for the POC

set -e

echo "======================================"
echo "AppSec Platform - Setup Script"
echo "======================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"

# Check Node.js version
echo "Checking Node.js version..."
if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js is not installed${NC}"
    exit 1
fi

NODE_VERSION=$(node --version)
echo -e "${GREEN}✓ Node.js $NODE_VERSION found${NC}"
echo ""

# Backend Setup
echo "======================================"
echo "Setting up Backend (Python/FastAPI)"
echo "======================================"
cd backend

echo "Creating Python virtual environment..."
python3 -m venv venv

echo "Activating virtual environment..."
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate 2>/dev/null

echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Configuring environment variables..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}⚠ Please edit backend/.env and add your ANTHROPIC_API_KEY${NC}"
    echo -e "${YELLOW}  Get your API key from: https://console.anthropic.com/${NC}"
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

cd ..

# Frontend Setup
echo ""
echo "======================================"
echo "Setting up Frontend (React/TypeScript)"
echo "======================================"
cd frontend

echo "Installing Node.js dependencies..."
npm install

echo "Frontend setup complete!"
cd ..

# Final Instructions
echo ""
echo "======================================"
echo "Setup Complete!"
echo "======================================"
echo ""
echo -e "${GREEN}✓ Backend setup complete${NC}"
echo -e "${GREEN}✓ Frontend setup complete${NC}"
echo ""
echo "Next Steps:"
echo ""
echo "1. Configure API Key:"
echo "   Edit ${YELLOW}backend/.env${NC} and add your ANTHROPIC_API_KEY"
echo ""
echo "2. Start the Backend:"
echo "   ${GREEN}cd backend${NC}"
echo "   ${GREEN}source venv/bin/activate${NC}  # On Windows: venv\\Scripts\\activate"
echo "   ${GREEN}python main.py${NC}"
echo "   Backend will run on: http://localhost:8000"
echo ""
echo "3. Start the Frontend (in a new terminal):"
echo "   ${GREEN}cd frontend${NC}"
echo "   ${GREEN}npm run dev${NC}"
echo "   Frontend will run on: http://localhost:5173"
echo ""
echo "4. Login with demo credentials:"
echo "   Email: admin@example.com"
echo "   Password: admin123"
echo ""
echo "5. Explore the features:"
echo "   - Create a project with architecture document"
echo "   - Run demo security scan"
echo "   - View threat model (DFD, STRIDE, MITRE)"
echo "   - Chat with AI assistant in any language"
echo "   - Export reports (Excel, PDF, XML)"
echo ""
echo "Documentation:"
echo "- README.md - Project overview"
echo "- DEMO_GUIDE.md - Comprehensive feature guide"
echo "- API Docs: http://localhost:8000/docs"
echo ""
echo -e "${GREEN}Happy security scanning! 🔒${NC}"
