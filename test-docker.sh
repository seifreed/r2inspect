#!/bin/bash
# Test script for Docker setup validation
# Validates Docker configuration without requiring Docker to be running

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}Testing r2inspect Docker configuration...${NC}"
echo

# Test 1: Check if required files exist
echo "1. Checking required Docker files..."
files=(
    "Dockerfile"
    "docker-compose.yml"
    ".dockerignore"
    "docker-run.sh"
    "docker-run.bat"
    "Makefile"
    "DOCKER.md"
)

for file in "${files[@]}"; do
    if [[ -f "$file" ]]; then
        echo -e "  ✓ $file exists"
    else
        echo -e "  ${RED}✗ $file missing${NC}"
        exit 1
    fi
done

# Test 2: Check if directories exist
echo
echo "2. Checking required directories..."
dirs=("samples" "output" "config")

for dir in "${dirs[@]}"; do
    if [[ -d "$dir" ]]; then
        echo -e "  ✓ $dir/ exists"
    else
        echo -e "  ${RED}✗ $dir/ missing${NC}"
        exit 1
    fi
done

# Test 3: Validate Dockerfile syntax
echo
echo "3. Validating Dockerfile syntax..."
if command -v docker &> /dev/null; then
    if docker info &> /dev/null; then
        echo "  ✓ Docker is running"
        
        # Test main Dockerfile
        if docker build -f Dockerfile -t r2inspect:test . --dry-run 2>/dev/null; then
            echo "  ✓ Main Dockerfile syntax valid"
        else
            echo -e "  ${YELLOW}! Main Dockerfile syntax check skipped (build required)${NC}"
        fi
    else
        echo -e "  ${YELLOW}! Docker is installed but not running${NC}"
    fi
else
    echo -e "  ${YELLOW}! Docker not installed - syntax validation skipped${NC}"
fi

# Test 4: Validate docker-compose.yml
echo
echo "4. Validating docker-compose.yml..."
if command -v docker-compose &> /dev/null; then
    if docker-compose config &> /dev/null; then
        echo "  ✓ docker-compose.yml is valid"
    else
        echo -e "  ${RED}✗ docker-compose.yml has errors${NC}"
        docker-compose config
        exit 1
    fi
else
    echo -e "  ${YELLOW}! docker-compose not installed - validation skipped${NC}"
fi

# Test 5: Check script permissions
echo
echo "5. Checking script permissions..."
if [[ -x "docker-run.sh" ]]; then
    echo "  ✓ docker-run.sh is executable"
else
    echo -e "  ${YELLOW}! docker-run.sh not executable (run: chmod +x docker-run.sh)${NC}"
fi

if [[ -x "test-docker.sh" ]]; then
    echo "  ✓ test-docker.sh is executable"
else
    echo -e "  ${YELLOW}! test-docker.sh not executable (run: chmod +x test-docker.sh)${NC}"
fi

# Test 6: Validate .dockerignore patterns
echo
echo "6. Validating .dockerignore..."
if [[ -s ".dockerignore" ]]; then
    echo "  ✓ .dockerignore contains patterns"
    
    # Check for common patterns
    patterns=("__pycache__" "*.pyc" ".git" "venv/" "samples/*" "output/*")
    for pattern in "${patterns[@]}"; do
        if grep -q "$pattern" .dockerignore; then
            echo "    ✓ Excludes $pattern"
        else
            echo -e "    ${YELLOW}! Missing pattern: $pattern${NC}"
        fi
    done
else
    echo -e "  ${RED}✗ .dockerignore is empty${NC}"
    exit 1
fi

# Test 7: Check Makefile targets
echo
echo "7. Validating Makefile..."
if command -v make &> /dev/null; then
    if make help &> /dev/null; then
        echo "  ✓ Makefile is valid"
        
        # Check for important targets
        targets=("build" "run" "shell" "batch" "clean")
        for target in "${targets[@]}"; do
            if make -n "$target" &> /dev/null; then
                echo "    ✓ Target '$target' exists"
            else
                echo -e "    ${YELLOW}! Target '$target' missing${NC}"
            fi
        done
    else
        echo -e "  ${RED}✗ Makefile has errors${NC}"
        exit 1
    fi
else
    echo -e "  ${YELLOW}! make not installed - validation skipped${NC}"
fi

echo
echo -e "${GREEN}✓ Docker configuration validation complete!${NC}"
echo
echo "Next steps:"
echo "1. Install Docker if not already installed"
echo "2. Start Docker daemon"
echo "3. Build image: make build"
echo "4. Test image: make test"
echo "5. Run analysis: make run FILE=sample.exe"
echo
echo "For detailed usage instructions, see DOCKER.md"
