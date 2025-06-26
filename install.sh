#!/bin/bash

# r2inspect Installation Script
# Installs r2inspect and its dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "  ██████╗ ██████╗ ██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗"
echo "  ██╔══██╗╚════██╗██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝"
echo "  ██████╔╝ █████╔╝██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   "
echo "  ██╔══██╗██╔═══╝ ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   "
echo "  ██║  ██║███████╗██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   "
echo "  ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   "
echo ""
echo "  Advanced Malware Analysis Tool using Radare2"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}This script should not be run as root${NC}"
   exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install package on different distros
install_package() {
    local package=$1
    
    if command_exists apt-get; then
        echo -e "${BLUE}Installing $package using apt-get...${NC}"
        sudo apt-get update
        sudo apt-get install -y $package
    elif command_exists yum; then
        echo -e "${BLUE}Installing $package using yum...${NC}"
        sudo yum install -y $package
    elif command_exists dnf; then
        echo -e "${BLUE}Installing $package using dnf...${NC}"
        sudo dnf install -y $package
    elif command_exists pacman; then
        echo -e "${BLUE}Installing $package using pacman...${NC}"
        sudo pacman -S --noconfirm $package
    elif command_exists brew; then
        echo -e "${BLUE}Installing $package using brew...${NC}"
        brew install $package
    else
        echo -e "${RED}Package manager not found. Please install $package manually.${NC}"
        return 1
    fi
}

echo -e "${GREEN}Starting r2inspect installation...${NC}"

# Check Python version
echo -e "${BLUE}Checking Python version...${NC}"
if command_exists python3; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    echo "Found Python $PYTHON_VERSION"
    
    # Check if Python version is 3.8 or higher
    if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
        echo -e "${GREEN}Python version is compatible${NC}"
    else
        echo -e "${RED}Python 3.8+ required, found $PYTHON_VERSION${NC}"
        exit 1
    fi
else
    echo -e "${RED}Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Check if pip is installed
echo -e "${BLUE}Checking pip...${NC}"
if ! command_exists pip3; then
    echo -e "${YELLOW}pip3 not found, installing...${NC}"
    install_package python3-pip
fi

# Check if radare2 is installed
echo -e "${BLUE}Checking radare2...${NC}"
if ! command_exists r2; then
    echo -e "${YELLOW}radare2 not found, installing...${NC}"
    
    # Install radare2
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        brew install radare2
    else
        # Linux
        install_package radare2
        
        # If package manager installation fails, try building from source
        if ! command_exists r2; then
            echo -e "${YELLOW}Installing radare2 from source...${NC}"
            git clone https://github.com/radareorg/radare2
            cd radare2
            ./configure --prefix=/usr/local
            make -j$(nproc)
            sudo make install
            cd ..
            rm -rf radare2
        fi
    fi
else
    echo -e "${GREEN}radare2 is already installed${NC}"
fi

# Install system dependencies
echo -e "${BLUE}Installing system dependencies...${NC}"

if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    if ! command_exists brew; then
        echo -e "${RED}Homebrew not found. Please install Homebrew first.${NC}"
        exit 1
    fi
    brew install libmagic
else
    # Linux
    if command_exists apt-get; then
        sudo apt-get update
        sudo apt-get install -y libmagic1 libmagic-dev build-essential
    elif command_exists yum; then
        sudo yum install -y file-devel gcc python3-devel
    elif command_exists dnf; then
        sudo dnf install -y file-devel gcc python3-devel
    elif command_exists pacman; then
        sudo pacman -S --noconfirm file gcc python
    fi
fi

# Install Python dependencies
echo -e "${BLUE}Installing Python dependencies...${NC}"
pip3 install --user -r requirements.txt

# Install r2inspect
echo -e "${BLUE}Installing r2inspect...${NC}"
pip3 install --user -e .

# Create config directory
echo -e "${BLUE}Setting up configuration...${NC}"
CONFIG_DIR="$HOME/.r2inspect"
mkdir -p "$CONFIG_DIR/rules/yara"
mkdir -p "$CONFIG_DIR/logs"

# Copy default YARA rules
if [ -f "r2inspect/rules/yara/default_rules.yar" ]; then
    cp r2inspect/rules/yara/default_rules.yar "$CONFIG_DIR/rules/yara/"
fi

# Add to PATH if not already there
SHELL_RC=""
if [[ $SHELL == *"bash"* ]]; then
    SHELL_RC="$HOME/.bashrc"
elif [[ $SHELL == *"zsh"* ]]; then
    SHELL_RC="$HOME/.zshrc"
elif [[ $SHELL == *"fish"* ]]; then
    SHELL_RC="$HOME/.config/fish/config.fish"
fi

if [ -n "$SHELL_RC" ] && [ -f "$SHELL_RC" ]; then
    LOCAL_BIN="$HOME/.local/bin"
    if ! grep -q "$LOCAL_BIN" "$SHELL_RC"; then
        echo -e "${BLUE}Adding ~/.local/bin to PATH in $SHELL_RC${NC}"
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
    fi
fi

echo -e "${GREEN}"
echo "✓ r2inspect installation completed successfully!"
echo ""
echo "Usage:"
echo "  r2inspect <file>                 # Basic analysis"
echo "  r2inspect -j <file>              # JSON output"
echo "  r2inspect -i <file>              # Interactive mode"
echo "  r2inspect -h                     # Show help"
echo ""
echo "Configuration directory: $CONFIG_DIR"
echo ""
echo "Note: You may need to restart your shell or run:"
echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
echo -e "${NC}" 