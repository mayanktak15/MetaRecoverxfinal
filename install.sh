#!/bin/bash
#
# Unearth Forensic Recovery Tool - Installation Script
# One-command installation for Linux/macOS
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/bhargavgajare1479/Unearth/master/install.sh | bash
#   or
#   wget -qO- https://raw.githubusercontent.com/bhargavgajare1479/Unearth/master/install.sh | bash
#   or
#   bash install.sh
#

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="${HOME}/.Unearth"
REPO_URL="https://github.com/bhargavgajare1479/Unearth.git"
PYTHON_MIN_VERSION="3.11"

# Print banner
print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
 ╔════════════════════════════════════════════════════════════════╗
 ║                                                                ║
 ║  ██    ██ ███    ██ ███████  █████  ██████╗ ████████╗ ██   ██  ║
 ║  ██    ██ ████   ██ ██      ██   ██ ██   ██ ╚══██╔══╝ ██   ██  ║
 ║  ██    ██ ██ ██  ██ █████   ███████ ██████╔╝   ██║    ███████  ║
 ║  ██    ██ ██  ██ ██ ██      ██   ██ ██   ██    ██║    ██   ██  ║
 ║   ██████  ██   ████ ███████ ██   ██ ██   ██    ██║    ██   ██  ║
 ║                                                                ║
 ║               Forensic Data Recovery & Analysis Tool           ║
 ║                           Version 1.0.0                        ║
 ║                                                                ║
 ╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Print colored message
print_msg() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python version
check_python() {
    print_info "Checking Python installation..."
    
    if command_exists python3; then
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_CMD="python"
    else
        print_error "Python not found. Please install Python 3.11 or higher."
        exit 1
    fi
    
    # Check version
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]); then
        print_error "Python 3.11+ required. Found: $PYTHON_VERSION"
        print_info "Please install Python 3.11 or higher"
        exit 1
    fi
    
    print_msg "Python $PYTHON_VERSION found"
}

# Install system dependencies
install_system_deps() {
    print_info "Checking system dependencies..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command_exists apt-get; then
            print_info "Detected Debian/Ubuntu system"
            print_warning "Installing system dependencies (requires sudo)..."
            sudo apt-get update -qq
            sudo apt-get install -y libmagic-dev python3-dev python3-pip python3-venv
            print_msg "System dependencies installed"
        elif command_exists yum; then
            print_info "Detected RedHat/CentOS system"
            sudo yum install -y file-devel python3-devel python3-pip
            print_msg "System dependencies installed"
        elif command_exists pacman; then
            print_info "Detected Arch Linux system"
            sudo pacman -S --noconfirm file python-pip
            print_msg "System dependencies installed"
        else
            print_warning "Unknown Linux distribution. Please install libmagic-dev manually."
        fi
    fi
}

# Download/clone repository
setup_repository() {
    print_info "Setting up Unearth..."
    
    # Remove old installation if exists
    if [ -d "$INSTALL_DIR" ]; then
        print_warning "Existing installation found at $INSTALL_DIR"
        read -p "Remove and reinstall? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf "$INSTALL_DIR"
            print_msg "Removed old installation"
        else
            print_error "Installation cancelled"
            exit 1
        fi
    fi
    
    # Create directory
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    # Clone or download
    if command_exists git; then
        print_info "Cloning repository..."
        git clone "$REPO_URL" . 2>/dev/null || {
            print_warning "Git clone failed. Downloading archive instead..."
            download_archive
        }
    else
        print_warning "Git not found. Downloading archive..."
        download_archive
    fi
    
    print_msg "Repository setup complete"
}

# Download archive (fallback)
download_archive() {
    if command_exists curl; then
        curl -fsSL "${REPO_URL}/archive/refs/heads/main.tar.gz" | tar xz --strip-components=1
    elif command_exists wget; then
        wget -qO- "${REPO_URL}/archive/refs/heads/main.tar.gz" | tar xz --strip-components=1
    else
        print_error "Neither curl nor wget found. Cannot download."
        exit 1
    fi
}

# Create virtual environment and install dependencies
setup_python_env() {
    print_info "Creating Python virtual environment..."
    
    cd "$INSTALL_DIR"
    $PYTHON_CMD -m venv venv
    
    # Activate venv
    source venv/bin/activate
    
    # Upgrade pip
    print_info "Upgrading pip..."
    pip install --upgrade pip setuptools wheel -q
    
    # Install dependencies
    print_info "Installing Python dependencies..."
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt -q
        print_msg "Dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
    
    # Install package in development mode
    print_info "Installing Unearth package..."
    pip install -e . -q
    print_msg "Unearth installed"
}

# Create command-line wrapper scripts
create_commands() {
    print_info "Creating command-line shortcuts..."
    
    # Create bin directory
    BIN_DIR="${HOME}/.local/bin"
    mkdir -p "$BIN_DIR"
    
    # Create Unearth command
    cat > "$BIN_DIR/Unearth" << 'EOFCMD'
#!/bin/bash
# Unearth launcher script
INSTALL_DIR="${HOME}/.Unearth"
source "${INSTALL_DIR}/venv/bin/activate"
cd "${INSTALL_DIR}"
python run.py "$@"
EOFCMD
    
    chmod +x "$BIN_DIR/Unearth"
    
    # Create Unearth-gui shortcut
    cat > "$BIN_DIR/Unearth-gui" << 'EOFCMD'
#!/bin/bash
# Unearth GUI launcher
INSTALL_DIR="${HOME}/.Unearth"
source "${INSTALL_DIR}/venv/bin/activate"
cd "${INSTALL_DIR}"
python run.py --gui
EOFCMD
    
    chmod +x "$BIN_DIR/Unearth-gui"
    
    # Create Unearth-cli shortcut
    cat > "$BIN_DIR/Unearth-cli" << 'EOFCMD'
#!/bin/bash
# Unearth CLI launcher
INSTALL_DIR="${HOME}/.Unearth"
source "${INSTALL_DIR}/venv/bin/activate"
cd "${INSTALL_DIR}"
python run.py --cli
EOFCMD
    
    chmod +x "$BIN_DIR/Unearth-cli"
    
    print_msg "Commands created in $BIN_DIR"
}

# Add to PATH if needed
setup_path() {
    BIN_DIR="${HOME}/.local/bin"
    
    # Check if already in PATH
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        print_info "Adding $BIN_DIR to PATH..."
        
        # Detect shell
        if [ -n "$BASH_VERSION" ]; then
            SHELL_RC="${HOME}/.bashrc"
        elif [ -n "$ZSH_VERSION" ]; then
            SHELL_RC="${HOME}/.zshrc"
        else
            SHELL_RC="${HOME}/.profile"
        fi
        
        # Add to shell config
        echo "" >> "$SHELL_RC"
        echo "# Unearth - Added by installer" >> "$SHELL_RC"
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
        
        print_msg "Added to PATH in $SHELL_RC"
        print_warning "Please restart your terminal or run: source $SHELL_RC"
    else
        print_msg "$BIN_DIR already in PATH"
    fi
}

# Create desktop entry (Linux only)
create_desktop_entry() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        print_info "Creating desktop entry..."
        
        DESKTOP_DIR="${HOME}/.local/share/applications"
        mkdir -p "$DESKTOP_DIR"
        
        cat > "$DESKTOP_DIR/Unearth.desktop" << EOF
[Desktop Entry]
Name=Unearth
Comment=Forensic Data Recovery Tool
Exec=${HOME}/.local/bin/Unearth-gui
Icon=${INSTALL_DIR}/icon.png
Terminal=false
Type=Application
Categories=Utility;System;
Keywords=forensics;recovery;Unearth;
EOF
        
        print_msg "Desktop entry created"
    fi
}

# Print completion message
print_completion() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                        ║${NC}"
    echo -e "${GREEN}║  ✓ Unearth Installation Complete!                     ║${NC}"
    echo -e "${GREEN}║                                                        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Installation Location:${NC} $INSTALL_DIR"
    echo ""
    echo -e "${BLUE}Available Commands:${NC}"
    echo -e "  ${GREEN}Unearth${NC}         - Interactive mode (choose GUI/CLI)"
    echo -e "  ${GREEN}Unearth-gui${NC}     - Launch GUI directly"
    echo -e "  ${GREEN}Unearth-cli${NC}     - Launch CLI directly"
    echo ""
    echo -e "${BLUE}Quick Start:${NC}"
    echo -e "  1. Restart your terminal or run: ${YELLOW}source ~/.bashrc${NC}"
    echo -e "  2. Run: ${YELLOW}Unearth${NC}"
    echo -e "  3. Choose option 1 for GUI"
    echo ""
    echo -e "${BLUE}Documentation:${NC} https://github.com/yourusername/Unearth"
    echo -e "${BLUE}Issues:${NC} https://github.com/yourusername/Unearth/issues"
    echo ""
}

# Main installation process
main() {
    print_banner
    
    print_info "Starting Unearth installation..."
    echo ""
    
    # Run installation steps
    check_python
    install_system_deps
    setup_repository
    setup_python_env
    create_commands
    setup_path
    create_desktop_entry
    
    print_completion
}

# Run main
main