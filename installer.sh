#!/bin/sh

# Ubuntu Server Setup Installer
# Unified script for Ubuntu server configuration with security hardening and Docker installation
# Compatible with both bash and sh
# Author: Quick Setup
# Version: 1.1
# Inspired by haoel's Ubuntu automation scripts
# GitHub: https://github.com/haoel/haoel.github.io/blob/master/scripts/install.ubuntu.18.04.sh

# Exit on any error
set -e

# Set strict mode for better error handling
set -u

# Check for help option before requiring root
if [ $# -gt 0 ] && ([ "$1" = "--help" ] || [ "$1" = "-h" ]); then
    cat << 'EOF'
Ubuntu Server Setup Installer v1.1

Usage: sudo sh installer.sh [OPTIONS]

Interactive Mode (default):
    sudo sh installer.sh                 # Run with interactive feature selection menu

Non-Interactive Mode:
    sudo sh installer.sh --hostname HOSTNAME [OPTIONS]

Options:
    --hostname HOSTNAME    Set server hostname
    --username USERNAME    Set username (default: ubuntu)
    --password PASSWORD    Set user password (optional)
    --ssh-key KEY          Set SSH public key
    --ssh-port PORT        Set SSH port (default: 22222)
    --enable-bbr           Enable BBR TCP congestion control
    --help, -h             Show this help message

Features:
    🎯 Configure All Features (A) - Complete server setup
    🔧 Selective Configuration (S) - Choose individual features
    🛠️  Development Setup (D) - Focus on development tools

Examples:
    sudo sh installer.sh                                    # Interactive mode
    sudo sh installer.sh --hostname web-server             # Non-interactive mode
    sudo sh installer.sh --hostname db-server --enable-bbr # With BBR enabled

Inspired by haoel's Ubuntu automation scripts:
https://github.com/haoel/haoel.github.io/blob/master/scripts/install.ubuntu.18.04.sh
EOF
    exit 0
fi

# Ensure we're running as root for system modifications
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Colors for output (compatible with sh)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log_info() {
    printf "${BLUE}[INFO]${NC} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[SUCCESS]${NC} %s\n" "$1"
}

log_warning() {
    printf "${YELLOW}[WARNING]${NC} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
}

log_step() {
    printf "${PURPLE}[STEP]${NC} %s\n" "$1"
}

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Progress indicator (inspired by haoel's scripts)
show_progress() {
    local current=$1
    local total=$2
    local description=$3
    local percent=$((current * 100 / total))
    printf "\r${CYAN}[%d/%d] (%d%%) %s${NC}" "$current" "$total" "$percent" "$description"
    if [ $current -eq $total ]; then
        echo ""
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Safe download function (inspired by haoel's approach)
safe_download() {
    local url=$1
    local output=$2
    local max_retries=3
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        if curl -fsSL "$url" -o "$output"; then
            return 0
        else
            retry_count=$((retry_count + 1))
            log_warning "Download failed, retrying... ($retry_count/$max_retries)"
            sleep 2
        fi
    done
    
    log_error "Failed to download $url after $max_retries attempts"
    return 1
}

# Backup original files before modification (haoel's best practice)
backup_file() {
    local file=$1
    if [ -f "$file" ] && [ ! -f "$file.backup.$(date +%Y%m%d_%H%M%S)" ]; then
        cp "$file" "$file.backup.$(date +%Y%m%d_%H%M%S)"
        log_info "Backed up $file"
    fi
}

# ASCII Art Banner
show_banner() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    🚀 Ubuntu Server Setup - Unified Installer 🚀           ║
║                                                              ║
║    This script will configure your Ubuntu server with       ║
║    security hardening, Docker installation, and network     ║
║    optimization features.                                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    printf "\n"
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check if running as root
    if [ "$(id -u)" -ne 0 ]; then
        error_exit "This script must be run as root (use sudo)"
    fi
    
    # Check if running on Ubuntu
    if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        error_exit "This script is designed for Ubuntu only"
    fi
    
    # Check internet connectivity
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        log_warning "No internet connectivity detected"
        printf "Some features may not work without internet access.\n"
        printf "Continue anyway? (y/N): "
        read -r confirm < /dev/tty
        if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
            exit 0
        fi
    fi
    
    log_success "Prerequisites check passed"
    printf "\n"
}

# Input validation functions
validate_hostname() {
    HOSTNAME="$1"
    
    if [ -z "$HOSTNAME" ]; then
        printf "❌ Hostname cannot be empty\n"
        return 1
    fi
    
    # Basic hostname validation
    if ! echo "$HOSTNAME" | grep -qE '^[a-zA-Z0-9][a-zA-Z0-9-]*$'; then
        printf "❌ Invalid hostname format\n"
        printf "   Use only alphanumeric characters and hyphens\n"
        return 1
    fi
    
    if [ ${#HOSTNAME} -gt 63 ]; then
        printf "❌ Hostname too long (max 63 characters)\n"
        return 1
    fi
    
    printf "✅ Hostname format is valid\n"
    return 0
}

validate_username() {
    USERNAME="$1"
    
    if [ -z "$USERNAME" ]; then
        printf "❌ Username cannot be empty\n"
        return 1
    fi
    
    if ! echo "$USERNAME" | grep -qE '^[a-zA-Z][a-zA-Z0-9_-]*$'; then
        printf "❌ Invalid username format\n"
        printf "   Start with a letter, use only letters, numbers, underscores, and hyphens\n"
        return 1
    fi
    
    if [ ${#USERNAME} -gt 32 ]; then
        printf "❌ Username too long (max 32 characters)\n"
        return 1
    fi
    
    printf "✅ Username format is valid\n"
    return 0
}

validate_password() {
    PASSWORD="$1"
    
    if [ ${#PASSWORD} -lt 8 ]; then
        printf "❌ Password must be at least 8 characters long\n"
        return 1
    fi
    
    if ! echo "$PASSWORD" | grep -q '[A-Z]'; then
        printf "❌ Password must contain at least one uppercase letter\n"
        return 1
    fi
    
    if ! echo "$PASSWORD" | grep -q '[a-z]'; then
        printf "❌ Password must contain at least one lowercase letter\n"
        return 1
    fi
    
    if ! echo "$PASSWORD" | grep -q '[0-9]'; then
        printf "❌ Password must contain at least one number\n"
        return 1
    fi
    
    printf "✅ Password strength is good\n"
    return 0
}

validate_ssh_key() {
    SSH_KEY="$1"
    
    if [ -z "$SSH_KEY" ]; then
        printf "⚠️  No SSH key provided - password authentication will be required\n"
        return 0
    fi
    
    if ! echo "$SSH_KEY" | grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)'; then
        printf "❌ Invalid SSH key format\n"
        printf "   Expected: ssh-rsa, ssh-ed25519, or ecdsa-sha2-*\n"
        return 1
    fi
    
    printf "✅ SSH key format is valid\n"
    return 0
}

validate_port() {
    PORT="$1"
    
    if ! echo "$PORT" | grep -qE '^[0-9]+$'; then
        printf "❌ Port must be a number\n"
        return 1
    fi
    
    if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        printf "❌ Port must be between 1 and 65535\n"
        return 1
    fi
    
    if [ "$PORT" -lt 1024 ] && [ "$PORT" != "22" ]; then
        printf "⚠️  Warning: Port %s is a privileged port (< 1024)\n" "$PORT"
        printf "Continue? (y/N): "
        read -r confirm < /dev/tty
        if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
            return 1
        fi
    fi
    
    # Check if port is already in use
    if netstat -tuln 2>/dev/null | grep -q ":$PORT "; then
        printf "❌ Port %s is already in use\n" "$PORT"
        return 1
    fi
    
    printf "✅ Port %s is available\n" "$PORT"
    return 0
}

# Feature selection menu
show_feature_menu() {
    clear
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              🎛️  Ubuntu Server Setup Features              ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}📋 Available Configuration Options:${NC}"
    echo ""
    echo -e "  ${YELLOW}1.${NC} 🖥️  Server Hostname Configuration"
    echo -e "     • Set custom hostname for the server"
    echo -e "     • Validate hostname format and length"
    echo ""
    echo -e "  ${YELLOW}2.${NC} 👤 User Account Management"
    echo -e "     • Create new Ubuntu user account"
    echo -e "     • Configure passwordless sudo access"
    echo -e "     • Set user password (optional)"
    echo ""
    echo -e "  ${YELLOW}3.${NC} 🔐 SSH Security Hardening"
    echo -e "     • Add SSH public key for authentication"
    echo -e "     • Change SSH port (default: 22222)"
    echo -e "     • Disable root login"
    echo -e "     • Disable password authentication"
    echo ""
    echo -e "  ${YELLOW}4.${NC} 🐳 Docker Installation"
    echo -e "     • Remove old Docker versions"
    echo -e "     • Install Docker CE and Docker Compose"
    echo -e "     • Configure Docker service"
    echo -e "     • Add user to docker group"
    echo ""
    echo -e "  ${YELLOW}5.${NC} 🔥 Firewall Configuration"
    echo -e "     • Configure UFW firewall"
    echo -e "     • Allow SSH on custom port"
    echo -e "     • Enable firewall protection"
    echo ""
    echo -e "  ${YELLOW}6.${NC} 🚀 BBR Network Optimization"
    echo -e "     • Enable BBR TCP congestion control"
    echo -e "     • Improve network performance"
    echo -e "     • Reduce latency and bufferbloat"
    echo ""
    echo -e "  ${YELLOW}7.${NC} 📦 System Updates"
    echo -e "     • Update package lists"
    echo -e "     • Upgrade system packages"
    echo ""
    echo -e "  ${YELLOW}8.${NC} 🔧 Security Best Practices"
    echo -e "     • Apply security recommendations"
    echo -e "     • Configure system hardening"
    echo ""
    echo -e "  ${YELLOW}9.${NC} 🛠️  Development Tools (Inspired by haoel's script)"
    echo -e "     • Install Git, curl, wget, vim, tmux"
    echo -e "     • Install build-essential, python3, pip"
    echo -e "     • Configure development environment"
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                        Configuration Options                ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${GREEN}A)${NC} 🎯 Configure All Features (Recommended for new servers)"
    echo -e "  ${GREEN}S)${NC} 🔧 Selective Configuration (Choose individual features)"
    echo -e "  ${GREEN}D)${NC} 🛠️  Development Setup (Focus on development tools)"
    echo -e "  ${GREEN}Q)${NC} ❌ Quit Setup"
    echo ""
}

get_feature_selection() {
    while true; do
        show_feature_menu
        echo -n "Please select an option (A/S/D/Q): "
        read -r choice < /dev/tty
        case "$choice" in
            [Aa])
                echo -e "${GREEN}✅ Selected: Configure All Features${NC}"
                echo "all"
                return
                ;;
            [Ss])
                echo -e "${GREEN}✅ Selected: Selective Configuration${NC}"
                echo "selective"
                return
                ;;
            [Dd])
                echo -e "${GREEN}✅ Selected: Development Setup${NC}"
                echo "development"
                return
                ;;
            [Qq])
                echo -e "${YELLOW}👋 Setup cancelled by user${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Invalid option. Please choose A, S, D, or Q.${NC}"
                sleep 2
                ;;
        esac
    done
}

get_selective_features() {
    local selected_features=""
    
    echo ""
    echo -e "${CYAN}🎯 Selective Feature Configuration${NC}"
    echo "Select the features you want to configure (y/n for each):"
    echo ""
    
    # Feature 1: Hostname
    echo -n "1. Configure server hostname? (y/N): "
    read -r choice < /dev/tty
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        selected_features="$selected_features,hostname"
        echo -e "${GREEN}✓ Hostname configuration enabled${NC}"
    fi
    
    # Feature 2: User Account
    echo -n "2. Configure user account? (y/N): "
    read -r choice < /dev/tty
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        selected_features="$selected_features,user"
        echo -e "${GREEN}✓ User account configuration enabled${NC}"
    fi
    
    # Feature 3: SSH Security
    echo -n "3. Configure SSH security? (y/N): "
    read -r choice < /dev/tty
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        selected_features="$selected_features,ssh"
        echo -e "${GREEN}✓ SSH security configuration enabled${NC}"
    fi
    
    # Feature 4: Docker
    echo -n "4. Install Docker? (y/N): "
    read -r choice < /dev/tty
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        selected_features="$selected_features,docker"
        echo -e "${GREEN}✓ Docker installation enabled${NC}"
    fi
    
    # Feature 5: Firewall
    echo -n "5. Configure firewall? (y/N): "
    read -r choice < /dev/tty
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        selected_features="$selected_features,firewall"
        echo -e "${GREEN}✓ Firewall configuration enabled${NC}"
    fi
    
    # Feature 6: BBR
    echo -n "6. Enable BBR network optimization? (y/N): "
    read -r choice < /dev/tty
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        selected_features="$selected_features,bbr"
        echo -e "${GREEN}✓ BBR optimization enabled${NC}"
    fi
    
    # Feature 7: System Updates
    echo -n "7. Update system packages? (y/N): "
    read -r choice < /dev/tty
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        selected_features="$selected_features,updates"
        echo -e "${GREEN}✓ System updates enabled${NC}"
    fi
    
    # Feature 8: Security Best Practices
    echo -n "8. Apply security best practices? (y/N): "
    read -r choice < /dev/tty
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        selected_features="$selected_features,security"
        echo -e "${GREEN}✓ Security hardening enabled${NC}"
    fi
    
    # Feature 9: Development Tools
    echo -n "9. Install development tools? (y/N): "
    read -r choice < /dev/tty
    if [ "$choice" = "y" ] || [ "$choice" = "Y" ]; then
        selected_features="$selected_features,devtools"
        echo -e "${GREEN}✓ Development tools enabled${NC}"
    fi
    
    echo ""
    echo -e "${GREEN}📋 Selected Features:${NC}"
    echo "$selected_features" | tr ',' '\n' | grep -v '^$' | sed 's/^/  • /'
    echo ""
    
    echo -n "Proceed with selected features? (y/N): "
    read -r confirm < /dev/tty
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        echo -e "${YELLOW}Configuration cancelled${NC}"
        exit 0
    fi
    
    echo "$selected_features"
}

# Development tools installation (inspired by haoel's script)
install_development_tools() {
    log_step "Installing development tools and essential packages..."
    
    # Essential packages
    local packages="curl wget git vim tmux build-essential software-properties-common apt-transport-https ca-certificates gnupg lsb-release"
    
    show_progress 1 4 "Updating package lists..."
    apt-get update -y >/dev/null 2>&1 || error_exit "Failed to update package lists"
    
    show_progress 2 4 "Installing essential packages..."
    apt-get install -y $packages >/dev/null 2>&1 || error_exit "Failed to install essential packages"
    
    show_progress 3 4 "Installing Python3 and pip..."
    apt-get install -y python3 python3-pip python3-venv >/dev/null 2>&1 || error_exit "Failed to install Python3"
    
    show_progress 4 4 "Installing Node.js (if available)..."
    if command_exists curl; then
        # Try to install Node.js using NodeSource repository
        curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - >/dev/null 2>&1 || log_warning "Node.js installation failed, skipping..."
        apt-get install -y nodejs >/dev/null 2>&1 || log_warning "Node.js installation failed, skipping..."
    fi
    
    log_success "Development tools installation completed"
}

configure_development_setup() {
    local has_ssh_key="false"
    local has_password="false"
    
    echo ""
    echo -e "${CYAN}🛠️  Starting Development Setup${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    
    # Step 1: Install development tools
    echo ""
    echo -e "${YELLOW}[STEP 1/6]${NC} Installing development tools..."
    install_development_tools
    
    # Step 2: Configure user account (if not already done)
    echo ""
    echo -e "${YELLOW}[STEP 2/6]${NC} Configuring user account..."
    if [ -z "$USERNAME" ]; then
        USERNAME=$(get_username)
    fi
    if [ -z "$PASSWORD" ]; then
        PASSWORD=$(get_password)
        if [ -n "$PASSWORD" ]; then
            has_password="true"
        fi
    fi
    
    # Step 3: Configure SSH (essential for development)
    echo ""
    echo -e "${YELLOW}[STEP 3/6]${NC} Configuring SSH security..."
    if [ -z "$SSH_KEY" ]; then
        SSH_KEY=$(get_ssh_key)
        if [ -n "$SSH_KEY" ]; then
            has_ssh_key="true"
        fi
    fi
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(get_ssh_port)
    fi
    
    # Step 4: Update system
    echo ""
    echo -e "${YELLOW}[STEP 4/6]${NC} Updating system packages..."
    update_system_packages
    
    # Step 5: Install Docker (useful for development)
    echo ""
    echo -e "${YELLOW}[STEP 5/6]${NC} Installing Docker..."
    install_docker "$USERNAME"
    
    # Step 6: Apply basic security
    echo ""
    echo -e "${YELLOW}[STEP 6/6]${NC} Applying basic security settings..."
    apply_security_best_practices "$HOSTNAME" "$USERNAME" "$SSH_PORT" "$has_ssh_key" "$has_password"
    
    echo ""
    echo -e "${GREEN}✅ Development setup completed successfully!${NC}"
}

configure_selective_features() {
    local features="$1"
    local has_ssh_key="false"
    local has_password="false"
    
    echo ""
    echo -e "${CYAN}🔧 Starting Selective Configuration${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    
    # Check if hostname configuration is selected
    if echo "$features" | grep -q "hostname"; then
        echo ""
        echo -e "${YELLOW}[STEP 1/8]${NC} Configuring server hostname..."
        if [ -z "$HOSTNAME" ]; then
            HOSTNAME=$(get_hostname)
        fi
    fi
    
    # Check if user account configuration is selected
    if echo "$features" | grep -q "user"; then
        echo ""
        echo -e "${YELLOW}[STEP 2/8]${NC} Configuring user account..."
        if [ -z "$USERNAME" ]; then
            USERNAME=$(get_username)
        fi
        if [ -z "$PASSWORD" ]; then
            PASSWORD=$(get_password)
            if [ -n "$PASSWORD" ]; then
                has_password="true"
            fi
        fi
    fi
    
    # Check if SSH security configuration is selected
    if echo "$features" | grep -q "ssh"; then
        echo ""
        echo -e "${YELLOW}[STEP 3/8]${NC} Configuring SSH security..."
        if [ -z "$SSH_KEY" ]; then
            SSH_KEY=$(get_ssh_key)
            if [ -n "$SSH_KEY" ]; then
                has_ssh_key="true"
            fi
        fi
        if [ -z "$SSH_PORT" ]; then
            SSH_PORT=$(get_ssh_port)
        fi
    fi
    
    # Check if system updates are selected
    if echo "$features" | grep -q "updates"; then
        echo ""
        echo -e "${YELLOW}[STEP 4/8]${NC} Updating system packages..."
        update_system_packages
    fi
    
    # Check if Docker installation is selected
    if echo "$features" | grep -q "docker"; then
        echo ""
        echo -e "${YELLOW}[STEP 5/8]${NC} Installing Docker..."
        install_docker "$USERNAME"
    fi
    
    # Check if firewall configuration is selected
    if echo "$features" | grep -q "firewall"; then
        echo ""
        echo -e "${YELLOW}[STEP 6/8]${NC} Configuring firewall..."
        configure_firewall "$SSH_PORT"
    fi
    
    # Check if BBR optimization is selected
    if echo "$features" | grep -q "bbr"; then
        echo ""
        echo -e "${YELLOW}[STEP 7/8]${NC} Enabling BBR optimization..."
        enable_bbr
    fi
    
    # Check if security best practices are selected
    if echo "$features" | grep -q "security"; then
        echo ""
        echo -e "${YELLOW}[STEP 8/9]${NC} Applying security best practices..."
        apply_security_best_practices "$HOSTNAME" "$USERNAME" "$SSH_PORT" "$has_ssh_key" "$has_password"
    fi
    
    # Check if development tools are selected
    if echo "$features" | grep -q "devtools"; then
        echo ""
        echo -e "${YELLOW}[STEP 9/9]${NC} Installing development tools..."
        install_development_tools
    fi
    
    echo ""
    echo -e "${GREEN}✅ Selective configuration completed successfully!${NC}"
}

configure_all_features() {
    local has_ssh_key="false"
    local has_password="false"
    
    echo ""
    echo -e "${CYAN}🎯 Starting Complete Configuration${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    
    # Step 1: Configure hostname
    echo ""
    echo -e "${YELLOW}[STEP 1/8]${NC} Configuring server hostname..."
    if [ -z "$HOSTNAME" ]; then
        HOSTNAME=$(get_hostname)
    fi
    
    # Step 2: Configure user account
    echo ""
    echo -e "${YELLOW}[STEP 2/8]${NC} Configuring user account..."
    if [ -z "$USERNAME" ]; then
        USERNAME=$(get_username)
    fi
    if [ -z "$PASSWORD" ]; then
        PASSWORD=$(get_password)
        if [ -n "$PASSWORD" ]; then
            has_password="true"
        fi
    fi
    
    # Step 3: Configure SSH security
    echo ""
    echo -e "${YELLOW}[STEP 3/8]${NC} Configuring SSH security..."
    if [ -z "$SSH_KEY" ]; then
        SSH_KEY=$(get_ssh_key)
        if [ -n "$SSH_KEY" ]; then
            has_ssh_key="true"
        fi
    fi
    if [ -z "$SSH_PORT" ]; then
        SSH_PORT=$(get_ssh_port)
    fi
    
    # Step 4: Update system packages
    echo ""
    echo -e "${YELLOW}[STEP 4/8]${NC} Updating system packages..."
    update_system_packages
    
    # Step 5: Install Docker
    echo ""
    echo -e "${YELLOW}[STEP 5/8]${NC} Installing Docker..."
    install_docker "$USERNAME"
    
    # Step 6: Configure firewall
    echo ""
    echo -e "${YELLOW}[STEP 6/8]${NC} Configuring firewall..."
    configure_firewall "$SSH_PORT"
    
    # Step 7: Enable BBR optimization
    echo ""
    echo -e "${YELLOW}[STEP 7/8]${NC} Enabling BBR optimization..."
    enable_bbr
    
    # Step 8: Apply security best practices
    echo ""
    echo -e "${YELLOW}[STEP 8/8]${NC} Applying security best practices..."
    apply_security_best_practices "$HOSTNAME" "$USERNAME" "$SSH_PORT" "$has_ssh_key" "$has_password"
    
    echo ""
    echo -e "${GREEN}✅ Complete configuration finished successfully!${NC}"
}

# Interactive input functions
get_hostname() {
    HOSTNAME=""
    while [ -z "$HOSTNAME" ]; do
        echo ""
        echo -e "${CYAN}📝 Server Hostname Configuration${NC}"
        echo "Enter a hostname for this server (e.g., web-server, db-server):"
        echo -n "Hostname: "
        read -r HOSTNAME
        
        if validate_hostname "$HOSTNAME"; then
            break
        else
            echo "Invalid hostname, please try again"
        fi
    done
    echo "$HOSTNAME"
}

get_username() {
    USERNAME=""
    while [ -z "$USERNAME" ]; do
        echo ""
        echo -e "${CYAN}👤 User Account Configuration${NC}"
        echo "Enter a username to create (default: ubuntu):"
        echo -n "Username: "
        read -r USERNAME < /dev/tty
        
        if [ -z "$USERNAME" ]; then
            USERNAME="ubuntu"
        fi
        
        if validate_username "$USERNAME"; then
            if id "$USERNAME" >/dev/null 2>&1; then
                echo -e "⚠️  User '$USERNAME' already exists"
                echo -n "Continue with existing user? (y/N): "
                read -r confirm < /dev/tty
                if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
                    USERNAME=""
                else
                    break
                fi
            else
                break
            fi
        else
            USERNAME=""
        fi
    done
    echo "$USERNAME"
}

get_password() {
    PASSWORD=""
    PASSWORD_CONFIRM=""
    
    echo ""
    echo -e "${CYAN}🔐 Password Configuration${NC}"
    echo "Set a password for the user account?"
    echo -n "Set password? (y/N): "
        read -r set_password < /dev/tty
    
    if [ "$set_password" = "y" ] || [ "$set_password" = "Y" ]; then
        while [ -z "$PASSWORD" ] || [ "$PASSWORD" != "$PASSWORD_confirm" ]; do
            printf "\n"
            printf "Password requirements:\n"
            printf "  • At least 8 characters\n"
            printf "  • At least one uppercase letter\n"
            printf "  • At least one lowercase letter\n"
            printf "  • At least one number\n"
            printf "\n"
            
            printf "Enter password: "
            read -rs password < /dev/tty
            printf "\n"
            printf "Confirm password: "
            read -rs password_confirm < /dev/tty
            printf "\n"
            
            if [ -z "$PASSWORD" ]; then
                printf "❌ Password cannot be empty\n"
            elif [ "$PASSWORD" != "$PASSWORD_confirm" ]; then
                printf "❌ Passwords do not match\n"
                PASSWORD=""
            elif ! validate_password "$PASSWORD"; then
                PASSWORD=""
            fi
        done
    fi
    echo "$PASSWORD"
}

get_ssh_key() {
    SSH_KEY=""
    
    printf "\n"
    printf "${CYAN}🔑 SSH Key Configuration${NC}\n"
    printf "SSH key authentication is more secure than passwords.\n"
    printf "You can paste your SSH public key here (or press Enter to skip):\n"
    printf "\n"
    printf "Example: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC...\n"
    printf "\n"
    printf "SSH Public Key: "
    read -r ssh_key < /dev/tty
    
    if [ -n "$SSH_KEY" ]; then
        if ! validate_ssh_key "$SSH_KEY"; then
            printf "\n"
            printf "Continue with invalid key format? (y/N): "
            read -r confirm < /dev/tty
            if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
                SSH_KEY=""
            fi
        fi
    fi
    echo "$SSH_KEY"
}

get_ssh_port() {
    SSH_PORT=""
    while [ -z "$SSH_PORT" ]; do
        printf "\n"
        printf "${CYAN}🌐 SSH Port Configuration${NC}\n"
        printf "Default SSH port is 22, but using a custom port increases security.\n"
        printf "Enter SSH port (default: 22222):\n"
        printf "SSH Port: "
        read -r ssh_port < /dev/tty
        
        if [ -z "$SSH_PORT" ]; then
            SSH_PORT="22222"
        fi
        
        if ! validate_port "$SSH_PORT"; then
            SSH_PORT=""
        fi
    done
    echo "$SSH_PORT"
}

get_bbr_option() {
    ENABLE_BBR=""
    
    printf "\n"
    printf "${CYAN}🚀 BBR TCP Congestion Control Configuration${NC}\n"
    printf "BBR (Bottleneck Bandwidth and RTT) is a modern TCP congestion control algorithm\n"
    printf "developed by Google that can significantly improve network performance.\n"
    printf "\n"
    printf "${GREEN}Benefits of BBR:${NC}\n"
    printf "  • Higher throughput and lower latency\n"
    printf "  • Better performance over lossy networks\n"
    printf "  • Improved fairness and stability\n"
    printf "  • Reduced bufferbloat\n"
    printf "\n"
    printf "${YELLOW}Requirements:${NC}\n"
    printf "  • Linux kernel 4.9+ with BBR support\n"
    printf "  • Modern network hardware recommended\n"
    printf "\n"
    
    while [ -z "$ENABLE_BBR" ]; do
        printf "Enable BBR TCP congestion control? (y/N): "
        read -r enable_bbr < /dev/tty
        
        if [ -z "$ENABLE_BBR" ]; then
            ENABLE_BBR="n"
        fi
        
        if [ "$ENABLE_BBR" = "y" ] || [ "$ENABLE_BBR" = "Y" ]; then
            # Check if BBR is available
            if modinfo tcp_bbr >/dev/null 2>&1; then
                printf "✅ BBR module is available\n"
                break
            else
                printf "❌ BBR module not available in current kernel\n"
                printf "   BBR requires Linux kernel 4.9+ with BBR support\n"
                printf "Continue anyway (may fail)? (y/N): "
                read -r confirm < /dev/tty
                if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
                    break
                else
                    ENABLE_BBR=""
                fi
            fi
        else
            printf "✅ BBR configuration skipped\n"
            break
        fi
    done
    
    if [ "$ENABLE_BBR" = "y" ] || [ "$ENABLE_BBR" = "Y" ]; then
        echo "true"
    else
        echo "false"
    fi
}

# Configuration summary
show_configuration_summary() {
    HOSTNAME="$1"
    USERNAME="$2"
    SSH_PORT="$3"
    has_PASSWORD="$4"
    has_SSH_KEY="$5"
    ENABLE_BBR="$6"
    
    printf "\n"
    printf "═══════════════════════════════════════════════════════════════\n"
    printf "${GREEN}📋 Configuration Summary${NC}\n"
    printf "═══════════════════════════════════════════════════════════════\n"
    printf "\n"
    printf "${CYAN}Server Settings:${NC}\n"
    printf "  Hostname: %s\n" "$HOSTNAME"
    printf "  Username: %s\n" "$USERNAME"
    printf "  SSH Port: %s\n" "$SSH_PORT"
    printf "\n"
    printf "${CYAN}Security Settings:${NC}\n"
    printf "  Root Login: Disabled\n"
    printf "  Password Auth: Disabled\n"
    printf "  SSH Key Auth: %s\n" "$(if [ "$has_ssh_key" = "true" ]; then echo "Enabled"; else echo "Disabled"; fi)"
    printf "  User Password: %s\n" "$(if [ "$has_password" = "true" ]; then echo "Set"; else echo "Not set"; fi)"
    printf "\n"
    printf "${CYAN}Network Optimization:${NC}\n"
    printf "  BBR TCP Control: %s\n" "$(if [ "$ENABLE_BBR" = "true" ]; then echo "Enabled"; else echo "Disabled"; fi)"
    printf "\n"
    printf "${CYAN}Software Installation:${NC}\n"
    printf "  Docker: Will be installed\n"
    printf "  Docker Compose: Will be installed\n"
    printf "  Firewall: Will be configured\n"
    printf "\n"
    printf "═══════════════════════════════════════════════════════════════\n"
    printf "\n"
}

# Final confirmation
confirm_execution() {
    HOSTNAME="$1"
    SSH_PORT="$2"
    
    printf "${YELLOW}⚠️  IMPORTANT WARNINGS:${NC}\n"
    printf "\n"
    printf "• SSH will be configured on port %s\n" "$SSH_PORT"
    printf "• Root login will be disabled\n"
    printf "• Password authentication will be disabled\n"
    printf "• Only SSH key authentication will be allowed\n"
    printf "• Make sure you can access the server via SSH key before proceeding!\n"
    printf "\n"
    printf "${RED}This will make permanent changes to your system.${NC}\n"
    printf "\n"
    
    printf "Do you want to proceed with this configuration? (y/N): "
    read -r confirm < /dev/tty
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        printf "\n"
        log_info "Configuration cancelled by user."
        printf "You can run this script again anytime.\n"
        exit 0
    fi
}

# Setup functions
update_system() {
    log_info "Updating system packages..."
    apt-get update -y || error_exit "Failed to update package list"
    apt-get upgrade -y || error_exit "Failed to upgrade packages"
    log_success "System packages updated successfully"
}

set_hostname() {
    HOSTNAME="$1"
    
    log_info "Setting hostname to: $HOSTNAME"
    
    # Set hostname temporarily
    hostnamectl set-hostname "$HOSTNAME" || error_exit "Failed to set hostname"
    
    # Update /etc/hosts
    sed -i "s/127.0.1.1.*/127.0.1.1\t$HOSTNAME/" /etc/hosts || error_exit "Failed to update /etc/hosts"
    
    log_success "Hostname set to: $HOSTNAME"
}

create_ubuntu_user() {
    USERNAME="$1"
    PASSWORD="$2"
    
    log_info "Creating user: $USERNAME"
    
    # Check if user already exists
    if id "$USERNAME" >/dev/null 2>&1; then
        log_warning "User $USERNAME already exists"
        return 0
    fi
    
    # Create user with sudo privileges
    useradd -m -s /bin/bash "$USERNAME" || error_exit "Failed to create user $USERNAME"
    
    # Add user to sudo group
    usermod -aG sudo "$USERNAME" || error_exit "Failed to add $USERNAME to sudo group"
    
    # Set password if provided
    if [ -n "$PASSWORD" ]; then
        echo "$USERNAME:$PASSWORD" | chpasswd || error_exit "Failed to set password for $USERNAME"
        log_success "Password set for user: $USERNAME"
    fi
    
    # Configure passwordless sudo for the user
    echo "$USERNAME ALL=(ALL) NOPASSWD:ALL" | tee "/etc/sudoers.d/dont-prompt-$USERNAME-for-sudo-password" >/dev/null || error_exit "Failed to configure passwordless sudo for $USERNAME"
    chmod 440 "/etc/sudoers.d/dont-prompt-$USERNAME-for-sudo-password" || error_exit "Failed to set sudoers file permissions"
    
    log_success "User $USERNAME created successfully with sudo privileges and passwordless sudo configured"
}

setup_ssh_key() {
    USERNAME="$1"
    SSH_KEY="$2"
    
    if [ -z "$SSH_KEY" ]; then
        log_warning "No SSH key provided, skipping SSH key setup"
        return 0
    fi
    
    log_info "Setting up SSH key for user: $USERNAME"
    
    # Create .ssh directory
    ssh_dir="/home/$USERNAME/.ssh"
    mkdir -p "$ssh_dir" || error_exit "Failed to create .ssh directory"
    
    # Set proper permissions
    chmod 700 "$ssh_dir" || error_exit "Failed to set .ssh directory permissions"
    
    # Add SSH key to authorized_keys
    echo "$SSH_KEY" >> "$ssh_dir/authorized_keys" || error_exit "Failed to add SSH key"
    
    # Set proper permissions for authorized_keys
    chmod 600 "$ssh_dir/authorized_keys" || error_exit "Failed to set authorized_keys permissions"
    
    # Change ownership
    chown -R "$USERNAME:$USERNAME" "$ssh_dir" || error_exit "Failed to change .ssh directory ownership"
    
    log_success "SSH key setup completed for user: $USERNAME"
}

configure_ssh_security() {
    SSH_PORT="$1"
    
    log_info "Configuring SSH security settings..."
    
    # Backup original sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup || error_exit "Failed to backup sshd_config"
    
    # Create new sshd_config with security settings
    cat > /etc/ssh/sshd_config << EOF
# SSH Security Configuration
Port $SSH_PORT
Protocol 2

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile %h/.ssh/authorized_keys

# Security settings
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60

# Allow specific users (adjust as needed)
AllowUsers ubuntu

# Logging
SyslogFacility AUTH
LogLevel INFO

# Disable unused features
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes

# Use strong ciphers
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256

# Disable agent forwarding
AllowAgentForwarding no
AllowTcpForwarding yes
GatewayPorts no

# Disable unused forwarding
PermitTunnel no
PermitUserEnvironment no
EOF

    # Test SSH configuration
    sshd -t || error_exit "SSH configuration test failed"
    
    # Restart SSH service
    systemctl restart ssh || error_exit "Failed to restart SSH service"
    
    log_success "SSH security configuration completed"
}

install_docker() {
    log_info "Installing Docker..."
    
    # Remove old Docker versions
    apt-get remove -y docker docker-engine docker.io containerd runc || true
    
    # Install prerequisites
    apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release || error_exit "Failed to install Docker prerequisites"
    
    # Add Docker's official GPG key
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg || error_exit "Failed to add Docker GPG key"
    
    # Set up Docker repository
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null || error_exit "Failed to set up Docker repository"
    
    # Update package index
    apt-get update -y || error_exit "Failed to update package index"
    
    # Install Docker Engine
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || error_exit "Failed to install Docker"
    
    # Start and enable Docker
    systemctl start docker || error_exit "Failed to start Docker"
    systemctl enable docker || error_exit "Failed to enable Docker"
    
    # Move docker-compose to /usr/bin
    if [ -f /usr/libexec/docker/cli-plugins/docker-compose ]; then
        mv /usr/libexec/docker/cli-plugins/docker-compose /usr/bin/docker-compose || error_exit "Failed to move docker-compose to /usr/bin"
    else
        log_warning "docker-compose not found, skipping move"
    fi
    
    # Add ubuntu user to docker group
    usermod -aG docker ubuntu || error_exit "Failed to add ubuntu user to docker group"
    
    log_success "Docker installed successfully"
}

configure_firewall() {
    SSH_PORT="$1"
    
    log_info "Configuring UFW firewall..."
    
    # Install UFW if not present
    apt-get install -y ufw || error_exit "Failed to install UFW"
    
    # Reset UFW to defaults
    ufw --force reset || error_exit "Failed to reset UFW"
    
    # Set default policies
    ufw default deny incoming || error_exit "Failed to set UFW default deny incoming"
    ufw default allow outgoing || error_exit "Failed to set UFW default allow outgoing"
    
    # Allow SSH on custom port
    ufw allow "$SSH_PORT/tcp" || error_exit "Failed to allow SSH port in UFW"
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp || error_exit "Failed to allow HTTP in UFW"
    ufw allow 443/tcp || error_exit "Failed to allow HTTPS in UFW"
    
    # Enable UFW
    ufw --force enable || error_exit "Failed to enable UFW"
    
    log_success "Firewall configured successfully"
    log_warning "SSH port $SSH_PORT is open. Make sure to test SSH connection before closing this session!"
}

configure_bbr() {
    ENABLE_BBR="$1"
    
    if [ "$ENABLE_BBR" != "true" ]; then
        log_info "BBR configuration skipped"
        return 0
    fi
    
    log_info "Configuring BBR TCP congestion control..."
    
    # Check if BBR module is available
    if ! modinfo tcp_bbr >/dev/null 2>&1; then
        log_error "BBR module (tcp_bbr) is not available in this kernel"
        log_warning "BBR requires Linux kernel 4.9+ with BBR support"
        return 1
    fi
    
    # Load BBR module
    modprobe tcp_bbr || error_exit "Failed to load BBR module"
    
    # Ensure BBR module loads at boot
    echo "tcp_bbr" | tee --append /etc/modules-load.d/modules.conf || error_exit "Failed to add BBR to modules.conf"
    
    # Configure sysctl parameters for BBR
    echo "net.core.default_qdisc=fq" | tee --append /etc/sysctl.conf || error_exit "Failed to add net.core.default_qdisc to sysctl.conf"
    echo "net.ipv4.tcp_congestion_control=bbr" | tee --append /etc/sysctl.conf || error_exit "Failed to add net.ipv4.tcp_congestion_control to sysctl.conf"
    
    # Apply sysctl changes
    sysctl -p || error_exit "Failed to apply sysctl changes"
    
    # Verify BBR is active
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control)
    if [ "$current_cc" = "bbr" ]; then
        log_success "BBR TCP congestion control configured successfully"
        log_info "Current congestion control: $current_cc"
    else
        log_warning "BBR may not be fully active. Current congestion control: $current_cc"
    fi
}

# Help function
show_help() {
    cat << EOF
Ubuntu Server Setup Installer

Usage: sh installer.sh [OPTIONS]

Interactive Mode (default):
    sh installer.sh                 # Run with interactive prompts for all settings

Non-Interactive Mode:
    sh installer.sh --hostname HOSTNAME [OPTIONS]

Options:
    --hostname HOSTNAME     Set the server hostname (required for non-interactive)
    --username USERNAME     Create user with specified name (default: ubuntu)
    --password PASSWORD     Set password for the user
    --ssh-key SSH_KEY       SSH public key for the user
    --ssh-port PORT         SSH port (default: 22222)
    --enable-bbr            Enable BBR TCP congestion control
    --non-interactive       Force non-interactive mode
    --help                  Show this help message

Examples:
    # Interactive mode (recommended for first-time setup)
    sh installer.sh
    
    # Non-interactive with all parameters
    sh installer.sh --hostname myserver --ssh-key "ssh-rsa..." --enable-bbr
    
    # Non-interactive with minimal parameters
    sh installer.sh --hostname myserver --non-interactive
    
    # Mixed mode (some parameters provided, others prompted)
    sh installer.sh --hostname myserver --ssh-port 2222 --enable-bbr

Features:
    • Hostname configuration
    • User account creation with sudo privileges
    • SSH security hardening (custom port, disable root/password auth)
    • SSH key authentication setup
    • Docker and Docker Compose installation
    • UFW firewall configuration
    • BBR TCP congestion control (optional)
    • Comprehensive input validation
    • Configuration preview and confirmation
    • Compatible with both bash and sh

EOF
}

# Main function
main() {
    # Parse command line arguments first to handle --help
    HOSTNAME=""
    USERNAME=""
    PASSWORD=""
    SSH_KEY=""
    SSH_PORT=""
    ENABLE_BBR=true
    INTERACTIVE_MODE=true
    
    while [ $# -gt 0 ]; do
        case $1 in
            --hostname)
                HOSTNAME="$2"
                INTERACTIVE_MODE=false
                shift 2
                ;;
            --username)
                USERNAME="$2"
                INTERACTIVE_MODE=false
                shift 2
                ;;
            --password)
                PASSWORD="$2"
                INTERACTIVE_MODE=false
                shift 2
                ;;
            --ssh-key)
                SSH_KEY="$2"
                INTERACTIVE_MODE=false
                shift 2
                ;;
            --ssh-port)
                SSH_PORT="$2"
                INTERACTIVE_MODE=false
                shift 2
                ;;
            --enable-bbr)
                ENABLE_BBR="true"
                INTERACTIVE_MODE=false
                shift
                ;;
            --non-interactive)
                INTERACTIVE_MODE=false
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    # Clear screen and show banner
    clear
    show_banner
    
    printf "${CYAN}Welcome to the Ubuntu Server Setup Installer!${NC}\n"
    printf "\n"
    printf "This unified installer will configure your Ubuntu server with:\n"
    printf "  ✓ Server hostname and user account\n"
    printf "  ✓ SSH security hardening\n"
    printf "  ✓ Docker and Docker Compose installation\n"
    printf "  ✓ Firewall configuration\n"
    printf "  ✓ BBR network optimization (optional)\n"
    printf "\n"
    printf "${YELLOW}⚠️  Important: This script will make significant changes to your system.${NC}\n"
    printf "${YELLOW}   Make sure you have a backup and alternative access method.${NC}\n"
    printf "\n"
    
    # Check prerequisites
    check_prerequisites
    
    # Interactive mode - feature selection and configuration
    if [ "$INTERACTIVE_MODE" = true ]; then
        log_info "Running in interactive mode..."
        
        # Show feature selection menu
        feature_selection=$(get_feature_selection)
        
        if [ "$feature_selection" = "selective" ]; then
            # Get selected features
            selected_features=$(get_selective_features)
            
            # Configure selected features
            configure_selective_features "$selected_features"
        elif [ "$feature_selection" = "development" ]; then
            # Configure development setup
            configure_development_setup
        else
            # Configure all features
            configure_all_features
        fi
    else
        # Non-interactive mode - validate required parameters
        if [ -z "$HOSTNAME" ]; then
            error_exit "Hostname is required in non-interactive mode"
        fi
        
        if [ -z "$USERNAME" ]; then
            USERNAME="ubuntu"
        fi
        
        if [ -z "$SSH_PORT" ]; then
            SSH_PORT="22222"
        fi
        
        log_info "Running in non-interactive mode..."
        log_info "Hostname: $HOSTNAME"
        log_info "Username: $USERNAME"
        log_info "SSH Port: $SSH_PORT"
    fi
    
    # Start setup process
    log_info "Starting Ubuntu server setup..."
    
    # Update system
    update_system
    
    # Set hostname
    set_hostname "$HOSTNAME"
    
    # Create user
    create_ubuntu_user "$USERNAME" "$PASSWORD"
    
    # Setup SSH key
    setup_ssh_key "$USERNAME" "$SSH_KEY"
    
    # Configure SSH security
    configure_ssh_security "$SSH_PORT"
    
    # Install Docker
    install_docker
    
    # Configure firewall
    configure_firewall "$SSH_PORT"
    
    # Configure BBR
    configure_bbr "$ENABLE_BBR"
    
    # Final message
    printf "\n"
    printf "═══════════════════════════════════════════════════════════════\n"
    printf "${GREEN}🎉 Setup Completed Successfully! 🎉${NC}\n"
    printf "═══════════════════════════════════════════════════════════════\n"
    printf "\n"
    log_success "Server hostname: $HOSTNAME"
    log_success "SSH port: $SSH_PORT"
    log_success "User created: $USERNAME"
    log_success "Docker installed: $(docker --version)"
    log_success "Docker Compose installed: $(docker-compose --version)"
    if [ "$ENABLE_BBR" = "true" ]; then
        log_success "BBR TCP congestion control: Enabled"
    fi
    printf "\n"
    log_warning "IMPORTANT: Test SSH connection on port $SSH_PORT before closing this session!"
    log_warning "SSH command: ssh -p $SSH_PORT $USERNAME@$(hostname -I | awk '{print $1}')"
    printf "\n"
}

# Run main function
main "$@"
