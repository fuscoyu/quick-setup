#!/bin/bash

# Interactive Ubuntu Server Setup Script
# This script provides a user-friendly interactive interface for Ubuntu server setup
# Author: Quick Setup
# Version: 1.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

# ASCII Art Banner
show_banner() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    🚀 Ubuntu Server Setup - Interactive Configuration 🚀    ║
║                                                              ║
║    This script will help you configure your Ubuntu server   ║
║    with security hardening and Docker installation.         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo ""
}

# Welcome message
show_welcome() {
    echo -e "${CYAN}Welcome to the Ubuntu Server Setup Wizard!${NC}"
    echo ""
    echo "This interactive setup will guide you through configuring:"
    echo "  ✓ Server hostname"
    echo "  ✓ User account creation"
    echo "  ✓ SSH security configuration"
    echo "  ✓ Docker installation"
    echo "  ✓ Firewall configuration"
    echo ""
    echo -e "${YELLOW}⚠️  Important: This script will make significant changes to your system.${NC}"
    echo -e "${YELLOW}   Make sure you have a backup and alternative access method.${NC}"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        echo "Please run: sudo $0"
        exit 1
    fi
    
    # Check if running on Ubuntu
    if ! grep -q "Ubuntu" /etc/os-release; then
        log_error "This script is designed for Ubuntu only"
        echo "Current OS: $(lsb_release -d | cut -f2)"
        exit 1
    fi
    
    # Check internet connectivity
    if ! ping -c 1 google.com &> /dev/null; then
        log_warning "No internet connectivity detected"
        echo "Some features may not work without internet access."
        read -p "Continue anyway? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            exit 0
        fi
    fi
    
    log_success "Prerequisites check passed"
    echo ""
}

# Input validation functions
validate_hostname() {
    local hostname="$1"
    
    if [[ -z "$hostname" ]]; then
        echo "❌ Hostname cannot be empty"
        return 1
    fi
    
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$ ]]; then
        echo "❌ Invalid hostname format"
        echo "   Use only alphanumeric characters and hyphens"
        return 1
    fi
    
    if [[ ${#hostname} -gt 63 ]]; then
        echo "❌ Hostname too long (max 63 characters)"
        return 1
    fi
    
    echo "✅ Hostname format is valid"
    return 0
}

validate_username() {
    local username="$1"
    
    if [[ -z "$username" ]]; then
        echo "❌ Username cannot be empty"
        return 1
    fi
    
    if [[ ! "$username" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
        echo "❌ Invalid username format"
        echo "   Start with a letter, use only letters, numbers, underscores, and hyphens"
        return 1
    fi
    
    if [[ ${#username} -gt 32 ]]; then
        echo "❌ Username too long (max 32 characters)"
        return 1
    fi
    
    if [[ "$username" =~ ^(root|admin|ubuntu|test|user)$ ]]; then
        echo "⚠️  Warning: Using common username '$username'"
        read -p "Continue? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    
    echo "✅ Username format is valid"
    return 0
}

validate_password() {
    local password="$1"
    
    if [[ ${#password} -lt 8 ]]; then
        echo "❌ Password must be at least 8 characters long"
        return 1
    fi
    
    if [[ ! "$password" =~ [A-Z] ]]; then
        echo "❌ Password must contain at least one uppercase letter"
        return 1
    fi
    
    if [[ ! "$password" =~ [a-z] ]]; then
        echo "❌ Password must contain at least one lowercase letter"
        return 1
    fi
    
    if [[ ! "$password" =~ [0-9] ]]; then
        echo "❌ Password must contain at least one number"
        return 1
    fi
    
    echo "✅ Password strength is good"
    return 0
}

validate_ssh_key() {
    local ssh_key="$1"
    
    if [[ -z "$ssh_key" ]]; then
        echo "⚠️  No SSH key provided - password authentication will be required"
        return 0
    fi
    
    if [[ ! "$ssh_key" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ]]; then
        echo "❌ Invalid SSH key format"
        echo "   Expected: ssh-rsa, ssh-ed25519, or ecdsa-sha2-*"
        return 1
    fi
    
    echo "✅ SSH key format is valid"
    return 0
}

validate_port() {
    local port="$1"
    
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        echo "❌ Port must be a number"
        return 1
    fi
    
    if [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        echo "❌ Port must be between 1 and 65535"
        return 1
    fi
    
    if [[ "$port" -lt 1024 ]] && [[ "$port" != "22" ]]; then
        echo "⚠️  Warning: Port $port is a privileged port (< 1024)"
        read -p "Continue? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    
    # Check if port is already in use
    if netstat -tuln | grep -q ":$port "; then
        echo "❌ Port $port is already in use"
        return 1
    fi
    
    echo "✅ Port $port is available"
    return 0
}

# Interactive input functions
get_hostname() {
    local hostname=""
    while [[ -z "$hostname" ]]; do
        echo ""
        echo -e "${CYAN}📝 Server Hostname Configuration${NC}"
        echo "Enter a hostname for this server (e.g., web-server, db-server):"
        read -p "Hostname: " hostname
        
        if validate_hostname "$hostname"; then
            break
        else
            hostname=""
        fi
    done
    echo "$hostname"
}

get_username() {
    local username=""
    while [[ -z "$username" ]]; do
        echo ""
        echo -e "${CYAN}👤 User Account Configuration${NC}"
        echo "Enter a username to create (default: ubuntu):"
        read -p "Username: " username
        
        if [[ -z "$username" ]]; then
            username="ubuntu"
        fi
        
        if validate_username "$username"; then
            if id "$username" &>/dev/null; then
                echo "⚠️  User '$username' already exists"
                read -p "Continue with existing user? (y/N): " confirm
                if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                    username=""
                fi
            else
                break
            fi
        else
            username=""
        fi
    done
    echo "$username"
}

get_password() {
    local password=""
    local password_confirm=""
    
    echo ""
    echo -e "${CYAN}🔐 Password Configuration${NC}"
    echo "Set a password for the user account?"
    read -p "Set password? (y/N): " set_password
    
    if [[ "$set_password" =~ ^[Yy]$ ]]; then
        while [[ -z "$password" || "$password" != "$password_confirm" ]]; do
            echo ""
            echo "Password requirements:"
            echo "  • At least 8 characters"
            echo "  • At least one uppercase letter"
            echo "  • At least one lowercase letter"
            echo "  • At least one number"
            echo ""
            
            read -s -p "Enter password: " password
            echo ""
            read -s -p "Confirm password: " password_confirm
            echo ""
            
            if [[ -z "$password" ]]; then
                echo "❌ Password cannot be empty"
            elif [[ "$password" != "$password_confirm" ]]; then
                echo "❌ Passwords do not match"
                password=""
            elif ! validate_password "$password"; then
                password=""
            fi
        done
    fi
    echo "$password"
}

get_ssh_key() {
    local ssh_key=""
    
    echo ""
    echo -e "${CYAN}🔑 SSH Key Configuration${NC}"
    echo "SSH key authentication is more secure than passwords."
    echo "You can paste your SSH public key here (or press Enter to skip):"
    echo ""
    echo "Example: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."
    echo ""
    read -p "SSH Public Key: " ssh_key
    
    if [[ -n "$ssh_key" ]]; then
        if ! validate_ssh_key "$ssh_key"; then
            echo ""
            read -p "Continue with invalid key format? (y/N): " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                ssh_key=""
            fi
        fi
    fi
    echo "$ssh_key"
}

get_ssh_port() {
    local ssh_port=""
    while [[ -z "$ssh_port" ]]; do
        echo ""
        echo -e "${CYAN}🌐 SSH Port Configuration${NC}"
        echo "Default SSH port is 22, but using a custom port increases security."
        echo "Enter SSH port (default: 22222):"
        read -p "SSH Port: " ssh_port
        
        if [[ -z "$ssh_port" ]]; then
            ssh_port="22222"
        fi
        
        if ! validate_port "$ssh_port"; then
            ssh_port=""
        fi
    done
    echo "$ssh_port"
}

validate_bbr() {
    local enable_bbr="$1"
    
    if [[ "$enable_bbr" =~ ^[Yy]$ ]]; then
        # Check if BBR module is available
        if modinfo tcp_bbr &>/dev/null; then
            echo "✅ BBR module is available"
            return 0
        else
            echo "❌ BBR module not available in current kernel"
            echo "   BBR requires Linux kernel 4.9+ with BBR support"
            return 1
        fi
    else
        echo "✅ BBR configuration skipped"
        return 0
    fi
}

get_bbr_option() {
    local enable_bbr=""
    
    echo ""
    echo -e "${CYAN}🚀 BBR TCP Congestion Control Configuration${NC}"
    echo "BBR (Bottleneck Bandwidth and RTT) is a modern TCP congestion control algorithm"
    echo "developed by Google that can significantly improve network performance."
    echo ""
    echo -e "${GREEN}Benefits of BBR:${NC}"
    echo "  • Higher throughput and lower latency"
    echo "  • Better performance over lossy networks"
    echo "  • Improved fairness and stability"
    echo "  • Reduced bufferbloat"
    echo ""
    echo -e "${YELLOW}Requirements:${NC}"
    echo "  • Linux kernel 4.9+ with BBR support"
    echo "  • Modern network hardware recommended"
    echo ""
    
    while [[ -z "$enable_bbr" ]]; do
        read -p "Enable BBR TCP congestion control? (y/N): " enable_bbr
        
        if [[ -z "$enable_bbr" ]]; then
            enable_bbr="n"
        fi
        
        if ! validate_bbr "$enable_bbr"; then
            if [[ "$enable_bbr" =~ ^[Yy]$ ]]; then
                read -p "Continue anyway (may fail)? (y/N): " confirm
                if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                    enable_bbr=""
                fi
            fi
        fi
    done
    
    if [[ "$enable_bbr" =~ ^[Yy]$ ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# Configuration summary
show_configuration_summary() {
    local hostname="$1"
    local username="$2"
    local ssh_port="$3"
    local has_password="$4"
    local has_ssh_key="$5"
    local enable_bbr="$6"
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${GREEN}📋 Configuration Summary${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${CYAN}Server Settings:${NC}"
    echo "  Hostname: $hostname"
    echo "  Username: $username"
    echo "  SSH Port: $ssh_port"
    echo ""
    echo -e "${CYAN}Security Settings:${NC}"
    echo "  Root Login: Disabled"
    echo "  Password Auth: Disabled"
    echo "  SSH Key Auth: $([ "$has_ssh_key" = "true" ] && echo "Enabled" || echo "Disabled")"
    echo "  User Password: $([ "$has_password" = "true" ] && echo "Set" || echo "Not set")"
    echo ""
    echo -e "${CYAN}Network Optimization:${NC}"
    echo "  BBR TCP Control: $([ "$enable_bbr" = "true" ] && echo "Enabled" || echo "Disabled")"
    echo ""
    echo -e "${CYAN}Software Installation:${NC}"
    echo "  Docker: Will be installed"
    echo "  Docker Compose: Will be installed"
    echo "  Firewall: Will be configured"
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
}

# Final confirmation
confirm_execution() {
    local hostname="$1"
    local ssh_port="$2"
    
    echo -e "${YELLOW}⚠️  IMPORTANT WARNINGS:${NC}"
    echo ""
    echo "• SSH will be configured on port $ssh_port"
    echo "• Root login will be permanently disabled"
    echo "• Password authentication will be disabled"
    echo "• Only SSH key authentication will be allowed"
    echo "• Make sure you can access the server via SSH key before proceeding!"
    echo ""
    echo -e "${RED}This will make permanent changes to your system.${NC}"
    echo ""
    
    read -p "Do you want to proceed with this configuration? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo ""
        log_info "Configuration cancelled by user."
        echo "You can run this script again anytime."
        exit 0
    fi
}

# Progress indicator
show_progress() {
    local step="$1"
    local total="$2"
    local description="$3"
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${BLUE}Progress: $step/$total - $description${NC}"
    echo "═══════════════════════════════════════════════════════════════"
}

# Main function
main() {
    # Clear screen and show banner
    clear
    show_banner
    show_welcome
    
    # Check prerequisites
    check_prerequisites
    
    # Get configuration
    log_step "Collecting configuration information..."
    
    local hostname=$(get_hostname)
    local username=$(get_username)
    local password=$(get_password)
    local ssh_key=$(get_ssh_key)
    local ssh_port=$(get_ssh_port)
    local enable_bbr=$(get_bbr_option)
    
    # Show configuration summary
    show_configuration_summary "$hostname" "$username" "$ssh_port" \
        "$([ -n "$password" ] && echo "true" || echo "false")" \
        "$([ -n "$ssh_key" ] && echo "true" || echo "false")" \
        "$enable_bbr"
    
    # Final confirmation
    confirm_execution "$hostname" "$ssh_port"
    
    # Execute the main setup script
    show_progress "1" "1" "Starting Ubuntu Server Setup"
    
    echo ""
    log_info "Executing main setup script with your configuration..."
    echo ""
    
    # Build command for main script
    local cmd="./ubuntu-setup.sh --hostname $hostname --username $username --ssh-port $ssh_port"
    
    if [[ -n "$password" ]]; then
        cmd="$cmd --password '$password'"
    fi
    
    if [[ -n "$ssh_key" ]]; then
        cmd="$cmd --ssh-key '$ssh_key'"
    fi
    
    if [[ "$enable_bbr" = "true" ]]; then
        cmd="$cmd --enable-bbr"
    fi
    
    # Execute the command
    eval $cmd
    
    # Final message
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo -e "${GREEN}🎉 Setup Completed Successfully! 🎉${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo -e "${CYAN}Next Steps:${NC}"
    echo "1. Test SSH connection: ssh -p $ssh_port $username@$(hostname -I | awk '{print $1}')"
    echo "2. Run verification script: ./test-installation.sh"
    echo "3. Configure additional services as needed"
    echo ""
    echo -e "${YELLOW}Remember to keep your SSH keys safe!${NC}"
    echo ""
}

# Run main function
main "$@"
