#!/bin/bash

# Ubuntu Server Setup Script
# This script configures Ubuntu server with security hardening and Docker installation
# Author: Quick Setup
# Version: 1.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
}

# Check if running on Ubuntu
check_ubuntu() {
    if ! grep -q "Ubuntu" /etc/os-release; then
        error_exit "This script is designed for Ubuntu only"
    fi
}

# Update system packages
update_system() {
    log_info "Updating system packages..."
    apt-get update -y || error_exit "Failed to update package list"
    apt-get upgrade -y || error_exit "Failed to upgrade packages"
    log_success "System packages updated successfully"
}

# Set hostname
set_hostname() {
    local hostname="$1"
    
    if [[ -z "$hostname" ]]; then
        error_exit "Hostname cannot be empty"
    fi
    
    log_info "Setting hostname to: $hostname"
    
    # Set hostname temporarily
    hostnamectl set-hostname "$hostname" || error_exit "Failed to set hostname"
    
    # Update /etc/hosts
    sed -i "s/127.0.1.1.*/127.0.1.1\t$hostname/" /etc/hosts || error_exit "Failed to update /etc/hosts"
    
    log_success "Hostname set to: $hostname"
}

# Create Ubuntu user
create_ubuntu_user() {
    local username="$1"
    local password="$2"
    
    if [[ -z "$username" ]]; then
        username="ubuntu"
    fi
    
    log_info "Creating user: $username"
    
    # Check if user already exists
    if id "$username" &>/dev/null; then
        log_warning "User $username already exists"
        return 0
    fi
    
    # Create user with sudo privileges
    useradd -m -s /bin/bash "$username" || error_exit "Failed to create user $username"
    
    # Add user to sudo group
    usermod -aG sudo "$username" || error_exit "Failed to add $username to sudo group"
    
    # Set password if provided
    if [[ -n "$password" ]]; then
        echo "$username:$password" | chpasswd || error_exit "Failed to set password for $username"
        log_success "Password set for user: $username"
    fi
    
    log_success "User $username created successfully with sudo privileges"
}

# Setup SSH key
setup_ssh_key() {
    local username="$1"
    local ssh_key="$2"
    
    if [[ -z "$username" ]]; then
        username="ubuntu"
    fi
    
    if [[ -z "$ssh_key" ]]; then
        log_warning "No SSH key provided, skipping SSH key setup"
        return 0
    fi
    
    log_info "Setting up SSH key for user: $username"
    
    # Create .ssh directory
    local ssh_dir="/home/$username/.ssh"
    mkdir -p "$ssh_dir" || error_exit "Failed to create .ssh directory"
    
    # Set proper permissions
    chmod 700 "$ssh_dir" || error_exit "Failed to set .ssh directory permissions"
    
    # Add SSH key to authorized_keys
    echo "$ssh_key" >> "$ssh_dir/authorized_keys" || error_exit "Failed to add SSH key"
    
    # Set proper permissions for authorized_keys
    chmod 600 "$ssh_dir/authorized_keys" || error_exit "Failed to set authorized_keys permissions"
    
    # Change ownership
    chown -R "$username:$username" "$ssh_dir" || error_exit "Failed to change .ssh directory ownership"
    
    log_success "SSH key setup completed for user: $username"
}

# Configure SSH security
configure_ssh_security() {
    local ssh_port="${1:-22222}"
    
    log_info "Configuring SSH security settings..."
    
    # Backup original sshd_config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup || error_exit "Failed to backup sshd_config"
    
    # Create new sshd_config with security settings
    cat > /etc/ssh/sshd_config << EOF
# SSH Security Configuration
Port $ssh_port
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
    log_warning "SSH is now running on port $ssh_port. Make sure to update your firewall rules!"
}

# Install Docker
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
    
    # Add ubuntu user to docker group
    usermod -aG docker ubuntu || error_exit "Failed to add ubuntu user to docker group"
    
    log_success "Docker installed successfully"
}

# Install Docker Compose
install_docker_compose() {
    log_info "Installing Docker Compose..."
    
    # Docker Compose is now included with Docker, but we'll also install the standalone version
    local compose_version="v2.23.0"
    
    # Download Docker Compose
    curl -L "https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose || error_exit "Failed to download Docker Compose"
    
    # Make it executable
    chmod +x /usr/local/bin/docker-compose || error_exit "Failed to make Docker Compose executable"
    
    # Create symlink for easier access
    ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose || true
    
    # Verify installation
    docker-compose --version || error_exit "Docker Compose installation verification failed"
    
    log_success "Docker Compose installed successfully"
}

# Configure firewall
configure_firewall() {
    local ssh_port="${1:-22222}"
    
    log_info "Configuring UFW firewall..."
    
    # Install UFW if not present
    apt-get install -y ufw || error_exit "Failed to install UFW"
    
    # Reset UFW to defaults
    ufw --force reset || error_exit "Failed to reset UFW"
    
    # Set default policies
    ufw default deny incoming || error_exit "Failed to set UFW default deny incoming"
    ufw default allow outgoing || error_exit "Failed to set UFW default allow outgoing"
    
    # Allow SSH on custom port
    ufw allow "$ssh_port/tcp" || error_exit "Failed to allow SSH port in UFW"
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp || error_exit "Failed to allow HTTP in UFW"
    ufw allow 443/tcp || error_exit "Failed to allow HTTPS in UFW"
    
    # Enable UFW
    ufw --force enable || error_exit "Failed to enable UFW"
    
    log_success "Firewall configured successfully"
    log_warning "SSH port $ssh_port is open. Make sure to test SSH connection before closing this session!"
}

# Configure BBR TCP congestion control
configure_bbr() {
    local enable_bbr="$1"
    
    if [[ "$enable_bbr" != "true" ]]; then
        log_info "BBR configuration skipped"
        return 0
    fi
    
    log_info "Configuring BBR TCP congestion control..."
    
    # Check if BBR module is available
    if ! modinfo tcp_bbr &>/dev/null; then
        log_error "BBR module (tcp_bbr) is not available in this kernel"
        log_warning "BBR requires Linux kernel 4.9+ with BBR support"
        return 1
    fi
    
    # Load BBR module
    modprobe tcp_bbr || error_exit "Failed to load BBR module"
    
    # Ensure BBR module loads at boot
    echo "tcp_bbr" | tee --append /etc/modules-load.d/modules.conf || error_exit "Failed to add BBR to modules.conf"
    
    # Configure sysctl parameters for BBR
    local sysctl_params=(
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
    )
    
    for param in "${sysctl_params[@]}"; do
        echo "$param" | tee --append /etc/sysctl.conf || error_exit "Failed to add $param to sysctl.conf"
    done
    
    # Apply sysctl changes
    sysctl -p || error_exit "Failed to apply sysctl changes"
    
    # Verify BBR is active
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control)
    if [[ "$current_cc" == "bbr" ]]; then
        log_success "BBR TCP congestion control configured successfully"
        log_info "Current congestion control: $current_cc"
    else
        log_warning "BBR may not be fully active. Current congestion control: $current_cc"
    fi
}

# Interactive input functions
get_hostname() {
    local hostname=""
    while [[ -z "$hostname" ]]; do
        read -p "Enter hostname for this server: " hostname
        if [[ -z "$hostname" ]]; then
            log_error "Hostname cannot be empty. Please try again."
        elif ! [[ "$hostname" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$ ]]; then
            log_error "Invalid hostname format. Use only alphanumeric characters and hyphens."
            hostname=""
        fi
    done
    echo "$hostname"
}

get_username() {
    local username=""
    while [[ -z "$username" ]]; do
        read -p "Enter username to create (default: ubuntu): " username
        if [[ -z "$username" ]]; then
            username="ubuntu"
        elif ! [[ "$username" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
            log_error "Invalid username format. Use only letters, numbers, underscores, and hyphens."
            username=""
        elif id "$username" &>/dev/null; then
            log_warning "User $username already exists."
            read -p "Continue with existing user? (y/N): " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                username=""
            fi
        fi
    done
    echo "$username"
}

get_password() {
    local password=""
    local password_confirm=""
    
    read -p "Set password for user? (y/N): " set_password
    if [[ "$set_password" =~ ^[Yy]$ ]]; then
        while [[ -z "$password" || "$password" != "$password_confirm" ]]; do
            read -s -p "Enter password: " password
            echo ""
            read -s -p "Confirm password: " password_confirm
            echo ""
            
            if [[ -z "$password" ]]; then
                log_error "Password cannot be empty."
            elif [[ ${#password} -lt 8 ]]; then
                log_error "Password must be at least 8 characters long."
                password=""
            elif [[ "$password" != "$password_confirm" ]]; then
                log_error "Passwords do not match. Please try again."
                password=""
            fi
        done
    fi
    echo "$password"
}

get_ssh_key() {
    local ssh_key=""
    read -p "Enter SSH public key for user (or press Enter to skip): " ssh_key
    
    if [[ -n "$ssh_key" ]]; then
        # Basic validation of SSH key format
        if [[ ! "$ssh_key" =~ ^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ]]; then
            log_error "Invalid SSH key format. Expected: ssh-rsa, ssh-ed25519, or ecdsa-sha2-*"
            read -p "Continue anyway? (y/N): " confirm
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
        read -p "Enter SSH port (default: 22222): " ssh_port
        if [[ -z "$ssh_port" ]]; then
            ssh_port="22222"
        elif ! [[ "$ssh_port" =~ ^[0-9]+$ ]] || [[ "$ssh_port" -lt 1 ]] || [[ "$ssh_port" -gt 65535 ]]; then
            log_error "Invalid port number. Please enter a number between 1 and 65535."
            ssh_port=""
        elif [[ "$ssh_port" -lt 1024 ]] && [[ "$ssh_port" != "22" ]]; then
            log_warning "Port $ssh_port is a privileged port (< 1024)."
            read -p "Continue? (y/N): " confirm
            if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
                ssh_port=""
            fi
        fi
    done
    echo "$ssh_port"
}

get_bbr_option() {
    local enable_bbr=""
    
    echo ""
    echo "BBR (Bottleneck Bandwidth and RTT) is a TCP congestion control algorithm"
    echo "that can significantly improve network performance, especially in high-latency"
    echo "or high-loss network environments."
    echo ""
    echo "Benefits of BBR:"
    echo "  • Higher throughput and lower latency"
    echo "  • Better performance over lossy networks"
    echo "  • Improved fairness and stability"
    echo ""
    
    read -p "Enable BBR TCP congestion control? (y/N): " enable_bbr
    
    if [[ "$enable_bbr" =~ ^[Yy]$ ]]; then
        # Check if BBR is available
        if modinfo tcp_bbr &>/dev/null; then
            echo "true"
        else
            log_warning "BBR module not available in current kernel"
            log_warning "BBR requires Linux kernel 4.9+ with BBR support"
            read -p "Continue anyway? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                echo "true"
            else
                echo "false"
            fi
        fi
    else
        echo "false"
    fi
}

# Configuration preview
show_config_preview() {
    local hostname="$1"
    local username="$2"
    local ssh_port="$3"
    local has_password="$4"
    local has_ssh_key="$5"
    local enable_bbr="$6"
    
    echo ""
    echo "=========================================="
    echo "    Configuration Preview"
    echo "=========================================="
    echo "Hostname: $hostname"
    echo "Username: $username"
    echo "SSH Port: $ssh_port"
    echo "Password: $([ "$has_password" = "true" ] && echo "Yes" || echo "No")"
    echo "SSH Key: $([ "$has_ssh_key" = "true" ] && echo "Yes" || echo "No")"
    echo "BBR TCP: $([ "$enable_bbr" = "true" ] && echo "Yes" || echo "No")"
    echo "=========================================="
    echo ""
}

# Confirmation prompt
confirm_configuration() {
    local hostname="$1"
    local ssh_port="$2"
    
    echo "⚠️  IMPORTANT WARNINGS:"
    echo "   • SSH will be configured on port $ssh_port"
    echo "   • Root login will be disabled"
    echo "   • Password authentication will be disabled"
    echo "   • Make sure you can access the server via SSH key before proceeding!"
    echo ""
    
    read -p "Do you want to continue with this configuration? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Configuration cancelled by user."
        exit 0
    fi
}

# Main function
main() {
    echo "=========================================="
    echo "    Ubuntu Server Setup Script"
    echo "=========================================="
    echo ""
    
    # Check prerequisites
    check_root
    check_ubuntu
    
    # Parse command line arguments first
    local hostname=""
    local username=""
    local password=""
    local ssh_key=""
    local ssh_port=""
    local enable_bbr="false"
    local interactive_mode=true
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --hostname)
                hostname="$2"
                interactive_mode=false
                shift 2
                ;;
            --username)
                username="$2"
                interactive_mode=false
                shift 2
                ;;
            --password)
                password="$2"
                interactive_mode=false
                shift 2
                ;;
            --ssh-key)
                ssh_key="$2"
                interactive_mode=false
                shift 2
                ;;
            --ssh-port)
                ssh_port="$2"
                interactive_mode=false
                shift 2
                ;;
            --enable-bbr)
                enable_bbr="true"
                interactive_mode=false
                shift
                ;;
            --non-interactive)
                interactive_mode=false
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
    
    # Interactive mode - collect missing parameters
    if [[ "$interactive_mode" = true ]]; then
        log_info "Running in interactive mode..."
        echo ""
        
        # Get hostname
        if [[ -z "$hostname" ]]; then
            hostname=$(get_hostname)
        fi
        
        # Get username
        if [[ -z "$username" ]]; then
            username=$(get_username)
        fi
        
        # Get password
        if [[ -z "$password" ]]; then
            password=$(get_password)
        fi
        
        # Get SSH key
        if [[ -z "$ssh_key" ]]; then
            ssh_key=$(get_ssh_key)
        fi
        
        # Get SSH port
        if [[ -z "$ssh_port" ]]; then
            ssh_port=$(get_ssh_port)
        fi
        
        # Get BBR option
        if [[ "$enable_bbr" = "false" ]]; then
            enable_bbr=$(get_bbr_option)
        fi
        
        # Show configuration preview
        show_config_preview "$hostname" "$username" "$ssh_port" \
            "$([ -n "$password" ] && echo "true" || echo "false")" \
            "$([ -n "$ssh_key" ] && echo "true" || echo "false")" \
            "$enable_bbr"
        
        # Confirm configuration
        confirm_configuration "$hostname" "$ssh_port"
    else
        # Non-interactive mode - validate required parameters
        if [[ -z "$hostname" ]]; then
            error_exit "Hostname is required in non-interactive mode"
        fi
        
        if [[ -z "$username" ]]; then
            username="ubuntu"
        fi
        
        if [[ -z "$ssh_port" ]]; then
            ssh_port="22222"
        fi
        
        log_info "Running in non-interactive mode..."
        log_info "Hostname: $hostname"
        log_info "Username: $username"
        log_info "SSH Port: $ssh_port"
    fi
    
    # Start setup process
    log_info "Starting Ubuntu server setup..."
    
    # Update system
    update_system
    
    # Set hostname
    set_hostname "$hostname"
    
    # Create user
    create_ubuntu_user "$username" "$password"
    
    # Setup SSH key
    setup_ssh_key "$username" "$ssh_key"
    
    # Configure SSH security
    configure_ssh_security "$ssh_port"
    
    # Install Docker
    install_docker
    
    # Install Docker Compose
    install_docker_compose
    
    # Configure firewall
    configure_firewall "$ssh_port"
    
    # Configure BBR
    configure_bbr "$enable_bbr"
    
    # Final message
    echo ""
    echo "=========================================="
    echo "    Setup Completed Successfully!"
    echo "=========================================="
    echo ""
    log_success "Server hostname: $hostname"
    log_success "SSH port: $ssh_port"
    log_success "User created: $username"
    log_success "Docker installed: $(docker --version)"
    log_success "Docker Compose installed: $(docker-compose --version)"
    if [[ "$enable_bbr" = "true" ]]; then
        log_success "BBR TCP congestion control: Enabled"
    fi
    echo ""
    log_warning "IMPORTANT: Test SSH connection on port $ssh_port before closing this session!"
    log_warning "SSH command: ssh -p $ssh_port $username@$(hostname -I | awk '{print $1}')"
    echo ""
}

# Help function
show_help() {
    cat << EOF
Ubuntu Server Setup Script

Usage: sudo $0 [OPTIONS]

Interactive Mode (default):
    sudo $0                 # Run with interactive prompts for all settings

Non-Interactive Mode:
    sudo $0 --hostname HOSTNAME [OPTIONS]

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
    sudo $0
    
    # Non-interactive with all parameters
    sudo $0 --hostname myserver --ssh-key "ssh-rsa AAAAB3NzaC1yc2E..." --enable-bbr
    
    # Non-interactive with minimal parameters
    sudo $0 --hostname myserver --non-interactive
    
    # Mixed mode (some parameters provided, others prompted)
    sudo $0 --hostname myserver --ssh-port 2222 --enable-bbr

Interactive Features:
    • Input validation with error messages
    • Configuration preview before applying
    • Safety confirmations for destructive changes
    • Password strength validation
    • SSH key format validation
    • Port number validation

EOF
}

# Run main function
main "$@"
