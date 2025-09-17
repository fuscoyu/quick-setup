#!/bin/bash

# Test script to verify Ubuntu setup installation
# Run this script after ubuntu-setup.sh to verify everything is working correctly

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

# Test functions
test_hostname() {
    log_info "Testing hostname configuration..."
    local hostname=$(hostname)
    if [[ -n "$hostname" ]]; then
        log_success "Hostname is set to: $hostname"
    else
        log_error "Hostname is not properly configured"
        return 1
    fi
}

test_user() {
    log_info "Testing user configuration..."
    local username="$1"
    
    if id "$username" &>/dev/null; then
        log_success "User $username exists"
        
        # Check if user is in sudo group
        if groups "$username" | grep -q sudo; then
            log_success "User $username has sudo privileges"
        else
            log_error "User $username does not have sudo privileges"
            return 1
        fi
        
        # Check if user is in docker group
        if groups "$username" | grep -q docker; then
            log_success "User $username is in docker group"
        else
            log_warning "User $username is not in docker group"
        fi
    else
        log_error "User $username does not exist"
        return 1
    fi
}

test_ssh_config() {
    log_info "Testing SSH configuration..."
    
    # Check SSH service status
    if systemctl is-active --quiet ssh; then
        log_success "SSH service is running"
    else
        log_error "SSH service is not running"
        return 1
    fi
    
    # Check SSH configuration
    if sshd -t; then
        log_success "SSH configuration is valid"
    else
        log_error "SSH configuration has errors"
        return 1
    fi
    
    # Check if root login is disabled
    if grep -q "PermitRootLogin no" /etc/ssh/sshd_config; then
        log_success "Root login is disabled"
    else
        log_error "Root login is not disabled"
        return 1
    fi
    
    # Check if password authentication is disabled
    if grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
        log_success "Password authentication is disabled"
    else
        log_error "Password authentication is not disabled"
        return 1
    fi
    
    # Check SSH port
    local ssh_port=$(grep "^Port " /etc/ssh/sshd_config | awk '{print $2}')
    if [[ -n "$ssh_port" ]]; then
        log_success "SSH is configured to use port: $ssh_port"
    else
        log_warning "Could not determine SSH port from configuration"
    fi
}

test_docker() {
    log_info "Testing Docker installation..."
    
    # Check if Docker is installed
    if command -v docker &> /dev/null; then
        log_success "Docker is installed: $(docker --version)"
    else
        log_error "Docker is not installed"
        return 1
    fi
    
    # Check if Docker service is running
    if systemctl is-active --quiet docker; then
        log_success "Docker service is running"
    else
        log_error "Docker service is not running"
        return 1
    fi
    
    # Test Docker functionality
    if sudo docker run --rm hello-world &> /dev/null; then
        log_success "Docker is working correctly"
    else
        log_error "Docker test failed"
        return 1
    fi
}

test_docker_compose() {
    log_info "Testing Docker Compose installation..."
    
    # Check if Docker Compose is installed
    if command -v docker-compose &> /dev/null; then
        log_success "Docker Compose is installed: $(docker-compose --version)"
    else
        log_error "Docker Compose is not installed"
        return 1
    fi
}

test_firewall() {
    log_info "Testing firewall configuration..."
    
    # Check if UFW is installed
    if command -v ufw &> /dev/null; then
        log_success "UFW is installed"
    else
        log_error "UFW is not installed"
        return 1
    fi
    
    # Check UFW status
    local ufw_status=$(ufw status | head -1)
    if [[ "$ufw_status" == *"active"* ]]; then
        log_success "UFW firewall is active"
    else
        log_warning "UFW firewall is not active"
    fi
    
    # Show UFW rules
    log_info "UFW rules:"
    ufw status numbered
}

test_bbr() {
    log_info "Testing BBR TCP congestion control..."
    
    # Check if BBR module is loaded
    if lsmod | grep -q tcp_bbr; then
        log_success "BBR module is loaded"
    else
        log_warning "BBR module is not loaded"
    fi
    
    # Check current congestion control algorithm
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    if [[ "$current_cc" == "bbr" ]]; then
        log_success "BBR is active as TCP congestion control"
    else
        log_info "Current TCP congestion control: $current_cc"
    fi
    
    # Check if BBR is configured to load at boot
    if grep -q "tcp_bbr" /etc/modules-load.d/modules.conf 2>/dev/null; then
        log_success "BBR is configured to load at boot"
    else
        log_warning "BBR is not configured to load at boot"
    fi
    
    # Check sysctl configuration
    local bbr_sysctl=$(grep -c "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf 2>/dev/null || echo "0")
    if [[ "$bbr_sysctl" -gt 0 ]]; then
        log_success "BBR sysctl configuration found"
    else
        log_warning "BBR sysctl configuration not found"
    fi
}

test_ssh_key() {
    log_info "Testing SSH key configuration..."
    local username="$1"
    local ssh_dir="/home/$username/.ssh"
    local auth_keys="$ssh_dir/authorized_keys"
    
    if [[ -d "$ssh_dir" ]]; then
        log_success "SSH directory exists for user $username"
        
        if [[ -f "$auth_keys" ]]; then
            local key_count=$(wc -l < "$auth_keys")
            log_success "SSH authorized_keys file exists with $key_count key(s)"
        else
            log_warning "SSH authorized_keys file does not exist for user $username"
        fi
        
        # Check permissions
        local dir_perm=$(stat -c "%a" "$ssh_dir")
        if [[ "$dir_perm" == "700" ]]; then
            log_success "SSH directory has correct permissions (700)"
        else
            log_error "SSH directory has incorrect permissions: $dir_perm (should be 700)"
        fi
        
        if [[ -f "$auth_keys" ]]; then
            local file_perm=$(stat -c "%a" "$auth_keys")
            if [[ "$file_perm" == "600" ]]; then
                log_success "SSH authorized_keys has correct permissions (600)"
            else
                log_error "SSH authorized_keys has incorrect permissions: $file_perm (should be 600)"
            fi
        fi
    else
        log_warning "SSH directory does not exist for user $username"
    fi
}

# Main test function
main() {
    echo "=========================================="
    echo "    Ubuntu Setup Installation Test"
    echo "=========================================="
    
    local username="${1:-ubuntu}"
    local test_failed=0
    
    log_info "Testing installation for user: $username"
    echo ""
    
    # Run all tests
    test_hostname || test_failed=1
    echo ""
    
    test_user "$username" || test_failed=1
    echo ""
    
    test_ssh_config || test_failed=1
    echo ""
    
    test_ssh_key "$username" || test_failed=1
    echo ""
    
    test_docker || test_failed=1
    echo ""
    
    test_docker_compose || test_failed=1
    echo ""
    
    test_firewall || test_failed=1
    echo ""
    
    test_bbr || test_failed=1
    echo ""
    
    # Summary
    echo "=========================================="
    if [[ $test_failed -eq 0 ]]; then
        log_success "All tests passed! Installation is successful."
    else
        log_error "Some tests failed. Please check the output above."
    fi
    echo "=========================================="
    
    return $test_failed
}

# Help function
show_help() {
    cat << EOF
Ubuntu Setup Installation Test Script

Usage: $0 [USERNAME]

Arguments:
    USERNAME     Username to test (default: ubuntu)

Examples:
    $0                    # Test with default user 'ubuntu'
    $0 admin             # Test with user 'admin'

EOF
}

# Check if help is requested
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    show_help
    exit 0
fi

# Run main function
main "$@"
