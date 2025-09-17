#!/bin/bash

# Demo script to showcase the interactive Ubuntu setup features
# This script demonstrates the interactive capabilities without making actual changes

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Demo banner
show_demo_banner() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    🎬 Ubuntu Server Setup - Interactive Demo 🎬             ║
║                                                              ║
║    This demo showcases the interactive features without      ║
║    making any actual changes to your system.                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo ""
}

# Demo functions
demo_input_validation() {
    echo -e "${CYAN}🔍 Input Validation Demo${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    echo -e "${YELLOW}Hostname Validation:${NC}"
    echo "✅ Valid: web-server, db-server, production-01"
    echo "❌ Invalid: web_server (underscores), 123server (starts with number)"
    echo ""
    
    echo -e "${YELLOW}Username Validation:${NC}"
    echo "✅ Valid: admin, deploy, user123"
    echo "❌ Invalid: 123user (starts with number), user@domain (special chars)"
    echo ""
    
    echo -e "${YELLOW}Password Strength:${NC}"
    echo "✅ Strong: MySecure123! (8+ chars, upper, lower, number)"
    echo "❌ Weak: password (no numbers), 12345678 (no letters)"
    echo ""
    
    echo -e "${YELLOW}SSH Key Format:${NC}"
    echo "✅ Valid: ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256"
    echo "❌ Invalid: ssh-dss (deprecated), invalid-key-format"
    echo ""
    
    echo -e "${YELLOW}Port Validation:${NC}"
    echo "✅ Valid: 22222, 2222, 8080 (1-65535)"
    echo "❌ Invalid: 0 (too low), 70000 (too high), abc (not a number)"
    echo ""
}

demo_interactive_features() {
    echo -e "${CYAN}🎯 Interactive Features Demo${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    echo -e "${GREEN}1. Configuration Preview${NC}"
    echo "   Before making changes, you'll see a summary:"
    echo "   ┌─────────────────────────────────────────┐"
    echo "   │ Configuration Summary                   │"
    echo "   ├─────────────────────────────────────────┤"
    echo "   │ Hostname: web-server                    │"
    echo "   │ Username: admin                         │"
    echo "   │ SSH Port: 22222                         │"
    echo "   │ Password: Yes                           │"
    echo "   │ SSH Key: Yes                            │"
    echo "   └─────────────────────────────────────────┘"
    echo ""
    
    echo -e "${GREEN}2. Safety Confirmations${NC}"
    echo "   Multiple confirmation prompts for safety:"
    echo "   ⚠️  IMPORTANT WARNINGS:"
    echo "   • SSH will be configured on port 22222"
    echo "   • Root login will be disabled"
    echo "   • Password authentication will be disabled"
    echo "   • Make sure you can access the server via SSH key!"
    echo ""
    echo "   Do you want to continue? (y/N): "
    echo ""
    
    echo -e "${GREEN}3. Progress Indicators${NC}"
    echo "   Clear progress tracking during setup:"
    echo "   [INFO] Updating system packages..."
    echo "   [SUCCESS] System packages updated successfully"
    echo "   [INFO] Setting hostname to: web-server"
    echo "   [SUCCESS] Hostname set to: web-server"
    echo ""
    
    echo -e "${GREEN}4. Error Handling${NC}"
    echo "   Helpful error messages with suggestions:"
    echo "   [ERROR] Invalid hostname format"
    echo "   Use only alphanumeric characters and hyphens"
    echo "   [ERROR] Port 22 is already in use"
    echo "   Please choose a different port"
    echo ""
}

demo_usage_examples() {
    echo -e "${CYAN}📚 Usage Examples${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    echo -e "${GREEN}Interactive Mode (Recommended):${NC}"
    echo "sudo ./interactive-setup.sh"
    echo ""
    
    echo -e "${GREEN}Basic Interactive:${NC}"
    echo "sudo ./ubuntu-setup.sh"
    echo ""
    
    echo -e "${GREEN}Non-Interactive Mode:${NC}"
    echo "sudo ./ubuntu-setup.sh --hostname myserver --ssh-key 'ssh-rsa...'"
    echo ""
    
    echo -e "${GREEN}Mixed Mode:${NC}"
    echo "sudo ./ubuntu-setup.sh --hostname myserver --ssh-port 2222"
    echo "  (Other settings will be prompted interactively)"
    echo ""
}

demo_security_features() {
    echo -e "${CYAN}🔒 Security Features Demo${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    echo -e "${GREEN}SSH Security Hardening:${NC}"
    echo "  • Custom SSH port (default: 22222)"
    echo "  • Root login disabled"
    echo "  • Password authentication disabled"
    echo "  • Strong cipher suites"
    echo "  • Connection limits and timeouts"
    echo ""
    
    echo -e "${GREEN}Firewall Configuration:${NC}"
    echo "  • UFW enabled with default deny"
    echo "  • Only SSH, HTTP, HTTPS allowed"
    echo "  • Custom SSH port opened"
    echo ""
    
    echo -e "${GREEN}User Management:${NC}"
    echo "  • New user with sudo privileges"
    echo "  • Added to docker group"
    echo "  • SSH key authentication setup"
    echo ""
}

demo_installation_process() {
    echo -e "${CYAN}⚙️  Installation Process Demo${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    echo -e "${GREEN}Step 1: System Updates${NC}"
    echo "  apt-get update && apt-get upgrade"
    echo ""
    
    echo -e "${GREEN}Step 2: Hostname Configuration${NC}"
    echo "  hostnamectl set-hostname <hostname>"
    echo "  Update /etc/hosts"
    echo ""
    
    echo -e "${GREEN}Step 3: User Management${NC}"
    echo "  useradd -m -s /bin/bash <username>"
    echo "  usermod -aG sudo <username>"
    echo ""
    
    echo -e "${GREEN}Step 4: SSH Configuration${NC}"
    echo "  Configure /etc/ssh/sshd_config"
    echo "  Set up SSH keys"
    echo "  Restart SSH service"
    echo ""
    
    echo -e "${GREEN}Step 5: Docker Installation${NC}"
    echo "  Install Docker CE from official repository"
    echo "  Install Docker Compose"
    echo "  Add user to docker group"
    echo ""
    
    echo -e "${GREEN}Step 6: Firewall Setup${NC}"
    echo "  Configure UFW rules"
    echo "  Enable firewall"
    echo ""
}

show_next_steps() {
    echo -e "${CYAN}🚀 Next Steps${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    
    echo "To use the interactive setup:"
    echo "1. Make scripts executable: chmod +x *.sh"
    echo "2. Run interactive wizard: sudo ./interactive-setup.sh"
    echo "3. Follow the guided prompts"
    echo "4. Test your configuration: ./test-installation.sh"
    echo ""
    
    echo -e "${YELLOW}Available Scripts:${NC}"
    echo "  • interactive-setup.sh  - User-friendly wizard (recommended)"
    echo "  • ubuntu-setup.sh       - Main setup script"
    echo "  • test-installation.sh  - Verify installation"
    echo "  • example-config.sh     - Example configuration"
    echo ""
}

# Main demo function
main() {
    clear
    show_demo_banner
    
    echo -e "${BLUE}This demo showcases the interactive features of the Ubuntu setup scripts.${NC}"
    echo -e "${BLUE}No actual changes will be made to your system.${NC}"
    echo ""
    
    read -p "Press Enter to start the demo..."
    
    demo_input_validation
    read -p "Press Enter to continue..."
    
    demo_interactive_features
    read -p "Press Enter to continue..."
    
    demo_security_features
    read -p "Press Enter to continue..."
    
    demo_installation_process
    read -p "Press Enter to continue..."
    
    demo_usage_examples
    read -p "Press Enter to continue..."
    
    show_next_steps
    
    echo ""
    echo -e "${GREEN}Demo completed! Ready to set up your Ubuntu server?${NC}"
    echo ""
    read -p "Would you like to run the interactive setup now? (y/N): " run_setup
    
    if [[ "$run_setup" =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "${CYAN}Starting interactive setup...${NC}"
        echo "Note: This will make actual changes to your system!"
        echo ""
        read -p "Continue with real setup? (y/N): " confirm_real
        
        if [[ "$confirm_real" =~ ^[Yy]$ ]]; then
            sudo ./interactive-setup.sh
        else
            echo "Setup cancelled."
        fi
    else
        echo "Demo finished. Run './interactive-setup.sh' when ready to configure your server."
    fi
}

# Run demo
main "$@"
