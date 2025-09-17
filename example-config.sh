#!/bin/bash

# Example configuration script for ubuntu-setup.sh
# Copy this file and modify the values according to your needs

# Server hostname
HOSTNAME="my-ubuntu-server"

# Username to create (default: ubuntu)
USERNAME="ubuntu"

# Password for the user (leave empty to skip password setup)
PASSWORD=""

# SSH public key (replace with your actual public key)
SSH_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajdhA..."

# SSH port (default: 22222)
SSH_PORT="22222"

# Enable BBR TCP congestion control (true/false)
ENABLE_BBR="true"

# Run the setup script with the configured parameters
echo "Running Ubuntu setup with the following configuration:"
echo "Hostname: $HOSTNAME"
echo "Username: $USERNAME"
echo "SSH Port: $SSH_PORT"
echo "SSH Key: ${SSH_KEY:0:50}..."
echo "BBR TCP: $ENABLE_BBR"
echo ""

# Build the command
CMD="sudo ./ubuntu-setup.sh --hostname $HOSTNAME --username $USERNAME --ssh-port $SSH_PORT"

if [[ -n "$PASSWORD" ]]; then
    CMD="$CMD --password $PASSWORD"
fi

if [[ -n "$SSH_KEY" ]]; then
    CMD="$CMD --ssh-key \"$SSH_KEY\""
fi

if [[ "$ENABLE_BBR" = "true" ]]; then
    CMD="$CMD --enable-bbr"
fi

# Execute the command
eval $CMD
