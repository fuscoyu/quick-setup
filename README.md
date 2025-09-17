# Ubuntu Server Setup Script

A comprehensive script to configure Ubuntu servers with security hardening and Docker installation.

## Features

- ✅ Set custom hostname
- ✅ Create Ubuntu user with sudo privileges
- ✅ Configure SSH key authentication
- ✅ SSH security hardening (disable root login, disable password auth, custom port)
- ✅ Install Docker and Docker Compose
- ✅ Configure UFW firewall
- ✅ Enable BBR TCP congestion control for better network performance
- ✅ Comprehensive error handling and logging

## Prerequisites

- Ubuntu 18.04 or later
- Root access (sudo)
- Internet connection

## Usage

### 🚀 Interactive Setup (Recommended)

The easiest way to configure your Ubuntu server is using the interactive setup wizard:

```bash
# Make scripts executable
chmod +x *.sh

# Run the interactive setup wizard
sudo ./interactive-setup.sh
```

The interactive wizard provides:
- ✅ User-friendly prompts with validation
- ✅ Configuration preview before applying changes
- ✅ Safety confirmations for destructive operations
- ✅ Input validation with helpful error messages
- ✅ ASCII art banner and colored output

### Basic Usage

```bash
# Make script executable
chmod +x ubuntu-setup.sh

# Run with interactive prompts (default mode)
sudo ./ubuntu-setup.sh
```

### Advanced Usage with Parameters

```bash
# Full configuration with all parameters
sudo ./ubuntu-setup.sh \
  --hostname myserver \
  --username admin \
  --password mypassword \
  --ssh-key "ssh-rsa AAAAB3NzaC1yc2E..." \
  --ssh-port 22222
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--hostname HOSTNAME` | Set the server hostname | Interactive prompt |
| `--username USERNAME` | Create user with specified name | `ubuntu` |
| `--password PASSWORD` | Set password for the user | No password |
| `--ssh-key SSH_KEY` | SSH public key for the user | Interactive prompt |
| `--ssh-port PORT` | SSH port | `22222` |
| `--enable-bbr` | Enable BBR TCP congestion control | `false` |
| `--non-interactive` | Force non-interactive mode | Interactive mode |
| `--help` | Show help message | - |

### Interactive Features

The interactive mode includes:

- **Input Validation**: Real-time validation of hostnames, usernames, passwords, SSH keys, and ports
- **Configuration Preview**: See all settings before applying changes
- **Safety Confirmations**: Multiple confirmation prompts for destructive operations
- **Password Strength**: Enforces strong password requirements
- **SSH Key Validation**: Validates SSH key format before acceptance
- **Port Availability**: Checks if ports are already in use
- **User-Friendly Interface**: Colored output, clear prompts, and helpful error messages

## Examples

### Example 1: Interactive Setup (Recommended)
```bash
# Run the interactive wizard with guided prompts
sudo ./interactive-setup.sh
```

### Example 2: Basic Setup
```bash
sudo ./ubuntu-setup.sh --hostname web-server
```

### Example 3: Full Configuration with BBR
```bash
sudo ./ubuntu-setup.sh \
  --hostname production-server \
  --username deploy \
  --ssh-key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..." \
  --ssh-port 2222 \
  --enable-bbr
```

### Example 4: With Password Authentication
```bash
sudo ./ubuntu-setup.sh \
  --hostname dev-server \
  --username developer \
  --password securepassword123 \
  --ssh-port 2222
```

### Example 5: Mixed Mode (Some parameters provided, others prompted)
```bash
sudo ./ubuntu-setup.sh --hostname myserver --ssh-port 2222
```

## What the Script Does

### 1. System Updates
- Updates package list
- Upgrades all installed packages

### 2. Hostname Configuration
- Sets the system hostname
- Updates `/etc/hosts` file

### 3. User Management
- Creates a new user with sudo privileges
- Optionally sets a password
- Adds user to docker group (after Docker installation)

### 4. SSH Configuration
- Sets up SSH key authentication
- Configures SSH security settings:
  - Disables root login
  - Disables password authentication
  - Changes SSH port to 22222 (or specified port)
  - Uses strong ciphers and MACs
  - Sets connection limits and timeouts

### 5. Docker Installation
- Removes old Docker versions
- Installs Docker CE from official repository
- Starts and enables Docker service
- Adds user to docker group

### 6. Docker Compose Installation
- Installs Docker Compose standalone version
- Creates symlinks for easy access

### 7. Firewall Configuration
- Installs and configures UFW
- Allows SSH on custom port
- Allows HTTP (80) and HTTPS (443)
- Denies all other incoming connections

### 8. BBR TCP Congestion Control (Optional)
- Enables BBR (Bottleneck Bandwidth and RTT) algorithm
- Improves network performance and reduces latency
- Requires Linux kernel 4.9+ with BBR support
- Configures automatic loading at boot

## Security Features

### SSH Hardening
- **Port Change**: SSH runs on port 22222 (configurable)
- **Root Login Disabled**: Prevents direct root access
- **Password Auth Disabled**: Only key-based authentication
- **Strong Ciphers**: Uses modern, secure cipher suites
- **Connection Limits**: Limits authentication attempts and sessions
- **Timeouts**: Automatic disconnection for idle sessions

### Firewall Configuration
- **Default Deny**: All incoming connections blocked by default
- **Minimal Open Ports**: Only SSH, HTTP, and HTTPS allowed
- **Outbound Allowed**: All outbound connections permitted

### BBR TCP Congestion Control
- **Modern Algorithm**: Uses Google's BBR algorithm for better performance
- **High Throughput**: Optimized for high-bandwidth, high-latency networks
- **Reduced Latency**: Minimizes bufferbloat and improves responsiveness
- **Better Fairness**: More stable and fair bandwidth sharing
- **Automatic Loading**: Configured to load at system boot

## Important Notes

### ⚠️ Before Running
1. **Backup Important Data**: Always backup important data before running system scripts
2. **Test SSH Key**: Ensure your SSH key is valid and working
3. **Current Session**: The script will change SSH settings - make sure you have alternative access

### ⚠️ After Running
1. **Test SSH Connection**: Verify you can connect via SSH on the new port
2. **Update Firewall Rules**: If you need additional ports, configure them in UFW
3. **Docker Permissions**: Log out and back in for Docker group permissions to take effect

### 🔧 Troubleshooting

#### SSH Connection Issues
```bash
# Test SSH configuration
sudo sshd -t

# Check SSH service status
sudo systemctl status ssh

# View SSH logs
sudo journalctl -u ssh
```

#### Docker Issues
```bash
# Check Docker status
sudo systemctl status docker

# Test Docker
sudo docker run hello-world

# Check user groups
groups $USER
```

#### Firewall Issues
```bash
# Check UFW status
sudo ufw status

# View UFW logs
sudo ufw show raw
```

## File Locations

- **Script**: `ubuntu-setup.sh`
- **SSH Config Backup**: `/etc/ssh/sshd_config.backup`
- **SSH Config**: `/etc/ssh/sshd_config`
- **User Home**: `/home/[username]`
- **Docker Socket**: `/var/run/docker.sock`

## Customization

### Adding More Users
After running the script, you can add more users:
```bash
sudo adduser newuser
sudo usermod -aG sudo newuser
sudo usermod -aG docker newuser
```

### Opening Additional Ports
```bash
sudo ufw allow 8080/tcp  # Example: Allow port 8080
sudo ufw reload
```

### Modifying SSH Settings
Edit `/etc/ssh/sshd_config` and restart SSH:
```bash
sudo nano /etc/ssh/sshd_config
sudo systemctl restart ssh
```

## Support

If you encounter issues:

1. Check the script output for error messages
2. Verify all prerequisites are met
3. Ensure you have proper permissions
4. Check system logs for detailed error information

## License

This script is provided as-is for educational and automation purposes. Use at your own risk.
