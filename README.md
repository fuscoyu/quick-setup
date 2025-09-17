# Ubuntu Server Setup - Unified Installer

A single, comprehensive script to configure Ubuntu servers with security hardening, Docker installation, and network optimization.

## 🚀 Quick Start

```bash
# Download and run (interactive mode - recommended)
curl -fsSL https://raw.githubusercontent.com/fuscoyu/quick-setup/main/installer.sh | sh

# Or download first, then run
wget https://raw.githubusercontent.com/fuscoyu/quick-setup/main/installer.sh
sh installer.sh
```

## 📋 Features

- ✅ **Hostname Configuration** - Set custom server hostname
- ✅ **User Management** - Create user with sudo privileges and passwordless sudo
- ✅ **SSH Security** - Hardened SSH with custom port, key-only auth
- ✅ **Docker Installation** - Docker CE and Docker Compose
- ✅ **Firewall Setup** - UFW configuration with minimal open ports
- ✅ **BBR TCP Control** - Network performance optimization (optional)
- ✅ **Input Validation** - Comprehensive validation and error handling
- ✅ **Sh Compatible** - Works with both bash and sh

## 🎯 Usage

### Interactive Mode (Recommended)
```bash
sh installer.sh
```
Guided setup with validation and confirmation prompts.

### Non-Interactive Mode
```bash
sh installer.sh --hostname myserver --ssh-key "ssh-rsa..." --enable-bbr
```

### Command Line Options
| Option | Description | Default |
|--------|-------------|---------|
| `--hostname HOSTNAME` | Set server hostname | Interactive prompt |
| `--username USERNAME` | Create user | `ubuntu` |
| `--password PASSWORD` | Set user password | No password |
| `--ssh-key SSH_KEY` | SSH public key | Interactive prompt |
| `--ssh-port PORT` | SSH port | `22222` |
| `--enable-bbr` | Enable BBR TCP control | `false` |
| `--non-interactive` | Force non-interactive | Interactive mode |
| `--help` | Show help | - |

## 📝 Examples

```bash
# Interactive setup
sh installer.sh

# Full automated setup
sh installer.sh \
  --hostname production-server \
  --username deploy \
  --ssh-key "ssh-rsa AAAAB3NzaC1yc2E..." \
  --ssh-port 2222 \
  --enable-bbr

# Minimal setup
sh installer.sh --hostname myserver --non-interactive
```

## 🔒 Security Features

### SSH Hardening
- Custom SSH port (default: 22222)
- Root login disabled
- Password authentication disabled
- Key-based authentication only
- Strong cipher suites
- Connection limits and timeouts

### Firewall Configuration
- UFW enabled with default deny
- Only SSH, HTTP, HTTPS allowed
- All outbound connections permitted

### BBR Network Optimization
- Modern TCP congestion control
- Higher throughput and lower latency
- Better performance over lossy networks
- Requires Linux kernel 4.9+

## ⚠️ Important Notes

### Before Running
1. **Backup Important Data** - Always backup before running system scripts
2. **Test SSH Key** - Ensure your SSH key is valid and working
3. **Alternative Access** - Make sure you have alternative server access

### After Running
1. **Test SSH Connection** - Verify SSH access on new port before closing session
2. **Update Firewall** - Configure additional ports if needed
3. **Docker Permissions** - Log out/in for Docker group permissions

## 🛠️ System Requirements

- Ubuntu 18.04 or later
- Root access (sudo)
- Internet connection
- Linux kernel 4.9+ (for BBR support)

## 📊 What Gets Configured

1. **System Updates** - Package list and system upgrades
2. **Hostname** - Server hostname and /etc/hosts
3. **User Account** - New user with sudo privileges
4. **SSH Configuration** - Security hardening and key setup
5. **Docker Installation** - Docker CE and Compose
6. **Firewall Setup** - UFW with minimal rules
7. **BBR Configuration** - TCP congestion control (optional)

## 🔧 Troubleshooting

### SSH Issues
```bash
# Test SSH configuration
sudo sshd -t

# Check SSH service
sudo systemctl status ssh

# View logs
sudo journalctl -u ssh
```

### Docker Issues
```bash
# Check Docker status
sudo systemctl status docker

# Test Docker
sudo docker run hello-world

# Check user groups
groups $USER
```

### BBR Issues
```bash
# Check BBR module
lsmod | grep tcp_bbr

# Check congestion control
sysctl net.ipv4.tcp_congestion_control

# Check BBR config
grep -r bbr /etc/sysctl.conf
```

## 📞 Support

If you encounter issues:
1. Check script output for error messages
2. Verify system requirements
3. Ensure proper permissions
4. Check system logs for details

## 📄 License

This script is provided as-is for educational and automation purposes. Use at your own risk.
