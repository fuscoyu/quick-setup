# Ubuntu Server Setup - Usage Examples

## 🚀 Quick Start

### Interactive Mode (Recommended for first-time setup)
```bash
# Download and run interactively
curl -fsSL https://raw.githubusercontent.com/your-repo/quick-setup/main/installer.sh | sh

# Or download first, then run
wget https://raw.githubusercontent.com/your-repo/quick-setup/main/installer.sh
sh installer.sh
```

### Non-Interactive Mode Examples

#### Basic Server Setup
```bash
sh installer.sh --hostname web-server --non-interactive
```

#### Production Server with SSH Key
```bash
sh installer.sh \
  --hostname production-server \
  --username deploy \
  --ssh-key "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..." \
  --ssh-port 2222 \
  --enable-bbr
```

#### Development Server with Password
```bash
sh installer.sh \
  --hostname dev-server \
  --username developer \
  --password "SecurePass123!" \
  --ssh-port 2222
```

#### Minimal Setup
```bash
sh installer.sh --hostname myserver --non-interactive
```

## 🔧 Advanced Usage

### Custom Configuration
```bash
sh installer.sh \
  --hostname my-ubuntu-server \
  --username admin \
  --password "MySecurePassword123" \
  --ssh-key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5..." \
  --ssh-port 22222 \
  --enable-bbr
```

### Server-Specific Configurations

#### Web Server
```bash
sh installer.sh \
  --hostname web-server \
  --username www \
  --ssh-key "ssh-rsa AAAAB3NzaC1yc2E..." \
  --enable-bbr
```

#### Database Server
```bash
sh installer.sh \
  --hostname db-server \
  --username dba \
  --ssh-key "ssh-rsa AAAAB3NzaC1yc2E..." \
  --ssh-port 2222
```

#### Application Server
```bash
sh installer.sh \
  --hostname app-server \
  --username deploy \
  --ssh-key "ssh-rsa AAAAB3NzaC1yc2E..." \
  --ssh-port 2222 \
  --enable-bbr
```

## 📋 Configuration Checklist

### Before Running
- [ ] Server has Ubuntu 18.04+
- [ ] Root access available
- [ ] Internet connection working
- [ ] SSH key ready (if using key auth)
- [ ] Backup important data

### After Running
- [ ] Test SSH connection on new port
- [ ] Verify Docker installation
- [ ] Check firewall rules
- [ ] Test BBR (if enabled)
- [ ] Update any additional firewall rules

## 🔍 Verification Commands

### Test SSH Connection
```bash
ssh -p 22222 username@server-ip
```

### Check Docker
```bash
docker --version
docker-compose --version
docker run hello-world
```

### Check BBR
```bash
sysctl net.ipv4.tcp_congestion_control
lsmod | grep tcp_bbr
```

### Check Firewall
```bash
sudo ufw status
```

## ⚠️ Important Notes

1. **Always test SSH connection before closing your current session**
2. **BBR requires Linux kernel 4.9+ with BBR support**
3. **Custom SSH ports need to be opened in cloud provider firewalls**
4. **Docker group permissions require logout/login to take effect**

## 🆘 Troubleshooting

### SSH Connection Issues
- Verify SSH key is correct
- Check if custom port is open in cloud firewall
- Ensure SSH service is running: `sudo systemctl status ssh`

### Docker Issues
- Check Docker service: `sudo systemctl status docker`
- Verify user is in docker group: `groups $USER`

### BBR Issues
- Check kernel version: `uname -r`
- Verify BBR module: `modinfo tcp_bbr`
- Check current congestion control: `sysctl net.ipv4.tcp_congestion_control`
