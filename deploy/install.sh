#!/bin/bash
# Hogwarts CTF - Installation Script for Ubuntu/Debian

set -e

echo "=========================================="
echo "Hogwarts CTF - Automated Installation"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Update system
echo "[1/7] Updating system packages..."
apt-get update
apt-get upgrade -y

# Install Python and dependencies
echo "[2/7] Installing Python 3 and pip..."
apt-get install -y python3 python3-pip python3-venv git net-tools

# Create application user
echo "[3/7] Creating application user..."
if ! id "ctfuser" &>/dev/null; then
    useradd -r -m -d /opt/hogwarts_ctf -s /bin/bash ctfuser
    echo "User 'ctfuser' created"
else
    echo "User 'ctfuser' already exists"
fi

# Create application directory
echo "[4/7] Setting up application directory..."
mkdir -p /opt/hogwarts_ctf
cd /opt/hogwarts_ctf

# Copy application files
echo "[5/7] Copying application files..."
cp -r /tmp/hp_ctf_source/* /opt/hogwarts_ctf/

# Setup Python virtual environment
echo "[6/7] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Set permissions
echo "[7/7] Setting file permissions..."
chown -R ctfuser:ctfuser /opt/hogwarts_ctf
chmod +x /opt/hogwarts_ctf/app.py

# Install systemd service
echo "Installing systemd service..."
cp /opt/hogwarts_ctf/deploy/hogwarts-ctf.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable hogwarts-ctf.service

# Get IP address
IP_ADDR=$(hostname -I | awk '{print $1}')

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "To start the CTF application:"
echo "  sudo systemctl start hogwarts-ctf"
echo ""
echo "To check status:"
echo "  sudo systemctl status hogwarts-ctf"
echo ""
echo "The application will be available at:"
echo "  http://$IP_ADDR:8080"
echo "  http://localhost:8080"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u hogwarts-ctf -f"
echo ""
echo "Default test credentials are in WALKTHROUGH.md"
echo "=========================================="

