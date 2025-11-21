#!/bin/bash
# VM Setup Script - Run this on a fresh Ubuntu VM before exporting to OVA

set -e

echo "=========================================="
echo "Hogwarts CTF - VM Preparation Script"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Copy source files to temp location
echo "[1/5] Preparing source files..."
mkdir -p /tmp/hp_ctf_source
cp -r ./* /tmp/hp_ctf_source/

# Run installation
echo "[2/5] Running installation script..."
chmod +x /tmp/hp_ctf_source/deploy/install.sh
/tmp/hp_ctf_source/deploy/install.sh

# Configure firewall
echo "[3/5] Configuring firewall..."
apt-get install -y ufw
ufw --force enable
ufw allow 22/tcp
ufw allow 8080/tcp
echo "Firewall configured (SSH and port 8080 open)"

# Create welcome message
echo "[4/5] Creating welcome message..."
cat > /etc/motd << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║      HOGWARTS SCHOOL OF WITCHCRAFT AND WIZARDRY     ║
║                                                               ║
║                    CTF Challenge Platform                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

Welcome to the Hogwarts CTF Challenge!

🎯 Quick Start:
   - CTF Application: http://localhost:8080
   - Service Status:   sudo systemctl status hogwarts-ctf
   - View Logs:        sudo journalctl -u hogwarts-ctf -f
   - Documentation:    /opt/hogwarts_ctf/WALKTHROUGH.md

🔧 Management Commands:
   - Start CTF:   sudo systemctl start hogwarts-ctf
   - Stop CTF:    sudo systemctl stop hogwarts-ctf
   - Restart CTF: sudo systemctl restart hogwarts-ctf
   - Reset DB:    sudo rm /opt/hogwarts_ctf/hogwarts.db && sudo systemctl restart hogwarts-ctf

 Documentation:
   - Full Walkthrough: /opt/hogwarts_ctf/WALKTHROUGH.md
   - README:           /opt/hogwarts_ctf/README.md

🌐 Access from Host Machine:
   - Find VM IP: ip addr show
   - Access:     http://<VM-IP>:8080

Happy Hacking! 🧙‍♂️✨

EOF

# Start the service
echo "[5/5] Starting CTF service..."
systemctl start hogwarts-ctf
sleep 3
systemctl status hogwarts-ctf --no-pager

# Get IP
IP_ADDR=$(hostname -I | awk '{print $1}')

echo ""
echo "=========================================="
echo "VM Setup Complete!"
echo "=========================================="
echo ""
echo "🎉 The Hogwarts CTF is now running!"
echo ""
echo "Access it at:"
echo "  - http://localhost:8080 (from VM)"
echo "  - http://$IP_ADDR:8080 (from host/network)"
echo ""
echo "This VM is ready to be exported as an OVA!"
echo ""
echo "=========================================="

