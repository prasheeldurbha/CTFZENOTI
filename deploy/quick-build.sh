#!/bin/bash
# Quick OVA Build Script - For Automated VM Creation
# This script helps prepare a VM for OVA export

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         Hogwarts CTF - Quick OVA Build Script                ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

echo "📋 Build Checklist:"
echo "   [1] Verify all application files are present"
echo "   [2] Install and configure application"
echo "   [3] Clean and optimize VM"
echo "   [4] Prepare for export"
echo ""

read -p "Continue with build? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Build cancelled."
    exit 1
fi

# Step 1: Verify files
echo ""
echo "[1/4] Verifying application files..."
REQUIRED_FILES=("app.py" "requirements.txt" "WALKTHROUGH.md" "deploy/install.sh" "deploy/hogwarts-ctf.service")
ALL_PRESENT=true

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "   ❌ Missing: $file"
        ALL_PRESENT=false
    else
        echo "   ✓ Found: $file"
    fi
done

if [ "$ALL_PRESENT" = false ]; then
    echo ""
    echo "❌ Missing required files. Please ensure all files are present."
    exit 1
fi

# Step 2: Run installation
echo ""
echo "[2/4] Running installation..."
chmod +x deploy/setup-vm.sh
./deploy/setup-vm.sh

# Step 3: Clean and optimize
echo ""
echo "[3/4] Cleaning and optimizing VM..."

# Clean package cache
apt-get autoremove -y
apt-get clean
apt-get autoclean

# Remove old kernels (keep current)
dpkg -l 'linux-*' | sed '/^ii/!d;/'"$(uname -r | sed "s/\(.*\)-\([^0-9]\+\)/\1/")"'/d;s/^[^ ]* [^ ]* \([^ ]*\).*/\1/;/[0-9]/!d' | xargs sudo apt-get -y purge

# Clear logs
journalctl --vacuum-time=1d
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \;
find /var/log -type f -name "*.gz" -delete

# Clear bash history
history -c
cat /dev/null > ~/.bash_history

# Clear temporary files
rm -rf /tmp/*
rm -rf /var/tmp/*

# Clear SSH host keys (will be regenerated on first boot)
# Uncomment if you want fresh SSH keys on each import
# rm -f /etc/ssh/ssh_host_*

echo "   ✓ VM cleaned and optimized"

# Step 4: Prepare for export
echo ""
echo "[4/4] Preparing for export..."

# Create OVA information file
cat > /opt/hogwarts_ctf/OVA_INFO.txt << EOF
Hogwarts CTF Virtual Appliance
================================

Build Date: $(date)
OS: $(lsb_release -d | cut -f2)
Kernel: $(uname -r)

Application Path: /opt/hogwarts_ctf
Service Name: hogwarts-ctf
Web Port: 8080

Default Credentials:
  Username: ctfadmin
  Password: hogwarts123

First Steps:
1. Login with default credentials
2. Find VM IP: ip addr show
3. Access CTF: http://<VM-IP>:8080
4. Change default password: passwd

Documentation:
  - Walkthrough: /opt/hogwarts_ctf/WALKTHROUGH.md
  - README: /opt/hogwarts_ctf/README.md
  - OVA Guide: /opt/hogwarts_ctf/deploy/README_OVA.md

For support and updates, check the project repository.
EOF

# Display final instructions
IP_ADDR=$(hostname -I | awk '{print $1}')

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                  Build Complete!                              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "✅ VM is ready for OVA export!"
echo ""
echo "Final Checks:"
echo "   1. Test the application: http://$IP_ADDR:8080"
echo "   2. Verify service status: systemctl status hogwarts-ctf"
echo "   3. Check documentation is present"
echo ""
echo "🔄 Next Steps:"
echo "   1. Test all functionality one more time"
echo "   2. Run: sudo shutdown -h now"
echo "   3. In VirtualBox: File > Export Appliance"
echo "   4. Choose OVA format and export location"
echo "   5. Fill in metadata (name, version, description)"
echo "   6. Click Export and wait for completion"
echo ""
echo "📦 Recommended OVA filename:"
echo "   Hogwarts_CTF_v1.0_$(date +%Y%m%d).ova"
echo ""
echo "🔍 After export, test by:"
echo "   1. Importing OVA in a fresh VirtualBox instance"
echo "   2. Verifying application starts automatically"
echo "   3. Testing web access"
echo ""
echo "Ready to shutdown for export? (will shutdown in 10 seconds)"
echo "Press Ctrl+C to cancel..."

for i in {10..1}; do
    echo -ne "\rShutting down in $i seconds... "
    sleep 1
done

echo ""
echo "Shutting down VM for export..."
shutdown -h now

