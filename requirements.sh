#!/bin/bash

# Update system
sudo apt-get update

# Install Python3 and pip (if not already installed)
sudo apt-get install python3 python3-pip -y

# Install dig
sudo apt-get install dnsutils -y

# Install Python requests library
pip3 install requests

# Verify installation
echo "=== Verification ==="
python3 --version
dig -v
python3 -c "import requests; print('requests version:', requests.__version__)"
echo "=== Installation Complete! ==="
