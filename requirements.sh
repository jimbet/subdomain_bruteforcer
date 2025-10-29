#!/bin/bash

# Update system
sudo apt-get update

# Install Python3 and pip (if not already installed)
sudo apt-get install python3 python3-pip -y

# Install dnsutil
sudo apt-get install dnsutils -y

# Install Python requests library
pip3 install --upgrade requests chardet urllib3 Mapping utils legacy-cgi charset-normalizer dnspython pysocks

# TOR for anonymity
sudo apt install tor
sudo systemctl start tor
sudo systemctl enable tor

### If using Windows, you have to install GIT and Microsoft C++ Distribution Tool 14.x
### Download TOR - https://www.torproject.org/download/tor/

# Verify installation
echo "=== Verification ==="
python3 --version
dig -v
python3 -c "import requests; print('requests version:', requests.__version__)"
echo "=== Installation Complete! ==="
