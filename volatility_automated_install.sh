# Volatility 2.7.1 Automated Installer Bash Script
# Hamza Haroon aka thegr1ffyn


#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Check if script is running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Please run the script as root.${NC}"
   exit 1
fi

# Update package lists
echo -e "\n\e[1mUpdating package lists...\e[0m"
sudo apt-get update

# Prompt user for confirmation
echo -e "\n\e[1mMake sure you have taken a valid snapshot and then proceed.\e[0m"
read -p "Enter 'y' to continue or any other key to cancel: " choice
if [[ $choice != "y" ]]; then
   echo -e "${RED}Script execution canceled.${NC}"
   exit 1
fi

# Installing dependencies
echo -e "\n\e[1mInstalling dependencies...\e[0m"
sudo apt-get install -y build-essential git libdistorm3-dev yara libraw1394–11 libcapstone-dev capstone-tool tzdata

# Installing pip for Python 2.7.x
echo -e "\n\e[1mInstalling pip for Python 2.7.x...\e[0m"
sudo apt-get install -y python2 python2.7-dev libpython2-dev
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
sudo python2 get-pip.py
sudo python2 -m pip install -U setuptools wheel

# Installing essential packages for volatility
echo -e "\n\e[1mInstalling essential packages for volatility...\e[0m"
sudo python2 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
sudo python2 -m pip install yara
sudo ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so

# Installing volatility and adding it to the path
echo -e "\n\e[1mInstalling volatility and adding it to the path...\e[0m"
sudo python2 -m pip install -U git+https://github.com/volatilityfoundation/volatility.git

# Add vol.py to the PATH
echo -e "\n\e[1mAdding vol.py to the PATH...\e[0m"
echo 'export PATH="/home/'"$username"'/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

echo -e "\n${GREEN}Enter vol.py -h to check if it has installed all the packages.${NC}"
echo -e "\n${GREEN}Script execution completed.${NC}"
