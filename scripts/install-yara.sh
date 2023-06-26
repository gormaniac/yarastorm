# Install yara-python as a system Python package on a Debian/Ubuntu system

apt-get install -y -qq \
  automake libssl-dev libtool gcc make pkg-config python3-dev

python -m pip install --break-system-packages yara-python