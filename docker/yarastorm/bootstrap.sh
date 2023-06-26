# Install all dependencies, and then install the package from /build/yarastorm.

apt-get update

# Extra dependencies
apt-get install -y -qq libmagic-dev

/build/yarastorm/install-yara.sh

python -m pip install --break-system-packages /build/yarastorm