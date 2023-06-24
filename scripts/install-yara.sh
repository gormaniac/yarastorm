mkdir tmp
cd tmp
wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.zip
unzip v4.3.2.zip -d yarasrc
cd yarasrc
cd yara-master/
./bootstrap.sh
brew install automake libtool make gcc pkg-config
./bootstrap.sh
./configure --enable-magic --enable-dotnet
make
make install
make check