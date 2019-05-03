sudo apt update
sudo apt upgrade -y
sudo apt install git python3 python3-dev python3-pip libpython3-dev gcc g++ build-essential cmake xdot -y
sudo -H python3 -m pip install -U pip
sudo -H python3 -m pip install pycparser z3-solver==4.5.1.0.post2 pyparsing future llvmlite==0.26.0 pyelftools pefile r2pipe PyQt5
git clone https://github.com/bdcht/grandalf.git
cd grandalf
sudo python3 setup.py install
cd ..
sudo rm -rf grandalf
git clone https://github.com/radare/radare2
cd radare2
sudo ./sys/install.sh
cd ..
cd miasm
sudo python3 setup.py install
