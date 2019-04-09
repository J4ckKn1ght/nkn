sudo apt update
sudo apt upgrade -y
sudo apt install git python3 python3-dev python3-pip python3-pyqt5 libpython3-dev python3-pyparsing gcc g++ build-essential pyqt5-dev-tools qttools5-dev-tools xdot -y
sudo -H python3 -m pip install -U pip
sudo -H python3 -m pip install pycparser z3-solver==4.5.1.0 pyparsing future llvmlite==0.26.0 elftools pefile
git clone https://github.com/bdcht/grandalf.git
cd grandalf
sudo python3 setup.py install
cd ..
sudo rm -rf grandalf
cd miasm
sudo python3 setup.py install
