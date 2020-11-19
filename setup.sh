#!/bin/sh
sudo apt upgrade -y
sudo apt update -y

#peda
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit

#pwntools
apt-get install -y python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
apt-get install -y python python-pip python3-dev
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
python -m pip install --upgrade pip
python -m pip install --upgrade pwntools

#one_gadget
apt install -y ruby-full
gem install one_gadget

mkdir /work
cd /work
git clone http://github.com/woounnan/ctf

#ROPgadget
git clone https://github.com/JonathanSalwan/ROPgadget
cd ROPgadget
sudo pip install capstone
