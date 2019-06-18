#!/bin/bash
apt install golang xterm git python3-pip upx-ucl -y
go get github.com/kbinani/screenshot
go get github.com/lxn/win
go get golang.org/x/sys/windows
go get github.com/atotto/clipboard
pip3 install -r requirements.txt
cd impacket
python setup.py install