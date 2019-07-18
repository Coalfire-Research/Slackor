#!/bin/bash
apt install golang xterm git python3-pip upx-ucl -y
desired_install_location="$GOPATH/src/github.com/Coalfire-Research/Slackor"
if [ $desired_install_location != `pwd` ]; then
    >&2 echo "Slackor should be checked out within: $desired_install_location"
    >&2 echo "Obtain with: go get github.com/Coalfire-Research/Slackor"
fi
go get github.com/atotto/clipboard
go get github.com/bmatcuk/doublestar
go get github.com/dustin/go-humanize
go get github.com/kbinani/screenshot
go get github.com/lxn/win
go get github.com/mattn/go-shellwords
go get github.com/miekg/dns
go get golang.org/x/sys/windows
pip3 install -r requirements.txt
pushd impacket && python setup.py install && popd
