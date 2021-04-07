#!/bin/bash
apt install golang xterm git python3-pip upx-ucl -y
GO111MODULE=on go get
GO111MODULE=on go test ./...
pip3 install -r requirements.txt
pushd impacket && python3 setup.py install && popd
