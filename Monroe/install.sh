#!/bin/bash

apt-get install automake libtool  libpcap-dev libjson0 libjson0-dev  lua-ldoc libnetfilter-queue-dev autotools-dev autoconf gcc g++ make liblua5.1-0-dev liblua50-dev liblualib50-dev

git https://github.com/tracebox/tracebox

cd tracebox

./bootstrap.sh

./configure

make

make install


