#!/bin/sh

mkdir /monroe/
mkdir /monroe/results
/usr/bin/multispider -p ECNSpider1 -I /opt/monroe/input_test.csv -o /tmp/ECNASpider1.txt
mv /tmp/* /monroe/results/
