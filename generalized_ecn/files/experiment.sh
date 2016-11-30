#!/bin/sh

mkdir /monroe/
mkdir /monroe/results
/usr/bin/multispider -p ECNSpiderA -I /opt/monroe/input_test.csv -o /tmp/ECNSpider.txt
mv /tmp/* /monroe/results/
