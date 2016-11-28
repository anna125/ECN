#!/bin/sh

/usr/bin/multispider -p ECNASpider1 -I /opt/monroe/input_test.csv -o /tmp/ECNASpider1.txt
mkdir /monroe/
mkdir /monroe/results
mv /tmp/output.txt /monroe/results/

