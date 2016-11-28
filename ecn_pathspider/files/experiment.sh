#!/bin/sh

/usr/bin/multispider -p DSCPSpider -I /opt/monroe/input.csv -o /tmp/output.txt
mkdir /monroe/
mkdir /monroe/results
mv /tmp/output.txt /monroe/results/

