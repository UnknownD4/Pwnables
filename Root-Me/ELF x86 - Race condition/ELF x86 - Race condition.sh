#!/bin/sh

chmod 777 /tmp/tmp_file.txt
./ch12
cat /tmp/tmp_file.txt
rm /tmp/tmp_file.txt
