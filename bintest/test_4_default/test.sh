#!/bin/sh

set -e

cat <<EOT | su ed -s /bin/bash
export EDITOR="/usr/bin/tee -a"
echo "abc 192.168.1.1" | pleaseedit /etc/test | grep 192.168.1.1
ls -al /etc/test | grep 'root.*root'
grep abc /etc/test
EOT

