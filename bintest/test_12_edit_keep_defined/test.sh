#!/bin/sh

set -e

echo "test edit keep /etc/profile"
cat <<EOT | su -s /bin/bash ed 
export EDITOR="/usr/bin/tee -a"
echo "###" | pleaseedit /etc/profile
ls -al /etc/profile | grep -E '^-rw-r--r--.* 1 root root.*/etc/profile$'
EOT

