#!/bin/sh

set -e

echo "test edit keep /etc/fstab_3"
cat <<EOT | su -s /bin/bash ed 
export EDITOR="/usr/bin/tee -a"
echo "###" | pleaseedit /etc/fstab_3
ls -al /etc/fstab_3 | grep -E '^-rw-r--r--.* root root.*/etc/fstab_3'
EOT

