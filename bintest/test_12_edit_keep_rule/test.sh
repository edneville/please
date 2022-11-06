#!/bin/sh

set -e

echo "test edit keep /etc/fstab"
cat <<EOT | su -s /bin/bash ed 
export EDITOR="/usr/bin/tee -a"
echo "###" | pleaseedit /etc/fstab
ls -al /etc/fstab | grep -E '^-rw-r--r--.* 1 root root.* /etc/fstab$'
EOT

echo "test edit keep /etc/fstab_2"
cat <<EOT | su -s /bin/bash ed 
export EDITOR="/usr/bin/tee -a"
echo "###" | pleaseedit /etc/fstab_2
ls -al /etc/fstab_2 | grep -E '^-rw-------.* 1 root root.* /etc/fstab_2$'
EOT

