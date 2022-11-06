#!/bin/sh

set -e

echo "test regex error line"
cat <<'EOT' | su -s /bin/bash ed 
set -e

please -l | grep 'Error parsing /etc/please.ini: ed_all:4'
EOT

