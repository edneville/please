#!/bin/sh

set -e

echo "secure path test"
cat <<'EOT' | su -s /bin/bash ed
export PLEASE=`which please`;
export PATH=/root:/usr/bin:/bin
$PLEASE .bashrc | grep 'command not found'
EOT

