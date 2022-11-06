#!/bin/sh

set -e

echo "test env assign"
cat <<'EOT' | su -s /bin/bash ed 
set -e

please env | grep 'THING=abc'
EOT

