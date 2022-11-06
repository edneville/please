#!/bin/sh

set -e

echo "test internal space \\0"
cat <<'EOT' | su -s /bin/bash ed 
set -e

please /bin/echo "hello world"
EOT

