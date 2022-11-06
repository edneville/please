#!/bin/sh

set -e

echo "test command not found"
cat <<'EOT' | su -s /bin/bash ed 
set -e

please command_not_found | grep 'command not found'
EOT

