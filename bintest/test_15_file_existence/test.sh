#!/bin/sh

set -e

echo "Arbitrary File Existence Test"

cat <<'EOT' | su -s /bin/bash ed
set -e
# please thing | grep -F '[please]: command not found' || exit 1
please thing | grep 'command not found'
echo "" | please bash
EOT

