#!/bin/sh

set -e

echo "test bash inherit 1"
cat <<EOT | su ed -s /bin/bash
echo "" | please -n /bin/bash || exit 0
exit 1
EOT

