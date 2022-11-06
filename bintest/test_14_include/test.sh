#!/bin/sh

set -e

echo "test include"
cat <<EOT | su ed -s /bin/bash
echo "cat /etc/hosts" | please /bin/bash | grep 'Error parsing already read file'
EOT

