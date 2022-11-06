#!/bin/sh

set -e

/bin/rm -rf /etc/please*

echo "test empty config"
cat <<EOT | su ed -s /bin/bash
echo "cat /etc/hosts" | please /bin/bash | grep "Could not open"
EOT


