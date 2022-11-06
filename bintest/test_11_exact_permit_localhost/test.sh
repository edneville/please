#!/bin/sh

set -e

echo "test exact permits hostname"
cat <<EOT | su -s /bin/bash ed
set -e
echo id | please /bin/bash
EOT

