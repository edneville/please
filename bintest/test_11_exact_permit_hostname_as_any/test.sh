#!/bin/sh

set -e

echo "test exact permits actual hostname"
cat <<EOT | su -s /bin/bash ed
set -e
echo id | please /bin/bash
EOT

