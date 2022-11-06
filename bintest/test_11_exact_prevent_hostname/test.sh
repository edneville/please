#!/bin/sh

set -e

echo "test exact prevents hostname"
cat <<EOT | su -s /bin/bash ed | grep "You may not"
set +e
echo id | please /bin/bash
EOT

