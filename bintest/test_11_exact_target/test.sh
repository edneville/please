#!/bin/sh

set -e

echo "test exact target"
cat <<EOT | su -s /bin/bash ed
set -e
echo id | please -t bob /bin/bash | grep bob
echo id | please -t root /bin/bash | grep "You may not"
EOT

