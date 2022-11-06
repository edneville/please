#!/bin/sh

set -e

echo "test exact name (bob)"
cat <<EOT | su -s /bin/bash ed
set -e
echo id | please /bin/bash
please /usr/bin/id | grep "You may not"
EOT

