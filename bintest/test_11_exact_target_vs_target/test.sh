#!/bin/sh

set -e

echo "test exact dir"
cat <<EOT | su -s /bin/bash ed
set -e
echo pwd | please -d /root /bin/bash
echo pwd | please -d /var/tmp /bin/bash | grep "You may not"
EOT

