#!/bin/sh

set -e

echo "test parameters (hello world)"
cat <<EOT | su -s /bin/bash ed
please /bin/echo "hello world"
EOT

echo "test parameters (hello)"
cat <<EOT | su -s /bin/bash ed
please /bin/echo "hello" | grep 'You may not'
EOT

