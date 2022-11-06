#!/bin/sh

set -e

echo "test parameters (hello \n world)"
cat <<EOT | su -s /bin/bash ed
please /bin/echo -e "hello \n world"
EOT

echo "test parameters (hello) - may not"
cat <<EOT | su -s /bin/bash ed
please /bin/echo -e "hello" | grep "may not"
EOT
 
