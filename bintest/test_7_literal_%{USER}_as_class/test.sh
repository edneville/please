#!/bin/sh

set -e

echo "test literal %{USER}"
cat <<'EOT' | su -s /bin/bash ed 
please /bin/echo hello %{USER} | grep '^hello'
EOT

