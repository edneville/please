#!/bin/sh

set -e

echo "test internal slash"
cat <<'EOT' | su -s /bin/bash ed 
please /bin/echo hello %{USER} | grep '%{USER}'
EOT

