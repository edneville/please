#!/bin/sh

set -e

echo "test syslog is off as a default"
cat <<'EOT' | su -s /bin/bash ed 
set -e

please -l
EOT

