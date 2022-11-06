#!/bin/sh

set -e

/bin/rm -rf /etc/please* || true

echo "test failure to read ini"
cat <<'EOT' | su ed
please -l | grep "Exiting due to error, cannot fully process /etc/please.ini"
EOT
