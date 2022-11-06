#!/bin/sh

set -e

echo "test list reason"
cat <<'EOT' | su -s /bin/bash ed
set -e
please -l | grep reason
please -l -r zip | grep "You may"
echo "list and reason passed"
EOT

