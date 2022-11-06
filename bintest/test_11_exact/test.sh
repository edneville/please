#!/bin/sh

set -e

echo "test exact"
cat <<'EOT' | su -s /bin/bash ed 
set -e

echo id | please /bin/bash | grep root
EOT

echo "test exact /bin/sh fails"
cat <<EOT | su -s /bin/bash ed | grep 'You may not execute "/bin/sh" on'
set +e
echo id | please /bin/sh
EOT

