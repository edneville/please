#!/bin/sh

set -e

echo "test misc empty please.ini"
cat <<'EOT' | su -s /bin/bash ed
please -l | egrep "You may not view your command list"
please -l -t ed | egrep "You may not view your command list"
please -l -t root | egrep "You may not view root"
EOT

