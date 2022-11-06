#!/bin/sh

set -e

cat <<'EOT' | su -s /bin/bash ed
set -e
export EDITOR=tee
echo "foo bar" | pleaseedit /etc/thing
please /bin/cat /etc/thing | grep "foo bar"
EOT


