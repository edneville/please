#!/bin/sh

set -e

echo thingy > /etc/thing

cat <<'EOT' | su -s /bin/bash ed
export EDITOR=tee
echo "foo bar baz alice bob eve" | pleaseedit /etc/thing
grep 'foo' /etc/thing* && exit 1
ls -al /tmp/*thing* && exit 1
/bin/true
EOT

