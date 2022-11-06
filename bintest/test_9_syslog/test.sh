#!/bin/sh

set -e

echo "test internal space \\0"
cat <<'EOT' | su -s /bin/bash ed 
set -e

please -l | grep "Could not connect to syslog:" && exit 1
echo test | EDITOR="/usr/bin/tee" pleaseedit /tmp/file | grep "Could not        connect to syslog:" && exit 1
please /bin/ls | grep "Could not connect to syslog:" && exit 1

please -c /sys/block/loop0 && exit 1

echo "test config against mode 600"
echo '#' > /tmp/perms
chmod 600 /tmp/perms
please -c /tmp/perms || exit 1

echo "test config against mode 640"
echo '#' > /tmp/perms
chmod 640 /tmp/perms
please -c /tmp/perms || exit 1

echo "test config against mode 660"
echo '#' > /tmp/perms
chmod 660 /tmp/perms
please -c /tmp/perms || true

echo "test config against mode 646"
echo '#' > /tmp/perms
chmod 660 /tmp/perms
please -c /tmp/perms || true

echo "test config against mode 446"
echo '#' > /tmp/perms
chmod 660 /tmp/perms
please -c /tmp/perms || true
EOT

