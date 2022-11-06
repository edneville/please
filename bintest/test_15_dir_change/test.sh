#!/bin/sh

set -e

echo "test dir change"
cat <<'EOT' | su -s /bin/bash ed
echo "dir change to /tmp"
please -d /tmp /bin/bash
if test $? -ne 0; then
    echo "could not execute please -d /tmp bash"
    exit 1
fi

echo "no dir"
please bash
if test $? -eq 0; then
    echo "bash executed, failing"
    exit 1
fi
EOT

