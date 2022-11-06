#!/bin/sh

set -e

echo "escaped arguments"

cat <<'EOT' | su -s /bin/bash ed
export RUST_BACKTRACE=1
echo "doing hello"
please /bin/echo "hello world" | egrep "^hello world"
if test $? -ne 0; then
    exit 1
fi
echo "did true"
please /bin/echo "goodbye world" | egrep "You may not.*"
if test $? -ne 0; then
    exit 0
fi
EOT


