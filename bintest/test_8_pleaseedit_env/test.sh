#!/bin/sh

set -e

echo "test pleaseedit environment"
cat <<'EOT' | su -s /bin/bash ed 
export EDITOR="bash -c export"
pleaseedit /tmp/test_env | grep 'HOME="/home/ed"'
if test $? -ne 0; then
    echo "HOME is not /home/ed"
    exit 1
fi
pleaseedit /tmp/test_env | grep 'LOGNAME="ed"'
if test $? -ne 0; then
    echo "LOGNAME is not ed"
    exit 1
fi
pleaseedit /tmp/test_env | grep 'MAIL="/var/mail/ed"'
if test $? -ne 0; then
    echo "MAIL is not /var/mail/ed"
    exit 1
fi
EOT

