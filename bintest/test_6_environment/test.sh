#!/bin/sh

set -e

echo "test env default"
cat <<'EOT' | su -s /bin/bash ed 
please env | grep PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EOT

cat <<'EOT' | su -s /bin/bash ed 
please -a PATH env | grep PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if test $? -eq 1; then
    exit 0
fi
exit 1
EOT

