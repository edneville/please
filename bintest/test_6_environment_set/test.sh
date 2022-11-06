#!/bin/sh

set -e

echo "test env can be set"
cat <<'EOT' | su -s /bin/bash ed 
export PATH="/foo/bar:$PATH"
please -a PATH env | grep PATH=/foo/bar
EOT

echo "test env can be set but partially permitted so should fail"
cat <<'EOT' | su -s /bin/bash ed 
export PATH="/foo/bar:$PATH"
please -a PATH,HOME env | grep PATH=/foo/bar
if test $? -eq 1; then
    exit 0
fi
exit 1
EOT

