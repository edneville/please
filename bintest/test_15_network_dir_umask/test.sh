#!/bin/sh

set -e

apt-get update
apt-get -y install expect

echo "directory umask control"
rm -rf /var/run/please
cat <<'EOT' | su -s /bin/bash ed
set -e
cat <<'EOF' | expect
spawn please /bin/ls
expect -re ".*password.*"
send "password\r" 
expect eof
EOF
EOT

find /var/run/please -ls | grep -- "drwx------" || exit 1
find /var/run/please -ls | grep -- "-rw-------" || exit 1


