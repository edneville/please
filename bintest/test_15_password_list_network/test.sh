#!/bin/sh

set -e

apt-get update
apt-get -y install expect

echo "test list reason and password"
cat <<'EOT' | su -s /bin/bash ed
please -l | grep reason || exit 1

echo 'spawn expect'
cat <<'EOF' | expect | grep "You may"
spawn please -l -r zippy
expect -re ".*password.*"
send "password\r" 
expect eof
EOF
echo "list reason and password passed"
EOT

