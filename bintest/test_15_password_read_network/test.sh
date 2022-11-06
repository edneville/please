#!/bin/sh

set -e

apt-get update
apt-get -y install expect

cat <<'EOT' | su -s /bin/bash ed
set -e
echo "test list password"
cat <<'EOF' | expect | grep "You may"
spawn please -l
expect -re ".*password.*"
send "password\r" 
expect eof
EOF
echo "list passed"
EOT

cat <<'EOT' | su -s /bin/bash ed
echo list
cat <<'EOF' | expect | grep "Authentication"
spawn please -l
expect -re ".*password.*"
send "zpassword\r"
expect -re ".*password.*"
send "zpassword\r"
expect -re ".*password.*"
send "zpassword\r"
expect eof
EOF
EOT


