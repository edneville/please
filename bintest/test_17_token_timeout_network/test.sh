#!/bin/sh

set -e

apt-get update
apt-get -y install expect

echo "warm password token"
cat <<'EOT' | su -s /bin/bash ed

echo 'spawn expect'
cat <<'EOF' | expect
spawn bash
send "/usr/bin/please -w\r"
expect -re ".*password.*"
send "password\r"
expect "$"
puts "warmed password"

send "sleep 1\r"
expect "$"
send "please id\r"
expect "root"

send "sleep 3\r"
expect "$"

send "please id\r"
expect {
    -re ".*password.*" {
        puts "found password prompt"
        exit 0
    }
}
puts "token did not timeout"
exit 1
EOF
EOT

