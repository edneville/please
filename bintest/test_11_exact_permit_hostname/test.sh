#!/bin/sh

set -e

mkdir /etc/tmp

cat <<EOT > /etc/tmp/hostname.ini
[ed_all]
syslog = false
exact_hostname = `hostname`
exact_name = ed
exact_rule = /bin/bash
require_pass = false
EOT

echo "test exact permits actual hostname"
cat <<EOT | su -s /bin/bash ed
set -e
echo id | please /bin/bash
EOT

