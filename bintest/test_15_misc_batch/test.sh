#!/bin/sh

set -e

echo "test misc batch"
cat <<'EOT' | su -s /bin/bash ed 
set -e

please -l
please -l | grep 'You may run'

echo "hostname" | please /bin/bash

please -l -t root | egrep "You may not view root's command list"
please -l | grep -Fx '    ed_all:root (pass=false,dirs=): ^.*$'
please -l | grep -Fx '    ed_edit:root (pass=false,dirs=): ^/tmp/foo.ini$'
please -l | grep -Fx '    all_users_list:list: ^%{USER}$'

echo "Append with tee"
export EDITOR="/usr/bin/tee -a"
echo "###" | pleaseedit /tmp/foo.ini
echo "grep '###' /tmp/foo.ini" | please /bin/bash

echo "cat /etc/please.ini" | please /bin/bash
(echo "###" | pleaseedit /etc/fstab ) | egrep 'You may not edit "/etc/fstab" on \S+ as root'
echo "skipped edit"

echo "overwrite with tee"
export EDITOR="/usr/bin/tee"
echo "###" | pleaseedit /tmp/foo.ini
EOT

echo "reveal file contents"
printf "[section]\ntest = test" > /tmp/t
cat <<'EOT' | su -s /bin/bash ed 
please -c /tmp/t | grep test

if test $? -eq 0; then
    echo "revealed test"
    exit 1
fi
exit 0
EOT

