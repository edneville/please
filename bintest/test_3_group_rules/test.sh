#!/bin/sh

set -e

echo "test nogroup"
cat <<EOT | su ed -s /bin/bash
export EDITOR=/usr/bin/tee
echo "cat /etc/hosts" | pleaseedit -g nogroup /tmp/file
ls -al /tmp/file | grep nogroup
EOT

echo "test normal edit group"
cat <<EOT | su ed -s /bin/bash
export EDITOR=/usr/bin/tee
echo "cat /etc/hosts" | pleaseedit /tmp/normal_file
ls -al /tmp/normal_file | grep root.*root
EOT

echo "test bob normal edit group"
cat <<EOT | su ed -s /bin/bash
export EDITOR=/usr/bin/tee
echo "cat /etc/hosts" | pleaseedit -t bob /tmp/bob_normal_file
ls -al /tmp/bob_normal_file | grep bob.*bob.*bob
EOT

echo "test bob exact nogroup edit group"
cat <<EOT | su ed -s /bin/bash
export EDITOR=/usr/bin/tee
echo "cat /etc/hosts" | pleaseedit -t bob -g nogroup /tmp/bob_nogroup_file
ls -al /tmp/bob_nogroup_file | grep bob.*nogroup.*nogroup
EOT

echo "test bob (id -a) normal group"
cat <<EOT | su ed -s /bin/bash
echo "id -a" | please -t bob /bin/bash | egrep 'uid=\S+\(bob\) gid=\S+\(bob\) groups=\S+\(bob\)'
EOT

echo "test bob (id -a) exact nogroup group"
cat <<EOT | su ed -s /bin/bash
echo "id -a" | please -t bob -g nogroup /bin/bash | grep bob | egrep 'uid=\S+\(bob\) gid=\S+\(nogroup\) groups=\S+\(nogroup\)'
EOT

