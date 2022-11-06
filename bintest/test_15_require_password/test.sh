#!/bin/sh

set -e

echo "test password require"
echo "please -n hostname"
cat <<'EOT' | su -s /bin/bash ed 
please -n /bin/hostname
EOT

echo "please -n id"
cat <<'EOT' | su -s /bin/bash ed 
please -n /usr/bin/id
if test $? -ne 0; then
    exit 0;
fi
exit 1
EOT

echo "please -n who"
cat <<'EOT' | su -s /bin/bash ed 
please -n /usr/bin/who
if test $? -ne 0; then
    exit 0;
fi
exit 1
EOT

echo "(tester) please -l"
cat <<'EOT' | su -s /bin/bash tester
please -l | grep "You may not view your"
EOT

echo "(tester USER=ed) please bash"
cat <<'EOT' | su -s /bin/bash tester
export USER=ed
please /bin/bash | egrep "You may not execute .* as root"
EOT

