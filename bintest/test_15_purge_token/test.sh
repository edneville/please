#!/bin/sh

set -e
echo "test purge token (manual create)"

cat <<'EOT' | su -s /bin/bash ed
cat <<'EOF' | script /tmp/tty_test
export RUST_BACKTRACE=1
TOKEN="/var/run/please/token/ed:`tty | sed -e 's,/,_,g'`:$$"
please touch "$TOKEN"
please ls -al "$TOKEN"
please -p
please ls -al "$TOKEN" | grep token
if test $? -eq 0; then
    exit 1
fi
EOF
EOT

echo "test purge token (broken tty)"
cat <<'EOT' | su -s /bin/bash ed
export RUST_BACKTRACE=1
TOKEN="/var/run/please/token/ed:`echo /dev/pts/0 | sed -e 's,/,_,g'`:$$"
echo "$TOKEN"
please touch "$TOKEN"
please ls -al "$TOKEN"
please -p
please ls -al "$TOKEN" | grep token
EOT

echo "test warm token (broken tty)"
cat <<'EOT' | su -s /bin/bash ed
export RUST_BACKTRACE=1
TOKEN="/var/run/please/token/ed:`echo /dev/pts/0 | sed -e 's,/,_,g'`:$$"
please -w
please ls -al "$TOKEN" | grep token
if test $? -eq 0; then
    exit 1
fi
EOT

echo "test help output"
cat <<'EOT' | su -s /bin/bash ed
set -e
export RUST_BACKTRACE=1
please | grep -i 'no command'
please | grep -i 'usage'
please -v | egrep -i 'please.*version'
please --version | egrep -i 'please.*version'
please -h | grep -i 'version'
please --help | grep -i 'version'

pleaseedit | grep -i 'file'
pleaseedit | grep -i 'usage'
pleaseedit -v | egrep -i 'please.*version'
pleaseedit --version | egrep -i 'please.*version'
pleaseedit -h | grep -i 'version'
pleaseedit --help | grep -i 'version'
EOT

