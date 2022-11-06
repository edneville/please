#!/bin/sh

set -e

echo "test target edit as bob"
cat <<'EOT' | su -s /bin/bash ed
export EDITOR=/usr/bin/tee
export RUST_BACKTRACE=1
echo "BOB WOZ ERE" | pleaseedit -t bob /tmp/bobs_edit
echo "... exited $?"
echo "... edited 1"
echo "grep 'BOB WOZ ERE' /tmp/bobs_edit" | please bash
ls -al /tmp/edited /tmp/bobs_edit | grep -- "-rw-------. 1 bob  bob"
stat /tmp/bobs_edit | egrep '^Access: \(0600'
EOT

echo "test -t -u conflicts"
cat <<'EOT' | su -s /bin/bash ed
export EDITOR=/usr/bin/tee
export RUST_BACKTRACE=1
please -u ed -t bob bash | grep "Cannot use -t and -u with conflicting values"
please -u bob -t bob bash | grep "You may not"
EOT


