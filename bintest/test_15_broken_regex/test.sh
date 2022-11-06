#!/bin/sh

set -e

echo "(check) test broken regex"
cat <<'EOT' | su -s /bin/bash ed
please -c /etc/please.ini || exit 0
exit 1
EOT

echo "(run) test broken regex"
cat <<'EOT' | su -s /bin/bash ed
please /bin/bash | egrep "Error parsing /etc/please.ini: ed_all:3"
please /bin/bash | egrep "Exiting due to error, cannot fully process /etc/please.ini"
EOT

