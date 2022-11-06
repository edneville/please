#!/bin/sh

cat <<'EOT' >/etc/please.ini
[ed_all]
include = /etc/please.d/00_please_missing.ini
permit = false
EOT

echo "test includedir (broken)"
cat <<EOT | su ed -s /bin/bash
echo "cat /etc/hosts" | please /bin/bash | grep "Could not include file"
EOT

