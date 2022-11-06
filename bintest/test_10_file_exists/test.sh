#!/bin/sh

set -e

echo "file exists mode"
for mode in 0755 0644 0600 4755 0777 0666 0222; do
    touch "/tmp/file_${mode}"
    chmod "$mode" "/tmp/file_${mode}"

    cat <<EOT | su -s /bin/bash ed
    echo test | EDITOR="/usr/bin/tee" pleaseedit "/tmp/file_${mode}" || exit 1
EOT

    grep test "/tmp/file_${mode}"
    ls -al "/tmp/file_${mode}"
done

cat <<'EOT' | su -s /bin/bash ed 
set -e

echo test | EDITOR="/usr/bin/tee" pleaseedit "/tmp/static_0600"
echo test | EDITOR="/usr/bin/tee" pleaseedit "/tmp/static_0644"
echo test | EDITOR="/usr/bin/tee" pleaseedit "/tmp/static_defaults"
EOT

ls -al "/tmp/static_0600" | grep -- -rw-------
ls -al "/tmp/static_0644" | grep -- -rw-r--r--
ls -al "/tmp/static_defaults" | grep -- -rw-------

