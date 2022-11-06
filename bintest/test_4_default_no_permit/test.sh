#!/bin/sh

set -e

echo "test bash inherit 3"
cat <<EOT | su ed -s /bin/bash
echo "" | please /bin/bash | grep 'You may not' && exit 0
exit 1
EOT

