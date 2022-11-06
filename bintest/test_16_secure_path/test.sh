#!/bin/sh

set -e

echo "test search path"
cat <<'EOT' | su -s /bin/bash ed 
set -e

printf '#!/bin/sh\n/bin/echo wibble\n' > /home/ed/foo
chmod 755 /home/ed/foo

export PATH=/home/ed

/usr/bin/please foo | /bin/grep wibble
EOT

