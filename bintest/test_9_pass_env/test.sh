#!/bin/sh

set -e

echo "test pass env"
cat <<'EOT' | su -s /bin/bash ed 
set -e

export THING=abc
export THIS=that
please -a THING env
please -a THIS, env
please -a THIS,THING env | grep ^THING=abc
please -a THIS,THING env | grep ^THIS=that
EOT

