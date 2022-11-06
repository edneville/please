#!/bin/sh

set -e

# it looks crazy in the error message if the command is changed:
# You may not execute "/bin/echo -e hello\ \\\ world\ 1" on 0d45d086b9ad as root
#                                        ^ ^ ^
#                                        | | +-- escape following space
#                                        | +---- escape the escape character
#                                        +------ escape following space

echo "test parameters (hello \ world)"
cat <<EOT | su -s /bin/bash ed
please /bin/echo -e 'hello \ world'
EOT

echo "test parameters (hello) - may not"
cat <<EOT | su -s /bin/bash ed
please /bin/echo -e "hello" | grep "may not"
EOT

